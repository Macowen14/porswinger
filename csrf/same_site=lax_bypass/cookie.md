Never mind the file and folder naming. Its not my thing :>)
# CSRF: Bypassing SameSite=Lax Restrictions via GET Requests

## Summary

`SameSite=Lax` cookies are only withheld from **cross-site subrequests** (iframes, `fetch`, `XHR`, `<img>`, form `POST`, etc.). They are still sent on **top-level navigations** using "safe" HTTP methods — primarily `GET`. If a state-changing endpoint (that's normally reached via `POST`) also accepts `GET`, an attacker can trigger it with a simple cross-site navigation and the victim's session cookie will ride along, completing a working CSRF attack.

---

## Background: What SameSite Actually Restricts

| Cookie attribute | Sent on same-site requests | Sent on cross-site subrequests (iframe, fetch, img, form POST) | Sent on cross-site top-level navigation (GET link/redirect) |
|---|---|---|---|
| `SameSite=Strict` | ✅ | ❌ | ❌ |
| `SameSite=Lax` (and modern browser default) | ✅ | ❌ | ✅ (safe methods only, e.g. GET) |
| `SameSite=None; Secure` | ✅ | ✅ | ✅ |

The key gap: **Lax was designed as a usability compromise** — so that clicking a normal link into a site (e.g. from an email or another page) doesn't log you out. That compromise is exactly what this attack abuses.

---

## Root Cause

Two conditions must both be true:

1. **The server accepts `GET` (or another "safe" method) for a state-changing action** that was only ever *intended* to be reached via `POST` (e.g. a form submission for `transfer-payment`, `change-email`, `delete-account`).
2. **The session cookie uses `SameSite=Lax`** (explicitly, or implicitly via browser default when no `SameSite` attribute is set).

Many backends don't strictly enforce method separation — routing frameworks or handlers often read parameters from the query string just as readily as from the POST body, so the "wrong" method quietly works.

---

## Attack Flow

1. Attacker hosts a page with a script that performs a **top-level navigation** to the vulnerable endpoint, passing the malicious parameters in the query string:

   ```html
   <script>
     document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
   </script>
   ```

2. Victim is lured to the attacker's page (phishing link, malicious ad, forum post, etc.) while they have an active session on `vulnerable-website.com`.

3. Page loads → script executes automatically (no click needed) → browser navigates the **current tab** to the vulnerable URL.

4. Because this is a top-level `GET` navigation, the browser attaches the `Lax` session cookie.

5. If the server processes `GET` the same as `POST` for that route, the action executes as the victim.

---

## Why This Differs From "Normal" CSRF

| | Classic CSRF (no SameSite, or None) | This bypass |
|---|---|---|
| Delivery mechanism | Auto-submitting HTML `<form>` doing a `POST`, hidden iframe, `fetch`, `<img>` | Simple top-level navigation (`document.location`, `<a>`, `<meta refresh>`, `window.open`) |
| Cookie attribute needed | Any (None/no SameSite/Lax with POST won't work) | Must be `Lax` (or missing, since Lax is the modern default) — **and** the endpoint must accept GET |
| Stealth | Can be fully hidden in an invisible iframe | Visible — the victim's tab actually navigates away (unless redirected via `window.open`, which is popup-blockable) |
| Complexity | Needs to replicate form fields / body | Just a URL with query parameters |

---

## Practical Notes / Gotchas

- **Visibility**: `document.location = ...` redirects the *current tab* — the victim will see the URL bar change and the target page load. It is not silent. Variants like `window.open()` can send it to a new tab, but are subject to popup blocking.
- **Iframes don't work here**: loading the URL in a hidden `<iframe>` is a cross-site *subrequest*, not a top-level navigation — `Lax` cookies are withheld from it. The whole reason this technique uses `document.location` (or a link/redirect) instead of an iframe is to qualify as top-level navigation.
- **Verifying it from the request, not from JS**: `document.cookie` in the target page's console only shows what's readable by JS on that page load — it doesn't prove the cookie was *sent* on the navigation request. The real evidence is in DevTools → Network tab → the request → Request Headers → `Cookie`.
- **Method leniency is the real bug**: the SameSite mechanism is working as designed; the actual vulnerability is the server treating `GET` and `POST` as interchangeable for a sensitive action.

---

## How to Test for It

1. Identify a sensitive `POST` endpoint (form submission, state change).
2. Re-send the exact same parameters as a `GET` request (e.g. via Burp Repeater), either as query string or by converting body params to query params.
3. Check if the server executes the action anyway (200 OK / state actually changed), rather than rejecting with `405 Method Not Allowed` or similar.
4. If it works, confirm whether the session cookie is `SameSite=Lax` (or unset, defaulting to Lax in modern browsers) — check `Set-Cookie` header on login.
5. Build a minimal top-level-navigation PoC (`document.location`) and confirm the cookie is attached on the outbound request in a real browser.

---

## Mitigations

- **Strictly enforce HTTP methods** at the routing/framework level — reject `GET` on state-changing endpoints with `405`, don't silently accept query-string params as a substitute for the POST body.
- **Use anti-CSRF tokens** (synchronizer token pattern) for all state-changing requests, regardless of cookie SameSite setting — this is the primary defense; SameSite is defense-in-depth, not a replacement.
- **Set `SameSite=Strict`** on sensitive session cookies where usability trade-offs are acceptable (fully blocks cross-site top-level navigation too, at the cost of breaking "click a link and stay logged in" flows).
- **Require re-authentication / step-up auth** for highly sensitive actions (large transfers, email/password changes), independent of session cookie alone.
- **Check `Origin` / `Referer` headers** server-side as a secondary signal for state-changing requests.

---

## Related Techniques (Same SameSite=Lax Family of Bypasses)

- **Client-side redirect bypass**: attacker page navigates to a same-site URL that the vulnerable site itself redirects cross-site — some older browser versions treated the cookie as "recently attached" due to timing/race conditions around the 2-minute Lax grace period (mostly patched now).
- **Method override parameters**: some frameworks support `_method=POST` style overrides read from query strings — if present, a `GET` request carrying `_method=POST` can be coerced into being treated as a POST server-side while still being sent as a GET at the transport layer (so it still qualifies for Lax's top-level-nav allowance).

---

## Key Takeaway

`SameSite=Lax` stops the most common CSRF delivery mechanisms (auto-submit forms, iframes, fetch) but was never meant to stop **top-level GET navigation**. Any sensitive action reachable by `GET` is still attackable with nothing more than a link.