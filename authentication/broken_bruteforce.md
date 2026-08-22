## Broken brute-force protection, IP block

**Lab:** [PortSwigger — Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/other-mechanisms/lab-broken-brute-force-protection-ip-block)

This lab has a login flow that's vulnerable to brute-forcing, despite having a
brute-force protection mechanism. To solve the lab, brute-force `carlos`'s password,
then log in to their account.

---

### Vulnerability concept

- The app locks out an IP after **3 consecutive failed login attempts** (for any
  username), not 3 failed attempts against one specific account.
- Critically, the failed-attempt counter is **reset by any successful login** —
  regardless of *which* account logged in successfully.
- This means the lockout isn't actually tracking "attacks against `carlos`", it's
  tracking "recent failures from this IP" — and a single valid login anywhere resets
  that count back to zero.
- Root cause: the brute-force protection conflates **request-level failure count**
  with **account-level attack detection**. It should be scoped per-target-account, not
  reset by unrelated successful logins.

---

### Exploitation logic

Since a successful login (even to a *different*, known-good account) resets the
counter, the attack pattern becomes:

```
attempt 1: carlos + wrong_password_1   -> fail   (streak = 1)
attempt 2: carlos + wrong_password_2   -> fail   (streak = 2)
attempt 3: wiener + peter (known good) -> success -> counter resets to 0
attempt 4: carlos + wrong_password_3   -> fail   (streak = 1)
attempt 5: carlos + wrong_password_4   -> fail   (streak = 2)
attempt 6: wiener + peter (known good) -> success -> counter resets to 0
...
```

By never letting the failure streak reach 3, the IP is never blocked — the attacker
gets unlimited password guesses against `carlos`, two at a time, at the cost of one
extra "wasted" request per cycle.

---

### Script workflow

1. **CSRF token handling** — PortSwigger's login form requires a `csrf` value pulled
   from the GET `/login` page and resubmitted with every POST. Missing this causes
   every login attempt to fail regardless of credentials, which would look identical
   to a wrong password if not checked for explicitly.

2. **Session persistence** — a single `requests.Session()` is reused across all
   requests so cookies (and the app's per-session/per-IP attempt tracking) stay
   consistent, matching how a real browser-driven attack would behave.

3. **Failure streak counter** — tracks consecutive failed `carlos` attempts in
   Python. Once it reaches the reset threshold (2), the script inserts one
   `wiener:peter` login before continuing, keeping the real failure count on the
   server always below the 3-attempt lockout trigger.

4. **Success detection** — a `302` status code (redirect after login) is treated as
   success; the form reloads with `200` on failure. `allow_redirects=False` is used so
   the redirect itself is observed rather than silently followed.

5. **Defensive backoff** — if the "known good" reset login itself doesn't succeed
   (unexpected status code), or if a `429`/lockout message is detected in the
   response, the script backs off (30–60s) instead of continuing to hammer a blocked
   session.

---

### Why this matters generally

This is a real-world pattern seen in poorly designed rate limiters: **counting failed
requests instead of tracking suspicious behavior per target**. Any mechanism that
resets a "risk score" based on an unrelated success (rather than success specifically
on the account being targeted) can be gamed the same way — attacker interleaves known-
valid credentials to keep resetting their own risk clock.

---

### Remediation (how this should be fixed)

- Scope brute-force lockout **per target account**, not per source IP with a global
  reset condition — failed attempts against `carlos` should count against `carlos`'s
  lockout state regardless of what else that IP does.
- Don't let success on Account A reset the failure count being tracked for Account B.
- Add progressive delays (exponential backoff) per account after repeated failures,
  independent of unrelated successful logins elsewhere.
- Rate-limit by combination of signals (IP *and* target username *and* request
  pattern/timing) rather than a single resettable counter.