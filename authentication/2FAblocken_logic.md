# Lab: 2FA Broken Logic

## Vulnerability Concept

The application implements two-factor authentication as a second step after
password login, but it never enforces any limit on how many times a 2FA
code can be guessed for a given session. The `verify` cookie ties every
subsequent request to a specific username (`carlos`), and the `/login2`
endpoint accepts a `mfa-code` parameter without:

- Locking the account after N failed attempts
- Invalidating the session/cookie after a failed guess
- Rate-limiting requests from the same session

Because the code is only 4 digits, the entire keyspace is 10,000 possible
values (`0000`–`9999`). Combined with no attempt limiting, this becomes
fully brute-forceable rather than just "theoretically weak."

## Exploitation Logic

1. Log in with valid credentials for the victim (`carlos`) to reach the
   `/login2` 2FA step and obtain a `verify=carlos` session cookie.
2. Reuse that same cookie across every guess — the app checks the code
   against whichever user the cookie identifies, so the cookie is the
   anchor, not the code itself.
3. Iterate all 4-digit codes `0000`–`9999`, zero-padded, submitting each as
   `mfa-code=<guess>` in the POST body.
4. Distinguish success from failure by response behavior:
   - Wrong code → `200 OK` with "Incorrect security code" in the body
   - Correct code → `302/303` redirect to `/my-account`
5. Stop as soon as a redirect is observed — that guess is the valid code.

## Script Workflow

- `requests.Session()` holds the `verify` cookie so it persists across all
  requests without re-setting it each time.
- A `ThreadPoolExecutor` dispatches guesses concurrently (15 workers) since
  each request is I/O-bound — the thread mostly waits on network I/O, so
  Python's GIL doesn't block real concurrency here the way it would for
  CPU-bound work.
- A `threading.Event` flag (`found_event`) lets already-running threads
  short-circuit once a hit is found, and `executor.shutdown(cancel_futures=True)`
  stops queuing any further guesses.
- Success detection keys off `resp.status_code in (302, 303)` with
  `allow_redirects=False`, so the redirect itself is the signal rather than
  following it and inspecting the destination page.

## Why It Matters Generally

2FA is only as strong as the *enforcement* around the second factor, not
just the existence of a code. Common real-world failure modes mirrored by
this lab:

- Short, numeric-only codes with no attempt cap (10,000 is trivial to
  exhaust programmatically)
- No session/token invalidation after a failed 2FA attempt
- No exponential backoff or lockout tied to the *session*, only (if at all)
  tied to the username — attackers can often route around per-username
  throttling by manipulating client-supplied state (as with the `verify`
  cookie here)
- Treating 2FA as a client-side speed bump rather than a server-enforced
  control

This is the same underlying category of flaw as the account-lockout and
brute-force protection labs — the fix pattern is consistent across all of
them: enforce limits server-side, tied to something the attacker can't
freely reset (IP + account, not just account; or a genuinely expiring
session).

## Remediation

- Enforce a strict maximum number of 2FA attempts per session/account
  (e.g., 3–5), after which the session is invalidated and the user must
  re-authenticate from the start.
- Add rate limiting/backoff on the `/login2` endpoint, independent of any
  client-controlled cookie value.
- Increase code length/entropy and use short expiry windows so even an
  unthrottled brute force runs out of time before exhausting the keyspace.
- Invalidate the 2FA code after a single use or failed attempt rather than
  allowing indefinite retries against the same value.
- Log and alert on abnormal volumes of 2FA attempts from a single
  session/IP as a detective control alongside the preventive fix.