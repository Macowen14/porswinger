# Lab Notes: Username Enumeration via Account Lock (PortSwigger — Practitioner)

## Objective
Exploit account-lockout behavior to enumerate a valid username, then brute-force
that user's password without triggering a *permanent* lock — ultimately logging
in as the target account.

## Vulnerability Summary
The login endpoint behaves differently depending on whether a username is valid:

- **Invalid username** → generic response, no matter how many times you try it.
  It can never be locked because it doesn't map to a real account.
- **Valid username** → after enough failed attempts, the account **locks**, and
  the response changes to a distinct "too many incorrect login attempts" message
  — even on a request that would otherwise look like a normal failed login.

This creates a **response-based oracle**: hammer every candidate username with a
few wrong passwords, and the ones that flip into a "locked" response are real
accounts. This is a classic case of an anti-automation control (lockout) leaking
information through a side channel (response content/length), rather than
actually protecting the account.

## Two-Phase Approach

### Phase 1 — Enumerate the valid username
Script: `uname_enumeration_block.py`

Logic:
1. Loop over a candidate username wordlist.
2. For each username, fire a fixed number of failed logins (`ATTEMPTS_PER_USERNAME`,
   set comfortably above the suspected lockout threshold) using one shared wrong
   password.
3. Record the **final** response's status code + body length for each username.
4. Compare response lengths across all candidates using a `Counter` — the
   majority share one length (the generic invalid-creds page); any outlier
   length is the account that got locked, i.e. a **valid username**.

Key design points:
- Uses a **fresh `requests.Session()` per username** so lockout state/cookies
  from one candidate don't bleed into the next.
- `find_lockout_threshold()` is a helper to manually probe a *known* valid
  username first and watch response length/status change attempt-by-attempt —
  useful for calibrating `ATTEMPTS_PER_USERNAME` before running the full sweep.
- `report_outliers()` does the actual "spot the different one" analysis instead
  of eyeballing raw output.
- CSRF extraction is stubbed out (commented) — worth wiring up if the target
  app embeds a per-request CSRF token in the login form, since a stale/missing
  token can itself change the response shape and produce false positives.

### Phase 2 — Brute-force the password
Script: `lazy_pass_enum.py`

Once the valid username is known, the challenge flips: you must guess the
password **without tripping the lockout permanently**. The lab's mitigation
resets the lockout after a cooldown window, so the trick is pacing requests
to stay under the threshold.

Logic:
1. Loop through a password wordlist against the known username.
2. Distinguish **three** response types (this was the key fix over a naive
   version): invalid credentials, account locked, and success.
   - `INVALID_MARKER` = `"Invalid username or password"`
   - `LOCKED_MARKER` = `"You have made too many incorrect login attempts..."`
   - Anything else (neither marker present) = credentials worked.
3. Track `attempts_since_cooldown` and sleep for `LOCK_COOLDOWN` (60s) once it
   hits `LOCK_THRESHOLD` (3) — *before* the app locks you out, so you're always
   proactively pacing rather than reactively recovering.
4. If a lock response is detected anyway (e.g. threshold estimate was off),
   sleep and reset the counter **without** counting that response as a real
   password attempt — otherwise you'd silently skip a password.

## Why the Naive Version Failed
The first draft only had one counter and one string check
(`if "Invalid username or password" not in response.text`) — it couldn't tell
"correct password" apart from "account locked," since a lockout response also
doesn't contain the invalid-creds string. That would have produced a false
positive on the first lockout hit. Splitting the response into three explicit
outcomes (invalid / locked / success) fixed this.

## Result
Enumerated the valid username via the lockout side-channel, then brute-forced
its password while pacing around the lockout window, and logged in successfully.

## Mitigation Takeaways (for write-up / real-world application)
- Lockout responses should be **indistinguishable** from normal invalid-login
  responses (same message, same status code, same timing) regardless of
  whether the username is real.
- Avoid **per-account** lockouts that leak validity; consider IP-based or
  device-based throttling, or CAPTCHA after N failures site-wide.
- Any timing or content difference tied to account existence (lockout, "check
  your email," different error copy) is a potential enumeration oracle —
  worth testing during a real assessment, not just in login flows but in
  password reset and registration flows too.

## Scripts
- `uname_enumeration_block.py` — Phase 1, username enumeration via lockout side-channel
- `lazy_pass_enum.py` — Phase 2, paced password brute force against the confirmed username