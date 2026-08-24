# Lab Notes: Password Brute-Force via Password Change

**Lab:** Password brute-force via password change
**Category:** Authentication — Brute-force protection flaws
**Difficulty:** Practitioner

---

## Vulnerability Concept

The account change-password form submits `username` as a hidden input alongside `current-password`, `new-password-1`, and `new-password-2`. The server validates `current-password` against whatever `username` was submitted — but never checks that this `username` matches the account tied to the active session.

This means an authenticated session (any valid login) can be used to test password guesses against a **different** account's `current-password` field. Critically, this endpoint doesn't share the same brute-force lockout as `/login` under every condition — it only locks the account when a guess is wrong **and** the two new-password fields match. This distinction becomes the exploitable oracle (see below).

---

## Exploitation Logic

1. Log in with your own valid account (session required — the endpoint is behind auth and won't process anything without a valid cookie).
2. Intercept a change-password request. Set `username` to the target (`carlos`), not yourself.
3. Set `current-password` to a guessed value from a wordlist.
4. Set `new-password-1` and `new-password-2` to two **different, throwaway** values (e.g. `"111"` / `"222"`) — never matching values. This is essential: a wrong guess with matching new passwords triggers an account lockout, which you want to avoid entirely while brute-forcing.
5. Read the response and classify it against the three known outcomes for this app:
   - `current-password` wrong → `"Current password is incorrect"`
   - `current-password` **correct**, new passwords mismatched → `"New passwords do not match"` ← the guess is right
   - `current-password` wrong, new passwords matched → account lockout (avoid triggering this)
6. Once the correct `current-password` is found, log out, log back in as `carlos` with that password, and load `/my-account` to solve the lab.

---

## Determining the Success/Failure Oracle — General Method

This is the part that actually blocked progress initially, so it's worth its own section. **Never guess the success/failure string.** Guessing produced a script that checked for `"Password changed successfully"` and `status_code == 200` — neither of which ever appeared, because:

- `requests` follows redirects by default, so `status_code` reflects the *final* page in the chain, not the original response. An unauthenticated request, a failed guess, and a successful one can all resolve to `200` if they each land on a normally-rendering page. Status code alone rarely distinguishes outcomes on form submissions like this.
- The assumed success string was never observed — it was an assumption about what a "generic" success message might look like, and this app doesn't even use that framing (its real signal is a *side effect* of a secondary check, not a direct confirmation message).

### The reliable process:
1. **Send one deliberately correct request and one deliberately wrong request through Burp Repeater first** (or via a quick manual `requests` call), for every relevant condition — right password, wrong password, right password with mismatched new-passwords, wrong password with matched new-passwords. Read the literal response bodies. Don't infer, observe.
2. **Diff the response bodies against each other.** The differentiating text is usually a short inline message near the form — look for `<p class="...is-warning...">`, `<div class="...is-warning...">`, or similar status-banner markup rather than assuming exact wording.
3. **Check `resp.url` (final URL after redirects), not just `resp.status_code`.** If it lands back on `/login`, the session isn't authenticated — this is a separate failure mode from a wrong password guess and needs to be ruled out first, or every subsequent check is meaningless.
4. **Build the classifier from the exact strings observed**, not paraphrased ones. Small wording differences (`"incorrect"` vs `"does not match"` vs `"invalid"`) are easy to get wrong from memory.
5. **When automating, print the raw signal for every request during a small test run** (status code, final URL, matched message, or a body snippet) before trusting the classifier over a full wordlist. If everything falls into an "unrecognized response" bucket, the oracle is still wrong — fix it before scaling up.
6. **Design payload fields so they can't accidentally trigger a side effect that erases your ability to observe outcomes** — e.g., using mismatched new-password values here to avoid account lockout, which would otherwise mask further legitimate guesses.

---

## Why It Matters Generally

- **Cross-account parameter trust**: any endpoint that accepts a target identifier (`username`, `user_id`, `account`) as a form field rather than deriving it from the authenticated session can be abused to act against a different account than the one that's logged in.
- **Inconsistent brute-force protections across endpoints**: rate-limiting/lockout logic implemented only on the primary login form, and not on secondary flows (password change, password reset, MFA re-verification) that also validate a secret, creates a bypass path for the exact same class of attack the login lockout was meant to prevent.
- **Error-message-based oracles**: differentiated error messages for different failure conditions (as opposed to one generic "something went wrong") let an attacker binary-search or brute-force distinguishable states even without ever seeing a literal "success" response.

---

## Remediation

- Never accept a target-account identifier from client-supplied form data on an authenticated action; derive it from the session.
- Apply the same brute-force protections (lockout, rate limiting, CAPTCHA) uniformly across every endpoint that validates a secret, not just the primary login form.
- Use generic, non-differentiating error messages for related-but-distinct failure conditions where feasible, so responses don't leak which specific check failed.