## Username enumeration via response timing

**Lab:** [PortSwigger — Username enumeration via response timing](https://portswigger.net/web-security/authentication/other-mechanisms/lab-username-enumeration-via-response-timing)

This lab is vulnerable to username enumeration using its response times. To solve the
lab, enumerate a valid username, brute-force that user's password, then access their
account page.

---

### Vulnerability concept

- The login endpoint gives no explicit signal ("user not found" vs "wrong password")
  — but it leaks an *implicit* signal through timing.
- Most apps only hash the submitted password **if the username exists** (to check it
  against the stored hash). If the username doesn't exist, the app short-circuits and
  returns immediately — no hashing needed.
- This creates a measurable timing gap:
  - **Invalid username** → fast response (no hashing performed)
  - **Valid username + wrong password** → slower response (password gets hashed and
    compared)
- Root cause: authentication logic that behaves differently in timing depending on
  whether a username exists — a classic **timing side-channel**.

---

### Bypassing the brute-force lockout

PortSwigger's brute-force protection tracks failed attempts **per IP**, but it reads
the IP from the client-supplied `X-Forwarded-For` header instead of the actual TCP
connection — a common misconfiguration for apps sitting behind a proxy/load balancer.

Since this header is attacker-controlled and unvalidated, sending a unique value on
every request resets which "bucket" the attempt counter applies to, so no single
identity ever crosses the lockout threshold — even though every request comes from the
same real IP.

This is the same vulnerability class as `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP`
rate-limit bypasses seen in real-world WAFs and app-layer rate limiters.

> **Verification tip:** run one request without the spoofed header to confirm lockout
> actually triggers — this proves the header is genuinely the bypass mechanism, not
> some other quirk of the lab.

---

### Custom script workflow

1. **Spoofed network context** — attaches a random value (UUID or fake IP) to
   `X-Forwarded-For` on every request, so the app's per-IP lockout counter never
   accumulates against a single identity.

2. **Timing measurement** — `time.perf_counter()` captures wall-clock execution time
   per request down to microsecond precision (not affected by system clock changes,
   unlike `time.time()`).

3. **Payload amplification** — submits a long password (`"A" * 150`) with every
   username attempt. If the username **is valid**, the server hashes/compares this
   long string against the stored hash, adding measurable computational delay. If the
   username is invalid, the app skips hashing entirely and responds fast.

4. **Statistical detection, not a fixed threshold** — rather than assuming a fixed
   cutoff like 350ms (server load and network jitter make a fixed number unreliable),
   take multiple timing samples per username, use the **median** to cancel out noise,
   then compare all usernames' medians against each other. The valid username stands
   out as a clear timing outlier relative to the baseline.

5. **Password extraction** — once the username is isolated, switch to standard
   brute-forcing against `passwords.txt`, checking for a `302 Redirect` or a session
   cookie in the response as the success signal.

---

### Why not just brute force username × password combos directly?

- Combinatorial brute force is O(usernames × passwords) — far more requests than
  needed.
- The timing side-channel lets you resolve the username in O(usernames) first, then
  brute the password in O(passwords) for just that one account — much faster and
  closer to how this vulnerability would realistically be exploited.

---

### Remediation (how this should be fixed)

- Ensure the app takes the **same amount of time** to respond regardless of whether
  the username exists (e.g., always perform a dummy hash comparison even for unknown
  usernames).
- Don't trust client-supplied headers (`X-Forwarded-For`, `X-Real-IP`, etc.) for
  security-relevant logic like rate limiting/lockouts unless the proxy layer strips
  and re-sets them from a trusted source.
- Use generic, identical error messages and response structure for both "unknown
  username" and "wrong password" cases.