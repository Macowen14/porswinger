# Lab: Brute-forcing a Stay-Logged-In Cookie

## Vulnerability Concept

The application implements "remember me" persistence via a `stay-logged-in`
cookie built as:

```
base64(username + ":" + MD5(password))
```

The password hash is computed with **no salt** — the same password always
produces the same MD5 output regardless of which account it belongs to.
Combined with MD5 being a fast, non-purpose-built-for-passwords hash
algorithm, this means an attacker who can observe one valid cookie can:

1. Reverse-engineer the cookie's format.
2. Confirm the hashing scheme using an account whose password they already
   know (their own low-privilege account).
3. Reuse that exact scheme to brute-force a target account's password
   entirely offline/client-side — no login attempts against `/login`
   itself are needed, only forged cookies tested against an
   authenticated-only page.

## Exploitation Logic

1. Capture your own valid `stay-logged-in` cookie (e.g. `wiener`'s).
2. Decode and analyze it (see "Cookie Analysis Method" below) to recover
   the format: `username:hash`.
3. Since you know `wiener`'s real password, hash it yourself and compare
   to the value from the cookie — this confirms both the algorithm (MD5)
   and that no salt is involved (see "Detecting Salting" below).
4. For the target account (`carlos`), take a password wordlist, compute
   `MD5(password)` for each candidate, and build a forged cookie:
   `base64("carlos:" + md5hash)`.
5. Send each forged cookie to an authenticated-only endpoint
   (`/my-account`) and check for a success marker in the response.
6. The candidate that produces a `200` with the marker present is the
   correct password — use that same cookie to log in as `carlos`.

## Cookie Analysis Method

This is the general workflow for any unfamiliar auth cookie, not just this
lab.

### Step 1 — Identify the encoding layer

Look at the character set before assuming anything about hashing:

- Only `A-Za-z0-9+/=` and length is a multiple of 4 → likely **Base64**
- Only `0-9a-f` → likely **raw hex**
- Contains `%` → likely **URL-encoded**
- Random-looking binary/unprintable bytes → possibly raw
  ciphertext/binary, not just an encoding wrapper

Decode Base64 first and see what comes out — if it's still binary noise,
you may be looking at actual encryption or a binary token format. If it
decodes to readable text, the "encryption" is often just an encoding
wrapper around a structured value (as in this lab).

### Step 2 — Look for structure in the decoded value

Once decoded, check for delimiters (`:`, `|`, `-`, `.`) splitting the
value into fields. Common patterns:

- `username:hash`
- `username:hash:salt`
- `userid.timestamp.signature` (common in JWT-style or signed tokens)

The delimiter and field count tell you what's actually being verified —
in this lab, the presence of a plain `username:` prefix means the hash
component is checked against that specific user's password.

### Step 3 — Fingerprint the hash by output length

Hex-encoded hash length gives away the algorithm:

| Length (hex chars) | Algorithm |
|---|---|
| 32  | MD5 |
| 40  | SHA-1 |
| 56  | SHA-224 |
| 64  | SHA-256 |
| 96  | SHA-384 |
| 128 | SHA-512 |

A 32-character hex string in the decoded cookie is a strong MD5 signal.

### Step 4 — Confirm with a known plaintext

Fingerprinting the length only tells you the *algorithm family* — not
what's actually being hashed (just the password? username+password?
password+static string?). The only reliable way to confirm is having a
known input/output pair:

- Use an account whose password you already know.
- Hash a few candidate constructions (`password`, `username:password`,
  `password:username`, etc.) and compare to the value in the cookie.
- A match confirms both the algorithm and the exact input format.

## Detecting Salting

You can't tell if a hash is salted just by staring at one hash value —
salting is invisible in isolation. What you can check:

1. **Known-plaintext test (most reliable).** Hash a known password with
   the suspected algorithm alone. If it doesn't match the stored/observed
   hash, something extra is being mixed in — try appending/prepending
   likely values (salt stored elsewhere, username, static pepper). If a
   truly random per-user salt is used and you have no way to obtain it,
   you generally cannot reproduce the hash externally at all — that's the
   point of a proper salt.

2. **Structural clues in the stored/transmitted value.** Salted schemes
   often need to expose the salt somewhere for later verification. Watch
   for:
   - A third delimited field (`username:hash:salt`)
   - A hash value longer than the algorithm's normal output length
     (extra bytes tacked on)
   - Separate `salt` field/cookie/hidden form field alongside the hash

3. **Cross-account comparison.** If two accounts are known/suspected to
   share the same password (e.g. default/test accounts, leaked credential
   reuse) and their stored hashes differ, that's a strong salting signal.
   Identical hashes across accounts with the same password is the
   unsalted case — exactly what showed up in this lab, since
   `MD5("peter")` is deterministic and would be identical for *any*
   account using that password.

4. **Timing behavior (weaker, indirect signal).** Purpose-built password
   hashing algorithms (bcrypt, scrypt, argon2) bundle salting together
   with deliberate slowness. Consistently slow, non-network-latency-
   explained auth response times suggest one of these is in use, which
   typically implies salting as well. Fast sub-millisecond hashing (raw
   MD5/SHA1, as in this lab) suggests neither.

## Script Workflow

- `requests.Session()` per attempt sets the forged `stay-logged-in`
  cookie directly, skipping `/login` entirely — the vulnerability lives
  in cookie verification, not the login form.
- `ThreadPoolExecutor` (15 workers) parallelizes the wordlist sweep since
  each request is I/O-bound.
- Success marker (`"Your username"`) was determined empirically first —
  by testing wiener's known-valid cookie against `/my-account` and
  inspecting the response — rather than assumed. This confirmed the
  marker is username-agnostic and would apply to any successfully
  authenticated account, including the target.
- `threading.Event` + `cancel_futures=True` stop the sweep as soon as a
  match is found instead of exhausting the full wordlist.

## Why It Matters Generally

- **Client-controlled state should never encode a security-sensitive
  hash where the client can experiment offline.** Once an attacker can
  compute forged hashes locally and simply test cookies against the
  server, the server's role in "protecting" the password is reduced to a
  single yes/no check per guess — which is trivially automatable.
- **Fast hash algorithms (MD5, SHA-1, SHA-256) are unsuitable for
  password storage**, even setting aside collision weaknesses, because
  their speed is exactly what makes large-scale guessing feasible.
  Purpose-built slow KDFs (bcrypt, scrypt, argon2) exist specifically to
  make each guess expensive.
- **Unsalted hashes leak information across the whole user base at
  once.** Any password reuse between accounts becomes immediately visible
  and a single cracked hash effectively cracks every account sharing that
  password.
- This lab is a variation on a theme common across the auth labs studied
  so far: security controls that look strong in isolation (hashing,
  encoding, cookie opacity) but collapse once an attacker has a
  known-plaintext foothold or can test guesses offline/at scale, without
  the server enforcing any friction.

## Remediation

- Use a purpose-built, slow, salted password hashing algorithm (bcrypt,
  scrypt, or argon2) instead of raw MD5/SHA-family hashes.
- Never derive session/persistence tokens directly and deterministically
  from the password hash in a way an attacker can forge offline — use a
  random, server-issued, unpredictable token stored server-side instead.
- Ensure salts are unique per user and sufficiently random; store them
  securely alongside (not instead of) the hash.
- Rate-limit or monitor repeated failed authentication attempts, even
  when they arrive as cookie-based requests rather than traditional login
  POSTs.
- Avoid exposing any directly hash-derived value to the client at all if
  it can be avoided — opaque, randomly generated session identifiers with
  server-side lookup remove the offline-guessing attack surface entirely.