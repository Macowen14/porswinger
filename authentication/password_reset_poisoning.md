# Lab Notes: Password Reset Poisoning via Middleware (X-Forwarded-Host)

**Lab:** Password reset poisoning via middleware
**Category:** Authentication — Password reset flaws
**Difficulty:** Practitioner

---

## Vulnerability Concept

The application builds the absolute URL for password reset links dynamically at request time, rather than using a hard-coded internal domain. It does this to remain correct when deployed behind a reverse proxy or load balancer, where the `Host` header seen by the app server may not match the public-facing domain the user actually visited.

To solve that, the backend trusts a forwarding header — `X-Forwarded-Host` — as the source of truth for "what domain should this link point to." In a correctly configured deployment, only the organization's own proxy is allowed to set that header. In this lab, the app has no mechanism to verify the header actually came from a trusted proxy — it accepts it from any client, including a direct request sent straight from Burp Repeater.

This is a **trust boundary failure**: a client-controlled header is being used for something security-sensitive (constructing a URL that will carry a secret token) as if it were proxy-controlled.

---

## Exploitation Logic

1. Trigger the password reset flow for the victim (`carlos`), while controlling the request that initiates it.
2. Add `X-Forwarded-Host: <exploit-server-domain>` to that request.
3. The backend reads this header, uses it to build the reset link, and emails that link to the victim.
4. Because the header was attacker-controlled, the link now points to the exploit server instead of the real app — with the valid reset token as a query parameter.
5. The victim (or the lab's simulated victim) clicks the link, hitting the exploit server. The token is captured in the exploit server's access log.
6. Replay that token against the real application's `/forgot-password?temp-forgot-password-token=...` endpoint to set a new password for the victim account.

### Two gotchas encountered debugging this

- **Header value must be a bare hostname.** `X-Forwarded-Host: https://exploit-xxxx.exploit-server.net` (with scheme included) is malformed — a `Host`-style header should never contain a scheme. This produced a `"Host header not present"` error from the app, since the malformed value wasn't parsed as a usable host at all.
  - Fix: `X-Forwarded-Host: exploit-xxxx.exploit-server.net`

- **HTTP/2 has no literal `Host` header.** In HTTP/2 the authority is carried in the `:authority` pseudo-header; Burp's Repeater just displays it as a `Host:` line for convenience. Hand-editing that line, or adding a conflicting `X-Forwarded-Host`, can cause inconsistent normalization between the pseudo-header and the typed header — leading the app-facing proxy to see no usable host at all.
  - Fix: switch the request's protocol from HTTP/2 to HTTP/1.1 in Repeater's request options before editing Host-related headers.

---

## Why It Matters Generally

`X-Forwarded-Host` (and similar `X-Forwarded-*` headers) exist to let an app recover information about the original client request when it's sitting behind a proxy:

| Header | Purpose |
|---|---|
| `X-Forwarded-Host` | The `Host` the original client requested, before a proxy rewrote it |
| `X-Forwarded-For` | The original client's IP address, before it was replaced by the proxy's IP on the TCP connection |

Both are **client-suppliable by default** — a proxy sets them, but nothing stops a direct client from setting them too, unless the app explicitly strips/overwrites them at the edge or only trusts them from a known proxy IP.

The general class of bug: any header prefixed `X-Forwarded-*` is trusted for something impactful (URL construction, IP-based access control, rate limiting, audit logging) without verifying it actually originated from a trusted intermediary. This shows up as:
- **Password reset / account takeover** (this lab) — poisoned links.
- **Rate-limit / lockout bypass** — spoofing `X-Forwarded-For` to appear as a "new" client each request.
- **SSRF / cache poisoning / open redirect** — trusted host used to build redirect or cache-key logic.

---

## Remediation

- Never derive security-sensitive values (URLs containing tokens, access-control decisions) from client-suppliable headers.
- If forwarding headers must be used, only accept them from requests originating at a known, trusted proxy IP — strip/overwrite them from any request arriving directly from the internet.
- Prefer a hard-coded, server-side-configured canonical domain for building absolute URLs (e.g. password reset links) rather than reflecting request headers.
- If dynamic host resolution is unavoidable, validate the resulting host against an allowlist of known-valid domains before using it.