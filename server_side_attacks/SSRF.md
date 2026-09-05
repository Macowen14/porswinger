# Lab Notes: Basic SSRF Against Another Back-End System

## Vulnerability Concept

Server-Side Request Forgery (SSRF) occurs when an application takes a
user-supplied URL (or part of one) and uses it to make an HTTP request
from the **server**, rather than the client. The server effectively
becomes a proxy that the attacker controls.

In this lab, the "Check stock" feature sends a `stockApi` parameter in
a POST body to `/product/stock`. The back-end takes that value and
fetches it directly — with no validation that it points to the
legitimate stock-checking service. Because the request originates from
the server, it can reach hosts the attacker's browser cannot: private
RFC1918 address space (`192.168.0.0/24`) that only exists inside the
application's own network.

The internal admin interface on port `8080` is a second trust boundary
that relies on network position instead of authentication — SSRF
collapses that boundary because the attacker borrows the server's
network position.

## Exploitation Logic

Two phases:

**1. Host discovery**
The internal subnet and port were known (`192.168.0.X:8080`) but not
the exact host. Every non-existent host causes the app server's
outbound request to fail, producing a distinctive error page
(`Could not connect to external stock check service` / `Internal
Server Error`). The one host actually running something on `8080`
does *not* produce that error — its response looks different (real
HTML, different length, 200 status). This is the same "find the
outlier" pattern used in the timing-based enumeration labs, just
surfaced as a text/response diff instead of a statistical one.

**2. Exploiting the found host**
Once the live host is found, every further interaction with the
internal admin panel — viewing it, and issuing the delete action for
`carlos` — has to be laundered through the same `stockApi` parameter
on the *real* lab domain. The attacker never talks to `192.168.0.X`
directly; they never can. Every step is: set `stockApi` to the
internal URL you want the server to fetch on your behalf, read the
response.

## Script Workflow

- `requests.Session()` to persist the lab's session cookie across
  requests (same pattern as the auth labs).
- `scan_backend_ip()`: POSTs (not GET — this endpoint only accepts
  POST) `stockApi=http://192.168.0.{i}:8080/admin` as a
  form-urlencoded body (not a header — the parameter lives in the
  POST body, confirmed from the raw Burp request).
- Detection: check for the *absence* of the known failure markers
  (`Internal Server Error`, `Could not connect to external`) rather
  than searching for a specific success string — more robust since
  the failure text is fixed and known, but the success page content
  varies.
- Loop `i` from 1–254, collect any IP that doesn't match the failure
  pattern.
- Stage 2 (manual once the host is found, or scriptable the same way):
  POST `stockApi=http://192.168.0.X:8080/admin` to view the panel,
  extract the delete link/form for `carlos` from the returned HTML,
  then POST `stockApi=http://192.168.0.X:8080/admin/delete?username=carlos`
  (or the lab's actual generated delete URL) through the same
  `/product/stock` endpoint to execute it.

Key bugs from the first draft, worth remembering for future labs:
- Confirm parameter *location* (header vs body vs query) directly
  from the intercepted request before writing detection logic —
  assuming it's a header cost the whole first version.
- Match HTTP method exactly (`POST` vs `GET`).
- String matching for error detection is case-sensitive — verify the
  exact casing from the actual response, don't guess.
- Malformed target URLs (missing `http://` scheme) can produce
  requests that don't fail the way you expect, making false positives
  look like they're working when they aren't actually testing anything.

## Why It Matters Generally

SSRF is a network-topology bypass, not a data-validation bug in the
usual sense — the "sanitization" that's missing isn't about malicious
characters, it's about *where the request is allowed to go*. This
makes it distinct from most injection-class bugs and means classic
input sanitization (stripping quotes, encoding HTML) does nothing to
stop it.

Real-world impact scales with what's reachable from the server:
- Cloud metadata endpoints (`169.254.169.254` on AWS/GCP/Azure) often
  return IAM credentials with no auth required — SSRF into a cloud
  environment can mean full account takeover, not just LAN access.
- Internal admin panels, monitoring dashboards, or databases that
  were never meant to be internet-facing become reachable.
- SSRF can sometimes be chained into port scanning (as done here),
  protocol smuggling (`gopher://`, `file://` schemes), or even RCE if
  the internal service itself is vulnerable.

## Remediation

- Allowlist acceptable destination hosts/URLs rather than trying to
  blocklist "bad" ones — blocklists are trivially bypassed (DNS
  rebinding, alternate IP encodings, redirects).
- Disable unused URL schemes (`file://`, `gopher://`, `dict://`) at
  the HTTP client library level.
- Network-level segmentation: the app server shouldn't have a route
  to internal admin interfaces it doesn't need, independent of
  application-layer controls.
- Don't return raw upstream responses to the client — the fact this
  app happily returned the internal admin panel's HTML back to the
  user is itself an amplifying factor.

---

# Reference: SSRF Generally

## Core definition
SSRF = tricking a server into making an HTTP (or other protocol)
request to a destination the attacker chose, using the server's
network position and/or credentials rather than the attacker's own.

## Common variants

| Variant | Description |
|---|---|
| **Basic / in-band SSRF** | Response from the internal request is returned directly to the attacker (this lab). Easiest to exploit — full visibility into the response. |
| **Blind SSRF** | The request fires but the response isn't returned to the attacker. Detected via out-of-band techniques (e.g. Burp Collaborator, DNS/HTTP callbacks) — you infer success from a callback hit, not response content. |
| **Partial / URL-parsing SSRF** | The app does attempt validation (allowlist, regex, blocklist) but the parser can be tricked — e.g. `https://expected-host.com@attacker.com`, embedded credentials tricks, or bypassing via `#` fragment tricks. |
| **SSRF via open redirect** | App validates the target host, but the target host issues a redirect to an internal address the app then follows without re-validating. |
| **DNS rebinding SSRF** | Validation resolves a domain once (external IP), but by the time the request actually fires, DNS has changed to resolve internally — TOCTOU on hostname resolution. |

## Typical targets once SSRF is confirmed

- Cloud metadata services (`169.254.169.254/latest/meta-data/` on AWS,
  similar on GCP/Azure) — credential theft.
- Internal-only admin panels / management interfaces (this lab's
  pattern).
- Other internal microservices not meant to be directly reachable.
- `localhost` / `127.0.0.1` to reach services only bound to loopback
  on the same host.
- Port scanning internal ranges by diffing response times/content
  across an IP/port sweep (same technique used here).

## Bypass techniques for weak filters

- Alternate IP representations: decimal (`3232235521`), octal
  (`0300.0250.0.1`), hex (`0xC0A80001`), IPv6-mapped
  (`::ffff:192.168.0.1`).
- `0.0.0.0` — often not blocked, frequently routes to localhost on
  many systems.
- Redirect chains — host a redirect on an allowed domain that 302s to
  the internal target.
- Case/encoding tricks in the allowlist check itself if it's a
  string/regex match rather than a real URL parse.

## Detecting SSRF in the wild (bug bounty context)

- Any feature that fetches a URL server-side on your behalf: webhooks,
  "import from URL," PDF/screenshot generators, link previews, stock
  checkers, avatar-from-URL uploaders, XML parsers, SSO/OAuth callback
  handling.
- Test with your own Burp Collaborator / equivalent listener first to
  confirm blind SSRF before trying internal IPs — confirms the
  primitive exists before spending time on internal discovery.

## Remediation checklist (general, beyond this lab)

- Allowlist destinations at the application layer.
- Network segmentation so the app server has no route to sensitive
  internal hosts regardless of app-layer bugs (defense in depth).
- Disable unneeded URL schemes.
- Validate *after* DNS resolution, not before, or re-validate
  immediately before the request fires, to reduce DNS-rebinding
  windows.
- Never return raw internal response bodies/headers to the client.