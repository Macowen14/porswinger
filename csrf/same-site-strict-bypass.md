# CSRF Lab Notes — SameSite Strict Bypass via Client-Side Redirect

Oct 14, 2026 · @Macowen

## Vulnerability Concept

The change-email function (`POST /my-account/change-email`) has no CSRF token, so it's vulnerable to CSRF in principle. But the session cookie is set with `SameSite=Strict`, which normally blocks this: the browser withholds the cookie on *any* cross-site request, including a top-level navigation (unlike `SameSite=Lax`, which still sends it on top-level GET navigations like clicking a link).

So a naive CSRF PoC hosted on an external exploit server fails — the request to `/my-account/change-email` would arrive with no session cookie attached, since it's cross-site from the browser's point of view.

The lab also has a second, independent bug: the endpoint accepts GET as well as POST. That matters because an attacker-triggered navigation can only ever be a GET — you can't make a victim's browser send a cross-origin POST via a simple redirect.

## Exploitation Logic

The site has a client-side gadget that can be hijacked to turn a cross-site navigation into a same-site one. Posting a blog comment redirects to `/post/comment/confirmation?postId=x`, which briefly shows a confirmation page before a bundled script, `commentConfirmationRedirect.js`, does a client-side redirect built by simple string concatenation: roughly `document.location = '/post/' + postId`.

**Two separate steps, with different normalization rules:**

1. **The initial request (query string, no normalization).** When the browser is sent to `/post/comment/confirmation?postId=1/../../my-account/change-email?email=...`, the `../` sequences inside the query string are just literal characters — HTTP routing doesn't touch them. The server reads `postId` as that raw string and serves the ordinary confirmation page. This request is cross-site (comes from the attacker's page), so the session cookie is withheld — but it doesn't matter, because this endpoint needs no authentication.
2. **The client-side redirect (a real URL, browser-normalized).** The page's own JS concatenates `postId` onto `/post/` and assigns the result to `document.location`. Browsers resolve `../` segments in a URL exactly like a filesystem path:

```
/post/1/../../my-account/change-email
         ^ cancels "1"   → /post/../my-account/change-email
              ^ cancels "post" → /my-account/change-email
```

The browser lands on `/my-account/change-email` — a page that has nothing to do with `/post/...`. Crucially, this second navigation is initiated *from a page already loaded on the target's own origin*, so the browser treats it as same-site, and the `SameSite=Strict` session cookie is attached.

The core bug: the developer assumed `postId` would only ever be a harmless numeric ID glued onto a fixed path. With zero validation, `../` sequences let you redirect the browser's own trusted logic to an arbitrary endpoint — and smuggle an authenticated request past a cookie restriction that was designed to stop exactly this.

## PoC Exploit

Hosted on the exploit server (so it's a genuinely different origin from the target):

```html
<script>
    document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
</script>
```

Key details:

- **The change-email endpoint must accept GET.** Found by sending the captured `POST /my-account/change-email` request to Burp Repeater and using "Change request method" to get the GET equivalent (`?email=...&submit=1`).
- **`%26` instead of a literal `&`.** The `&` separates query parameters on the *outer* confirmation-page URL. If left unencoded, the browser would parse `submit=1` as a second parameter of `/post/comment/confirmation`, not as part of the value assigned to `postId`. URL-encoding it keeps the whole change-email path + query string as one unbroken `postId` value, which the vulnerable JS then concatenates in full.
- **`%40` for `@`** in the email address, for the same reason — kept inside the single `postId` value rather than breaking the URL structure.

## Attack Steps Walkthrough

1. Log in, change your own email once via the normal form; confirm the request has no CSRF token in Burp's HTTP history.
2. Confirm the login response sets `Set-Cookie: session=...; SameSite=Strict`.
3. Post a blog comment; observe the redirect through `/post/comment/confirmation?postId=x` to `/post/x`.
4. Break `postId` on purpose (`?postId=foo`) to confirm the redirect target is built client-side with no validation.
5. Test traversal manually: `?postId=1/../../my-account` lands on the account page.
6. Confirm the two-hop chain works cross-site by hosting the step-5 payload on the exploit server and viewing it from there.
7. In Burp Repeater, change the `POST /my-account/change-email` request method to GET; confirm it still works.
8. Combine: point `postId` at `/my-account/change-email?email=...&submit=1`, URL-encoding `&` as `%26` and `@` as `%40`.
9. Test on yourself; confirm the email changed.
10. Swap in an email the account doesn't already have, then deliver to the victim.

## Why It Matters Generally

`SameSite=Strict` only evaluates the *immediate* navigating context — where the current request is being initiated from — not some global "is this user authenticated" state. It doesn't track intent across a chain of redirects.

Any client-side redirect that builds its destination from an unvalidated URL parameter is a same-site "relay" an attacker can land on from off-site, then use to pivot into a trusted, cookie-bearing request. This generalizes beyond CSRF: the same gadget (unvalidated client-side redirect + browser URL normalization) is also a classic source of open-redirect and client-side path-traversal bugs, independent of any SameSite bypass.

Two independent weaknesses had to line up for this exploit: the missing CSRF token, and the GET-accepting endpoint. Either one alone wouldn't have been enough once `SameSite=Strict` was in place.

## Remediation

- Add a per-session, unpredictable CSRF token to the change-email form and validate it server-side on every state-changing request.
- Restrict the change-email endpoint to POST only; reject GET.
- Validate or whitelist the `postId` parameter server-side before it's ever used to build a redirect path — don't let arbitrary strings reach `document.location` construction.
- Prefer a server-issued redirect (looking up the real post URL by numeric ID server-side) over a client-side redirect built from a raw, attacker-controlled parameter.
- Keep `SameSite=Strict` (it's doing real work here) but don't treat it as a substitute for CSRF tokens — defense in depth, not either/or.
