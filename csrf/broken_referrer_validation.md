# PortSwigger Lab: CSRF with Broken Referer Validation

## Overview
This lab focuses on a Cross-Site Request Forgery (CSRF) vulnerability present in the email change functionality of the application. The server attempts to validate the `Referer` header to block cross-domain requests, but the validation mechanism has weaknesses that can be exploited.

## Objective
Use your exploit server to host an HTML page that performs a CSRF attack to change the viewer's email address.

## Credentials
- **Username**: `wiener`
- **Password**: `peter`

## Steps to Solve the Lab

### Step 1: Log In and Capture the Request
1. Open Burp's browser and navigate to the lab URL.
2. Log in with the provided credentials.
3. Go to the **"Update email"** form and submit it with a new email address (ensure it’s unique).
4. Capture the resulting request in Burp's Proxy History.

### Step 2: Test Referer Validation
1. Send the captured request to Burp Repeater.
2. Modify the `Referer` header to an arbitrary incorrect domain (e.g., `Referer: https://arbitrary-incorrect-domain.net`) and send the request. 
   - **Result**: The request is rejected.

### Step 3: Bypass the Referer Check
1. Copy the original domain of your lab instance.
2. Append it as a query string to the erroneous domain in the `Referer` header.
   - Example:
     ```
     Referer: https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net
     ```
3. Send the modified request. 
   - **Result**: The request is accepted, as it contains the valid domain somewhere in the `Referer`.

### Step 4: Create CSRF Proof of Concept (PoC) HTML
1. Host a CSRF PoC exploit on your exploit server.
2. Edit the JavaScript in your HTML so that the `history.pushState()` method includes your lab instance URL:
   ```javascript
   history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net");
this js command appends the url to the exploit server url path since the logic in target machine only checks if there is a match or the origin

### Summary of Vulnerability
- Type: CSRF with broken Referer validation.
- Mechanism: The server accepts any Referer containing the valid domain, allowing attackers to craft requests that bypass validation.
- Mitigation Gaps: The server’s reliance on an inadequate check creates exploitable situations for CSRF attacks.

### Key Learnings
- Understanding CSRF attacks and their implications.
- Identifying flaws in the implementation of Referer validation.
- Practical experience in crafting and delivering CSRF exploits.