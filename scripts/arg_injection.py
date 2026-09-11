"""
Local, harmless playground for ARGUMENT INJECTION (not shell injection).
Everything here talks to 127.0.0.1 only — nothing leaves your machine.

Run:
    python3 arg_injection_demo.py

What it does:
  1. Spins up a local HTTP server on 127.0.0.1:8000 serving a harmless file.
  2. Lets you type a "storeID"-style input, same as the earlier labs.
  3. Runs it through a VULNERABLE call (no "--") and a FIXED call (with "--")
     so you can compare behavior side by side.
"""

import http.server
import socketserver
import subprocess
import threading
import os
import time

PORT = 8000
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))


def start_server():
    os.chdir(SERVE_DIR)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("127.0.0.1", PORT), handler) as httpd:
        httpd.serve_forever()


def run_curl(args_after_curl, label):
    print(f"\n--- {label} ---")
    print("argv:", ["curl"] + args_after_curl)
    result = subprocess.run(
        ["curl"] + args_after_curl,
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    print("stdout:", result.stdout.strip() or "(empty)")
    print("stderr:", result.stderr.strip() or "(empty)")


def main():
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    time.sleep(0.5)  # let the server come up
    print(f"Local server running at http://127.0.0.1:{PORT}/payload.txt")

    print("\nTry a normal input first, e.g.:  payload.txt")
    print("Then try an injection payload, e.g.:")
    print("  -o /tmp/pwned_by_lab.txt http://127.0.0.1:8000/payload.txt")
    print("(this only ever writes to /tmp on YOUR machine — totally local)")

    user_input = input("\nEnter path/query for the app to fetch: ").strip()

    # This mimics a REALISTIC vulnerable pattern: the app splits user input
    # on whitespace to build a list of args (e.g. an "advanced query" field,
    # or a config-driven CLI wrapper). THIS split is what turns one string
    # into multiple argv elements -- no shell required for that, it's plain
    # Python. If we did NOT split (kept user_input as one element), curl
    # would just see one weird literal string and nothing would inject
    # (try changing split() to a no-op below to prove that to yourself).
    args_from_input = user_input.split()

    # VULNERABLE: nothing stops a leading "-" from landing in its own argv
    # slot and being parsed by curl as a flag.
    run_curl(args_from_input, "VULNERABLE (no --, input pre-split into argv)")

    # FIXED: "--" tells curl "everything after this is a literal positional
    # argument, not a flag" per POSIX convention.
    run_curl(["--"] + args_from_input, "FIXED (with --)")

    if os.path.exists("/tmp/pwned_by_lab.txt"):
        print("\n[!] /tmp/pwned_by_lab.txt exists — the vulnerable call wrote a file.")
        with open("/tmp/pwned_by_lab.txt") as f:
            print("    contents:", f.read().strip())
        os.remove("/tmp/pwned_by_lab.txt")  # cleanup so re-runs are clean
    else:
        print("\nNo stray file was written this run.")


if __name__ == "__main__":
    main()