### Vulnerabilities

- *Verboase error*
- *Improper restriction to authentication*

Found the following
    Username : ar (Shows incorrect password verboase error on enumeration of usernames)
    Password : ranger 
    Email :  ar@normal-user.net

``` 
Raw response on enumeartion :
 HTTP/2 302 Found
Location: /my-account?id=ar
Set-Cookie: session=rRzkJoAgmrCBMK4W79U0ez7wxm1Jetyz; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0

```

