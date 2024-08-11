# Resources
[Host Header Attacks Playlist - Michael Sommer](https://www.youtube.com/playlist?list=PL0W_QjMcqdSB6eYrOrzKsPSede42nWpN3)
# Burp Extension
Param Miner "Guess headers" function to probe for supported headers
# Detection
Check if the host header can be manipulated and how it is being interpreted.
There are different attack vectors to explore.
## Supply an arbitrary host header
```http
From
Host: real-host.net
To
Host: test-host.net
```
## Check for validation
- Check if it is being validated. Change .net for .com
```http
From
Host: real-host.net
To
Host: real-host.com
```
## Check for flawed validation
- Port
- Domain containing the whitelisted one
- Compromised subdomain
```http
Host: website.com:bad-stuff
Host: badwebsite.com
Host: subdomain.website.com
```
## Change the host header value
```http
From
Host: website.com
To
Host: localhost
```
## Send ambiguous requests
- Send multiple Host headers
```http
GET /example HTTP/1.1
Host: website.com
Host: bad-stuff
```
- Supply and absolute URL
```http
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-site-here
```
- Add line wrapping
```http
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```
## Inject host override headers
Use Param Miner "Guess headers" function to probe for supported headers
```http
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```
### Short list of headers
```http
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
```
# Vulnerabilities
- Password reset poisoning
    - See if the Host header could be modified and how it affects the functionality
    - If the host header is not showing results, try `X-Forwarded-Host` or any of the other options
- Web cache poisoning via ambiguous requests
    - Add cache buster. Send double host headers
    - Observe how the server handles this additional header
    - Craft payload and poison the cache
- Routing-based SSRF:
    - Check if no validation is being done on the host header, inject the burp collaborator payload
    - Use the host header to detect an internal resource, `Host: 192.168.0.0`
    - Access admin panel
- SSRF via flawed request parsing:
    - The host header is being validated; however, it can be bypassed by providing an absolute url in the `GET /path` section of the request
    - Using this bypass, scan the internal network to detect sensitive resources
    ```http
    GET https://absolute-url.net/
    Host: 192.168.0.0
    ```
- Host validation bypass via connection state attack
    - Based on the assumption that the front-end server makes, send the requests in a group
    -  Send the group in sequence in a single connection
    - Change the Connection header to `keep-alive`
