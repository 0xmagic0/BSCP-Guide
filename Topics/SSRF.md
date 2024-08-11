# Resources
- [Portswigger - SSRF](https://portswigger.net/web-security/ssrf)
- [Rana Khalil - SSRF Complete Guide](https://www.youtube.com/watch?v=ih5R_c16bKc&list=PLuyTk2_mYISIlDtWBIqmgJgn6CYlzHVsQ)
- Michael Sommer videos
- [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.youtube.com/watch?v=voTHFdL9S2k)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Hacktricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [Cracking the lens: targeting HTTP's hidden attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
# Burp Suite Extensions
- Collaborator Everywhere
# What is SSRF?
In simmple terms: Making the server side of the application make requests to unintended locations
The attacker is exploiting the trust granted to requests originating from the machine hosting the web application and the internal systems
Ask This Question: Are the URL parameters being properly validated at te backend?
# What can you do with SSRF?
- Port scan the network
- Enumerate the system, e.g.: Get the Instance Metadata
- Get access to restricted functionality
- Access sensitive data
- Remote Code Execution
# Type
- Regular/ In Band
- Blind / Out-of-Band
# Example
FROM
```http
POST /some/endpoint HTTP/1.0
Host: mydomain

parameter=https://some-intended-endpoint.com/retrieving/something%3Fid%3D13
```
TO

```http
POST /some/endpoint HTTP/1.0
Host: mydomain

parameter=http://localhost/unintended-endpoint
```
Use:
- localhost
- 127.0.0.1
- Alternative representation of 127.0.0.1 => 2130706433, 017700000001, 127.1
- spoofed.burpcollaborator.net <= Resolves to 127.0.0.1
- Other backend system's IP - 192.168.0.x:portNumber
- nip.io <= Wildcard DNS for any IP Address
- Burp Suite Collaborator

# Methodology to Find SSRF - Black-Box
## Map the application:
- Requests expecting a url value to perform actions
- Requests fetching data from backend
- Identify requests that contain hostnames, IPs, or URLs
- Try the Referer Header
- Chain with an open redirect
- Automate with Extension - Collaborator Everywhere
- Walk throuhgh all the pages
- Try to understand the logic of the application
## Discovery
- Fuzz the parameter and tweak the payload to bypass defenses
- While exploiting a Blind SSRF, look for any differences between response (time, response status, etc)
# Methodology to Find SSRF - White-Box
Note: The Black-Box testing methodology steps are also followed
## Source Code Review
- Identify all request parameters that accept URLs
- Review security measures (blacklist, whitelist, etc) and see how to bypass them

# How to Exploit
Depends on the type of SSRF
## Regular / In-Band SSRF
### No filter
- Determine if a port number can be specified
- Can you port-scan the internal network?
- Can you connect to other services on the loopoback address?
### Filter
- Use bypass techniques - Check resources
    - Try different representations of `localhost` and `127.0.0.1`
- Encode the payload
    - URL encoding
- DNS Rebinding attack - Register a domain name that resolves to internal IP address
- HTTP Redirection - Does the application has an open redirect vulnerability? Combine it with the SSRF and make requests to the desired system
- HTTP Redirection - Use your own server that redirects to an internal IP address
- Exploit inconsistencies in URL parsing
## Blind / Out-of-Band SSRF
- Attempt to trigger an HTTP request to an external system under control
    - Use Burp Collaborator
    - Automate with Extension - Collaborator Everywhere
- Use bypass techniques - Check resources
# Hidden attack surface
- Partial URL in requests
- URLs within data formats
- Referer header
# A New Era of SSRF
- URL parsing discrepancies in the authority domain 
    - Compared cURL to the parses of other languages like PHP
- Nodejs - Unicode encoding to bypass filters
    - NN for \xFF\x2E\xFF\x2E => the \xFF gets dropped so it becomes \x2E\x2E which is `..`
    - Same principle applies for CR-LF attacks => -* in unicode is U+FF0D U+FF0A which is `\r\n`
