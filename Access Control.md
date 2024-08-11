# Resources
- [Access Control Playlist - Rana Khalil](https://www.youtube.com/playlist?list=PLuyTk2_mYISJxFXJDdkDZjXD4K1yl3NFU)
- [Access Control Playlist - Popo Hack](https://www.youtube.com/playlist?list=PLzgroH3_jK2jRFuqp2g0ZlIf6UotnZ-Lr)
- [Portswigger](https://portswigger.net/web-security/access-control)
- [403 Bypasser](https://github.com/sting8k/BurpSuite_403Bypasser)
- [403 & 401 Bypasses](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses)
- [OWASP Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
- [AuthMatrix - Burp Extension](https://github.com/SecurityInnovation/AuthMatrix/)
# What is it?
- Lack of access control
- Unauthenticated or unauthorized user being able to access resources or perform actions that he should not be able to do
# Vertical privilege escalation
- Regular user to admin
- Look for higher privilege functionalities
# Horizontal privilege escalation
- Regular user to regular user
# Manual versus Automated
- Both are necessary
- Start with the easiest step = /robots.txt and build up from there
- Wordlists speed up the general discovery process
- Manual review will find endpoints and functions unreachable through generic wordlists or with obfuscated names
# Reconnaissance - Systematic steps
- Check /robots.txt
- Walk the web app to see patterns
- Check the source code for endpoints
- Look for comments in the code
- Look for source js.map exposure. This might give away more endpoints
- Check the Burp Suite HTTP history tab with the Search functionality
- Request's retrieving user information
- Request's modifying user information
# Parameter-based access control
- Sometimes access is determined by parameters that the user is able to manipulate.
- If the parameters are not validated, then user can simply modify them and get access
- Hidden field
- A cookie
- A query string parameter
```http
https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1
```
- Sending a parameter in the body of the request (Mass assignment).
# URL based controls bypass
- There are controls on the specific URL but they could be bypassed with:
- X-Original-URL and X-Rewrite-URL
- Start testing with `X-Original-URL: /invalid` and look for a `not found`
- This can tell if the back-end system is processing the URL from the X-Original-URL header.
```http
GET / HTTP/1.1
X-Original-URL: /doesnotexist

```
- Append parameters to the original query string to pass it to the endpoint on the X-Original-URL
```http
GET /?parameter=value HTTP/1.1
X-Original-URL: /admin/action

```
# HTTP-Method based controls 
- This can be done manually or Burp Suites tool "Change request method"
FROM
```http
POST /admin-roles HTTP/2
Host: uuid.web-security-academy.net
{more headers}

username=carlos&action=upgrade
```
TO
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Host: uuid.web-security-academy.net
```
# URL-matching discrepancies
- Check hacktricks 403 & 401 Bypasses for a longer list of examples
- Path fuzzing
```
site.com/secret –> HTTP 403 Forbidden
site.com/SECRET –> HTTP 200 OK
site.com/secret/ –> HTTP 200 OK
site.com/secret/. –> HTTP 200 OK
```
# IDORS
Insecure direct object reference
`https://mydomain.com/balance?userId=33`
`https://mydomain.com/balance?userId=uuid`
# Vulnerability in multi-step processes
- An action might be performed and the implementation requires several steps (requests)
    - Step 1 (access control in place)
    - Step 2 (access control in place)
    - Step 3 (no access control)
- Test different parts of the workflow
# Referer-based access control
- An endpoint like `/admin/deleteUser` looks for `/admin` on the Referer header
# Location-based access control
- Bypass:
    - VPN
    - Manipulating the client side geolocation mechanism
    - X-Forwarded-For: IP
    - Other headers, check the OWASP and Hacktricks resources for more examples
# Preventing access control issues
- There are many ways. A general way to think of it is "Explicit access, implicit denial"
- Deny by default if it is not meant to be public
