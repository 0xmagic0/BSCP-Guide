# Resources
- Michael Sommer videos
- [CSRF Playlist - Rana Khalil](https://www.youtube.com/playlist?list=PLuyTk2_mYISKn1UzXAFl_DA3MaEJ9J-yq)
- [CSRF Playlist - Jarno Timmermans](https://www.youtube.com/playlist?list=PLGb2cDlBWRUXkNttyU7hqkQg7zNmnb396)
# Bypass Protection
## CSRF Token Bypass
- CSRF depends on the request method (change POST request to GET)
- CSRF token is validated if it is present (Remove it from the request)
- CSRF token is not tied to user session (Include a valid CSRF token to the CSRF PoC)
- CSRF token is tied to a non-session cookie
    - Can you set a cookie via session fixation CRLF payload?
    - If CRLF is possible, craft the CSRF PoC with an <img> element with the vulnerable request for session fixation as the `src` and onerror submit the form
```html
<html>
    <body>
    <!-- CSRF code here-->
    <form>
    <!-- POC code-->
    <!-- CSRF code here-->
    </form>
    <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
    </body>
</html>
```
- CSRF token is duplicated in cookie (similar to when it is tied to a non-session cookie, using the cookie setting route and make sure the cookie and CSRF token are the same)

## SameSite
SameSite:
- Strict: The cookie will not be sent in any cross-site request
    - This could be bypassed with a client-side redirect
- Lax: The cookie will be sent if the request uses the GET method or if performed via a top-level navigation
    - If the cookie is not set with the "SameSite" flag. This means that Chrome will use "Lax" as default but there is a 120 second window
- None: no protection

Bypass when SameSite is set on Cookies: Use GET method as the cookie won't be sent on POST requests.
- SameSite Lax Bypass via method override:
    - Use an HTTP method spoofing approach
    - Use a GET request, the server might only allow POST requests, so trying overriding the method add `&_method=POST` into the endpoint path
    - Use the <script> tag and use document.location to cause a top-level navigation).
- SameSite Strict bypass via client-side redirect:
    - Similar payload using <script> and `document.location`
    ```html
    <script>
    document.location = ''
    </script>
    ```
    - Use an open redirect and a path traversal to craft the GET request CSRF payload
- SameSite Strict Bypass via sibling domain Also involves Cross-site WebSocket hijacking (CSWSH):
    - Other sibling domains that are vulnerable to XSS might be used to deliver the payload to the malicious CSRF request
    - Check in the HTTP requests for disclosure of sibling domains: E.g.: In the server response headers or body
    - Trigger a redirection with `document.location` to the xss vulnerable sibling domain
- SameSite Lax Bypass via cookie refresh:
    - Observe that the cookie is not set with the "SameSite" flag. This means that Chrome will use "Lax" as default but there is a 120 second window
    - If there is a mechanism to refresh the cookie, craft a CSRF PoC that refreshes the user cookie with a pop-up window
    - Bypass popup blocker: Change the PoC to induce the victim to click on the page and use a window.onclick event handler
    - To avoid timing issues use setTimeout() to delay the form submission until after updating the user's session cookie

## Bypass Referer header check
- Validation depends on the header being present:
    - Craft a CSRF PoC that causes the browser to drop the Referer header, to accomplish this add `<head><meta name="referrer" content="never"></head>` to the PoC
- Referer header with broken validation:
    - Check how the referer header is being validated
    - The expected value could be inserted after the query `?` symbol
    - The expected value could be a subdomain of an attacker controlled domain
    - Modify the CSRF Poc `history.pushState("", "", "/?expected-value.net")`
    - Some browsers might strip the query string form the referer header by default .Add `Referrer-Policy: unsafe-url` to the exploit server response to circumvent this issue
