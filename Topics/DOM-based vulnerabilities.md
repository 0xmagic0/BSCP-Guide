# Resources
- Michael Sommer videos
- [Dom Vulnerabilities - z3nsh3ll Playlist](https://www.youtube.com/playlist?list=PLWvfB8dRFqba4RedkuUDWMEkAkP8cdZCW)
# Reconnaissance - Where to look for it
- Look for event listeners in the page source and other files
# Document Object Model (DOM) vulnerabilities
When JavaScript takes user-controlled data from a source and passes it into a sink handling it in an unsafe manner
This would allow the attacker to perform malicious actions
## Sources
A JavaScript property that accepts user-controlled data
Examples:
```js
location.search
document.referrer
document.cookie
document.URL
document.documentURI
document.URLUencoded
document.baseURI
location
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
Stored data
Reflected data
Web messages
```
## Sink
JavaScript function or DOM object that can trigger an dangerous behavior if user-controlled data is passed into it
Examples:
```js
eval()
document.body.innerHTML()
document.write()
window.location
document.cookie
document.domain
WebSocket()
element.src
postMessage()
setRequestHeader()
FileReader.readAsText()
ExecuteSql()
sessionStorage.setItem()
document.evaluate()
JSON.parse()
element.setAttribute()
RegExp()
```
# Vulnerabilities
- Open redirect
Review the server response, DOM, and other loaded files
Check how the webpage is doing cross-page/cross-domain navigation and see if this can be manipulated with user supplied input
- Cookie manipulation
Observe if any cookie is somehow taking user-controlled data and reflecting it
```html
<iframe src="domain?parameters&payload" width="800" height="800" onload='if(!window.x)this.src="domain";window.x=1;'></iframe>
```
- JavaScript injection
- Document-domain manipulation
- WebSocket-URL poisoning
- Link manipulation
- Web message manipulation: `postMessage()` can lead to vulnerabilities if the event listener receiving messages handles the incoming data in an unsafe way
```html
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('payload','*')">
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```
