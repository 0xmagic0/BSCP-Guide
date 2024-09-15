# Wordlist reference:
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Assetnote](https://wordlists.assetnote.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

# References
- [FFUF.me Website](http://ffuf.me)
- [Nahamsec - Recon Basics](https://www.youtube.com/watch?v=Z9es1_BUXmQ)
- [Bruteforcing with the Wrong Wordlist is a Waste of time!](https://www.linkedin.com/posts/florian-ethical-hacker_penetrationtesting-security-cybersecurity-activity-7118608765918035968-yVZo/)
- [Don't make this recon mistakes](https://www.youtube.com/watch?v=YbIEXJhZxUk)
- [HackingHub](https://app.hackinghub.io/)
- [Turbo Intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)


# Basic Recon
# Asset Discovery
- subfinder 
```bash
subfinder -d domain.com
```
# Information Gathering
- httpx
```bash
# Quickly look at page titles
subfinder -d domain.com | httpx -title -ports 443,8443
```
- nmap - scan
```bash
nmap -v -sV -sC -Pn -p- target
```
- nikto - scan
```bash
nikto -h target
```
# Content Discovery
## Methodology 
### ffuf and gobuster
1. Find The File Extension: Visit urls like `host/index.php`, replace php with another file extension
```bash
ffuf -u https://domain.com/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -v -c
ffuf -u https://domain.com/W1W2 -w /usr/share/wordlists/dirb/common:W1 -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:W2 -v -c
```
2. File bruteforcing:
```bash
gobuster dir -u https://domain.com/ -w seclists/raft-medium-files.txt
```
3. Directory bruteforcing:
```bash
gobuster dir -u https://domain.com/ -w seclists/raft-medium-directories.txt
```
4. Comprehensive Bruteforcing: Use the previously identified file extensions alongside general purpose ones e.g.: `.txt`,`.log`,`.pdf`, or `.zip`. Do not use a wordlist that contains file extensions already.
```bash
gobuster dir -u https://domain.com/ -w seclists/raft-medium-words.txt -x log,txt,php,html,phtml
```
### Tips
- For apps running on windows use a lowercase wordlist like `seclists/raft-medium-files-lowercase.txt`
- Add file extensions relevant to the technologies discovered

- gobuster
```bash
gobuster dir -u https://domain.com/ -w wordlist
```
- ffuf
```bash
ffuf -w /wordlist/path/file.txt -c -u https://domain.com/FUZZ
```
### Turbo Intruder
1. Send the request to Turbo Intruder
2. Select the appropriate Script. Set the %s on the desired injection point
3. Set a wordlist
4. Tweak the `concurrentConnections`, `requestsPerConnection` to optimal values, and set `pipeline` to True
Note: If confused watch the demo made by the Portswigger team in the link provided
