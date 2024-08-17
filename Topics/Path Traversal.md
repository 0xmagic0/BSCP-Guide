# Resources
- [Path Traversal Playlist - z3nsh3ll](https://www.youtube.com/playlist?list=PLWvfB8dRFqbbO2wRawnn6u8JlfttA74wE)
- Michael Sommer videos
# What is directory traversal?
- As an attacker, you can read arbitrary files on the server running the application.
# Reconnaissance - Where to look for it
- Look for requests fetching resources from the server
- Look for requests posting resources to the server
# Walk back the directory
- getFile=thisImage.jpg
- What happens if you input `/etc/passwd` in the getFile parameter?
- Try absolute paths
- Try relative paths
- Try to understand what kind of validation might be done to the path
    - Does it have to start in a specific way?
- Try different payloads like
```http
`../../etc/passwd`
`..././..././etc/passwd`
`..%252f..%252f..%252fetc/passwd`
`....//etc/passwd` - From Portswigger, not seen on the payload lists shown below
`....\/etc/passwd` - From Portswigger, not seen on the payload lists shown below
`..%c0%af` 
`..%ef%bc%8f` - From Portswigger, not seen on the payload lists shown below
`../../etc/passwd%00.png`
and more.
```
# Types of payloads
- URL Encoded - See OWASP and the payloads linked below for examples
- URL Double encoded - See OWASP and the payloads linked below for examples
- Absolute Path
- Deep path traversal
- Nested
- Base folder + payload - e.g.: Instead of just `/etc/passwd/` maybe need to send `/var/www/images/../../../etc/passwd`
- Null byte file extension bypass `%00`
- Combinations of all the above
# Payload list
- Use Burp Intruder with these payloads. 
- Use Match and Replace Regex whenever needed.
    - Burp Suite's pro Fuzzing - path traversal list
    - [Directory Traversal - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)
    - [Path Traversal](https://github.com/omurugur/Path_Travelsal_Payload_List/tree/master)
    - Use an AI to generate a payload list based on specific rules
    - [Hacker Recipes](https://www.thehacker.recipes/web/inputs/directory-traversal)
    - [OWASP Guide with some examples of encoding](https://owasp.org/www-community/attacks/Path_Traversal)
# How to prevent path traversal
- Avoid passing user input to filesystem API altogether
- Validate user input - preferably against a whitelist
- Append this input to a base path and canonicalize it. Validate the canonicalized path.
