# Resource
- [Portswigger - Obfuscation using encoding](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
# Table
| Scenario                                    |Example                                   |
|---------------------------------------------|------------------------------------------|
| URL Encoding                                |%22                                       |
| Double URL Encoding                         |%2522                                     |
| HTML Encoding                               |Dec or Hex - alert(1) to &#x61;lert(1)    | 
| HTML Encoding + leading zeros               |javascript&#0000000000000058;alert(1)     |
| XML Encoding                                |821 &#x53;ELECT * FROM information_shc... |
| Unicode                                     |eval("\u0061lert(1)")                     |
| Unicode + leading zeros                     |javascript\u{0000000000003a}alert(1)      |
| Hex encoding                                |eval("\x61lert")                          |
| Octal encoding                              |eval("\141lert(1)")                       |
| Combiantions                                |javascript:&bsol;u0061lert(1)             |
| SQL CHAR Function                           |CHAR(83) or CHAR(0x53)                    |
