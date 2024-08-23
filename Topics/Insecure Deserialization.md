# Resources
- [Insecure Deserilization Playlist - Emanuele Picariello](https://www.youtube.com/playlist?list=PL16wrrijM0H-v1GBbBWYSxSq8-2WC3rBM)
# Extensions & Tools
- [ysoserial](https://github.com/frohoff/ysoserial)
- Java Deserialization Scanner
- [PHPGGC](https://github.com/ambionics/phpggc)
- Hackvertor
# Types of serialization
- String format
- Binary format
# Reconnaissance - Where to look for it
- Look for any data passed to the web application that looks like serialized data
- Look for files disclosing source code
- Generate error messages to disclose information
- Look for developer comments that disclose information
- Cookies
- Once serialized data has been found, modify it to see how the server responds
# How to identify it
- Look for any data passed to the web application that looks like serialized data
- To be able to do this you need to become familiar with the format used by the programming language
## PHP
- String format: letters represent the data type and numbers the length
```php
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```
- The methods for serialization are `serialized()` and `unserialized()`
### Modifying data types
- Supply unexpected data types
- Loose comparison operator `==` leads to weird behaviours
- In a integer == string comparison, PHP tries to convert the string to integer
```php
5 == "5" // evaluates to true
5 == "5 of something" // evaluates to true
0 == "A string" // evaluates to true
i:0 == s:4:"aaaa" -> 0 == "aaaa" //evaluates to true
```
## Java
- Binary format
- serialized objects always begin with the same bytes `ac ed` in hexadecimal and `rO0` in base64
- Any class implementing the interface `java.io.Serializable` can be serialized and deserialized
- the `readObject()` is used to read and deserialize data from an `InputStream`
# Using application functionality as a means to exploit insecure deserialization
- The application might perform actions utilizing the data provided in serialized objects
- This behavior could be leveraged by the attacker
# Magic Methods
- They do not need to be explicitly invoked. They execute whenever a particular event occurs
- think of the `__construct()` in PHP and `__init__` in Python
- Some of these methods can be invoked during the deserialization process
- Magic methods that get invoked during the deserialization process on user-controlled data could be used to create exploits
## Arbitrary Object Injection
- The attacker might be able to inject arbitrary object into the serialized object
- Later when the object is deserialized it might be passed to a magic method and trigger the payload
- Inspect the app, check the http sitemap or http history and inspect loaded files
- This files might reveal source code that allows the user to construct a payload
# Gadget Chains
- A gadget is a snipped of code that can help the attacker achieve a particular goal
- An exploit might be constructed by chaining gadgets so the attacker can arrive at the code functionality that would perform the desired action
## Pre-built gadget chains
### ysoserial
- There are tools that allow the attacker to utilize gadget chains previously discovered by other researchers in the past
- **ysoserial** is an example of such tools to be used for Java deserialization

- [thread in github to solve java17> issue](https://github.com/frohoff/ysoserial/issues/203)
Version 1
```bash
java -jar ysoserial-all.jar \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   [payload] '[command]'
```
Version 2 
```bash
java \
 --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED\
 --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED\
 --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED\
 -jar ./ysoserial.jar <payload> <command>
```
- Base64 encode the payload piping the output to `base64 -w 0`
   - For MacOS use the `gbase64` command which accepts the -w flag

- These gadget chains can also be used for detection
   - URLDNS: Use it to make a DNS Lookup request to a supplied URL
   - JRMPClient: Attempt to establish a TCP connection to an IP. Test for an internal IP and then for an external IP. Notice any differences in the response of the server
### PHPGGC
```bash
./phpggc GadgetChain arguments | base64 -w 0
```
- Base64 encode the payload piping the output to `base64 -w 0`
   - For MacOS use the `gbase64` command which accepts the -w flag
- Use the phpggc payload and insert it in the code below
```php
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```
### Search engines
- Use search engines to find documented exploits/gadgets chains
# Exploitation
- Modifying object attributes
- Modifying data types
- Using application functionality to exploit insecure deserialization
- Arbitrary object injection
- Using Pre-built chain tools to exploit magic methods 
