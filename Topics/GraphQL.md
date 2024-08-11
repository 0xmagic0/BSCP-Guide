# Resources
- [Intigriti Hackacademy videos on GraphQL](https://www.youtube.com/watch?v=Og0k952EsOo&list=PLmqenIp2RQciV955S2rqGAn2UOrR2NX-v&index=67)
- [Popo Hack videos on GraphQL](https://www.youtube.com/playlist?list=PLzgroH3_jK2jDj14lUQRVyHmn0x3i_Cjh)
# Tools
- [GraphQL Visualizer](http://nathanrandal.com/graphql-visualizer/)
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance)
# Finding GraphQL endpoints
- GraphQL APIs use the same endpoint
- This can be done manually or with Burp Scanner
## Universal query to probe
POST Request
```http
query{__typename}
```
Response
```http
{"data": {"__typename": "query"}}
```
GET Request
```http 
GET /api?query=query{__typename}
GET /graphql?query=query{__typename}
```
Short list of possible ednpoints
```
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
```
Test to see what request methods and content type are being accepted
```http
GET
POST
content-type: application/json
content-type: x-www-form-urlencoded
```
## Exploiting unsanitized arguments
Look for access control issues, IDORs, etc
```json
    #Query to get missing product

    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```
# Discovering schema information
- Use the introspection queries
- Burp Suite can facilitate these queries
    - [GraphQL using Burp](https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql#accessing-graphql-api-schemas-using-introspection)
    - To test intorspection: Send the request to the Repeater tab -> Right click -> Select GraphQL -> Set introspection query
    - To save response on the site map: Right click on the response -> GraphQL -> Save GraphQL queries to site map
- Use a GraphQL visualizer to view the relationships between schema entities
- If introspection is disabled, maybe suggestions (a feature in Apollo GraphQL) might aid studying the API and find useful information
    - [Clairvoyance](https://github.com/nikitastupin/clairvoyance) is a tool that uses suggestions to automatically recover GraphQL schema
# Bypassing GraphQL introspection defenses
- They might do regex to detect the usage of `_schema`
- Try to bypass it using special characters: white spaces, new lines, and commas at the end. These are ignored by GraphQL
- Encoding might be needed if sending the query in a GET request: white spaces(%20), new lines(%0a), and commas(%2c). 
```json
  #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }
```
- Try a different method like a GET request, or a POST request with a content-type of `x-www-form-urlencoded`.
```http
# Introspection probe as GET request

GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```
# Bypassing rate limiting using aliases
- Aliases could be used to brute force a GraphQL endpoint
- Lab to study: https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass
- Python can be used to automate this task
```json
    #Request with aliased queries

    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }
```
# GraphQL CSRF
- They arise due to:
    - Lack of content-type `application/json` validation on POST requests
    - No CSRF tokens are implemented
- Try to send the data in a request with the content-type of `x-www-form-urlencoded`
- To change the content-type type simply use the "Change request method" functionality twice. Convert the graphql to a url encoded query
