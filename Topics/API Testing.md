# Resources
- [Intigriti Hackademy videos on API Testing](https://www.youtube.com/watch?v=AxzpOVS23o8&list=PLmqenIp2RQciV955S2rqGAn2UOrR2NX-v&index=62)
- [API Testing Playlist - Popo Hack](https://www.youtube.com/playlist?list=PLzgroH3_jK2ilNsKWDCghJpb7VfxO_h82)
# Extension
- JS Link Finder
- Content type converter extension
# Methodology
- Recon:
    - Find the endpoint
        - Use a payload list
        ```
        /api/swagger/v1
        /api/swagger
        /api
        ```
        - Burp Scanner
        - JS Link Finder
        - Manual JavaScript file review
    - Find documentation
        - Use Burp Scanner
        - Use a payload list
        ```
        /api
        /swagger/index.html
        /openapi.json
        ```
    - Find parameters
    - Supported Methods
        - Use Burp's Built-in HTTP verbs list
    - Determine accepted Content-Type
        - Some APIs might be vulnerable if the data format is changed. For example the API might be susceptible to injeciton attacks if the format is changed from JSON to XML
        - Content type converter extension could be used to facility the re-formatting
    - Rate limits
    - Authentication Mechanisms
# Vulnerabilities
- Exploiting an API endpoint using documentation
    - Follow the recon methodology on the api endpoint
    - Find the API documentation endpoint
- Finding and exploiting an unused API endpoint
    - Follow the recon methodology on the api endpoint
    - Find interesting functionality
    - Determine supported methods
- Exploiting a mass assignment vulnerability
    - Follow the recon methodology on the api endpoint
    - Identify hidden parameters
    - Inspect the objects returned by the API responses
- Exploiting server-side parameter pollution in a query string: The server might be passing user controlled data to a backend-api
    - URL encode special characters and see how the API responds: #,&,=
    - Use # to truncate the query string
    - Inject a string after the special character to investigate differences in the response
    - Use & to inject more parameters (valid or invalid): This could be used to override existing parameters 
        - Use burp intruder and burp's lists to brute force the server-side variable name
        - Inspect JavaScript files to find more parameters
