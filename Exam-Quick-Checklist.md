# Topics
- [Quick recon](/Exam-Quick-Checklist.md#quick-recon)
- [Essential Skills](/Exam-Quick-Checklist.md#essential-skills)
- [SQL Injection](/Exam-Quick-Checklist.md#sql-injection)
- [HTTP request smuggling](/Exam-Quick-Checklist.md#http-request-smuggling)
- [Web Cache Poisoning](/Exam-Quick-Checklist.md#web-cache-poisoning)
- [Cross-site Scripting - XSS](/Exam-Quick-Checklist.md#cross-site-scripting---xss)
- [CSRF](/Exam-Quick-Checklist.md#csrf)
- [Clickjacking](/Exam-Quick-Checklist.md#clickjacking)
- [DOM-based vulnerabilities](/Exam-Quick-Checklist.md#dom-based-vulnerabilities)
- [CORS](/Exam-Quick-Checklist.md#cors)
- [XXE](/Exam-Quick-Checklist.md#xxe)
- [Prototype Pollution](/Exam-Quick-Checklist.md#prototype-pollution)
- [SSRF](/Exam-Quick-Checklist.md#ssrf)
- [OS Command Injection](/Exam-Quick-Checklist.md#os-command-injection)
- [Server-Side Template Injection - SSTI](/Exam-Quick-Checklist.md#server-side-template-injection---ssti)
- [Path Traversal](/Exam-Quick-Checklist.md#path-traversal)
- [Access Control](/Exam-Quick-Checklist.md#access-control)
- [Authentication](/Exam-Quick-Checklist.md#authentication)
- [WebSockets](/Exam-Quick-Checklist.md#websockets)
- [Insecure Deserialization](/Exam-Quick-Checklist.md#insecure-deserialization)
- [Information Disclosure](/Exam-Quick-Checklist.md#information-disclosure)
- [Business Logic](/Exam-Quick-Checklist.md#business-logic)
- [Host Header attacks](/Exam-Quick-Checklist.md#host-header-attacks)
- [OAuth authentication](/Exam-Quick-Checklist.md#oauth-authentication)
- [File upload](/Exam-Quick-Checklist.md#file-upload)
- [JWT](/Exam-Quick-Checklist.md#jwt)
- [GraphQL](/Exam-Quick-Checklist.md#graphql)
- [Race conditions](/Exam-Quick-Checklist.md#race-conditions)
- [NoSQL Injection](/Exam-Quick-Checklist.md#nosql-injection)
- [API Testing](/Exam-Quick-Checklist.md#api-testing)
- [Web LLM attacks](/Exam-Quick-Checklist.md#web-llm-attacks)

# Quick recon
- Start an active scan on interesting requests
- Run scans on selected insertion points
    - URL parameters
    - cookies
    - JSON body parameters
- Use the HTTP Request Smuggling Probe
- Use Param Miner to Probe for different vulnerabilities
    - Web Cache Poisoning
    - Host header injection
- Use payloads provided by Portswigger academy and other online resources to speed up the process
# Essential Skills
### Objective
- Quickly detect potential vulnerabilities
### Most Probable Exam Stages to Find This Vulnerability
- Any
### Reconnaissance - Where to look for it
- Interesting Functionality
- API
- Cookies
### Reconnaissance - Determine the type
- Interesting Functionality
- API
- Cookies
# SQL Injection
### Objective
- Extract Information: Username, Passwords, and more
- Subvert application logic: Login function, and more
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- URL parameters
- Login fields
- Cookies
- JSON body parameters
### Reconnaissance - Determine the type
- Reflected
- Blind
    - Conditional responses / error based
    - Synchronous execution - time based OR Asynchronous execution: out-of-band based
# HTTP request smuggling
### Objective
- Bypass front-end security controls to access resources
- Retrieve other HTTP requests to disclose information: front-end rewriting, other users' cookies, queue poisoning, etc
- Deliver XSS payloads (reflected xss, self-xss, redirect to load a resource from another host, etc)
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Determine HTTP method being used, check for issues (Use HTTP Request Smuggler)
### Reconnaissance - Determine the type
- HTTP/1.1 OR HTTP/2: Check for HTTP issues (Use HTTP Request Smuggler)
# Web Cache Poisoning
### Objective
- Poison cache to deliver XSS payloads (observe weird behavior if other headers are added)
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Unkeyed request headers
- Unkeyed cookies
- Unkeyed query string
### Reconnaissance - Determine the type
- Single parameter
- Multiple parameters
- Parameter cloaking (mix with parameter pollution)
- Fat GET request (mix with parameter pollution)
- URL normalization
# Cross-site Scripting - XSS
### Objective
- Steal other user's cookies
- XSS to CSRF
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Any input field that is reflected or stored somewhere
- Url parameters
- Form fields
- Source code: Check server response, Elements tab, Network tab for requests, loaded documents and JS files
### Reconnaissance - Determine the type
- Reflected
- Stored
- DOM
# CSRF
### Objective
- Perform account sensitive functionalities (potentially to takeover the user's account)
- Perform high privilege actions through another user (e.g.: Admin)
- Perform actions that extract data
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Pages where account sensitive operations are performed
- Pages where the user might disclose sensitive information
### Reconnaissance - Determine the type
- CSRF token bypass
- SameSite bypass
- Chained with XSS
- Cross-site WebSocket hijacking (CSWSH)
- Referer header bypass
# Clickjacking
### Objective
- Make the user perform account sensitive operations
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Pages where account sensitive operations are performed
### Reconnaissance - Determine the type
- Single Step
- Multi Step
# DOM-based vulnerabilities
### Objective
- Trigger XSS - Steal user's cookies
- Trigger Open Redirect
### Most Probable Exam Stages to Find This Vulnerability
- Stages 1 and 2
### Reconnaissance - Where to look for it
- Look for event listeners in the page source and other files
### Reconnaissance - Determine the type
- Web Message
- Open Redirect
- XSS
- Etc
# CORS
### Objective
- Extract sensitive information
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Pages where sensitive information could be extracted
- Find a request disclosing sensitive information
- Inject the Origin header and start testing different url options
### Reconnaissance - Determine the type
- Subdomain of the current Host
- Arbitrary URL accepted
- Only null origin allowed
- Chained with XSS
# XXE
### Objective
- Extract sensitive information from the server
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- Look for functionality where a SVG could be uploaded
- Look for API requests using XML
- If the API expects another format, see if it accepts XMLS
- If it does not accept XML, try to declare and XML entity and see the server response, it might reveal that the application is parsing XML
### Reconnaissance - Determine the type
- Read local files
- XXE to SSRF
- In-band
- Out-of-band
# Prototype Pollution
### Objective
#### CSPP
- Execute XSS
- Steal other user's cookies
#### SSPP
- Escalate Privileges
- RCE
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
#### CSPP
- Use DOM Invader
- Use DevTools to study the JavaScript files that are loaded
#### SSPP
- Use Burp Suite Extension - Server-Side Prototype Pollution Scanner
- POST and PUT request updating object properties
### Reconnaissance - Determine the type
- Client-side
- Server-side
# SSRF
### Objective
- Escalate privileges
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- Identify requests that contain hostnames, IPs, or URLs
- Requests fetching data from backend server
- Try the Referer Header
- Chain with an open redirect
- Automate with Extension - Collaborator Everywhere
- Walk throuhgh all the pages
- Try to understand the logic of the application
### Reconnaissance - Determine the type
- Regular/ In Band
- Blind / Out-of-Band
# OS Command Injection
### Objective
- Execute code on the server
- Retrieve sensitive data
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- In request parameters
- User provided input
### Reconnaissance - Determine the type
- In-band
- Out-of-band
# Server-Side Template Injection - SSTI
### Objective
- Execute code on the server
- Retrieve sensitive data
### Most Probable Exam Stages to Find This Vulnerability
- Stages 2 or 3
### Reconnaissance - Where to look for it
- Look for user controlled input that is reflected
- Enumerate the template engine being used by testing with multiple payloads
- If the previous step didn't work, try to trigger an error that discloses useful information
### Reconnaissance - Determine the type
- Plaintext context
- Code context
# Path Traversal
### Objective
- Retrieve sensitive data
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- Look for requests fetching resources from the server
### Reconnaissance - Determine the type
- Absolute path
- Relative path
- Bypass validation
- Encoding needed
# Access Control
### Objective
- Escalate privileges by accessing resources/functionalities we shouldn't have access to
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
Start with the easiest step = /robots.txt and build up from there
Check the source code for endpoints
Look for comments in the code
Check the Burp Suite HTTP history tab with the Search functionality
Request's retrieving user information
Request's modifying user information
### Reconnaissance - Determine the type
#### Access type
- Access to functionality
- Access to information
#### Technique
- Force browsing
- Changing request parameter/cookie/header
- Change HTTP Method
- Mass assignment
- IDOR
- Referer header
# Authentication
### Objective
- Gain Access to user accounts
- Enumerate usernames
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Login Form
- Signup form
- Password reset functionality
- Password change functionality
- Account lock
### Reconnaissance - Determine the type
- Login Form
- Signup form
- Password reset functionality
- Password change functionality
- IP Restriction bypass required
- 2FA Bypass
- Account lock
- Password Cracking
- XSS + Cracking
- Header Injection + Password Reset functionality
# WebSockets
### Objective
- Trigger XSS
- Trigger Cross-site WebSocket hijack (CSWSH)
- Extract's user information
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Features using Websockets
- Chat features
### Reconnaissance - Determine the type
- CSWSH
- XSS
# Insecure Deserialization
### Objective
- Escalate privileges
- RCE
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- Look for any data passed to the web application that looks like serialized data
- Look for files disclosing source code
- Generate error messages to disclose information
- Look for developer comments that disclose information
- Cookies
### Reconnaissance - Determine the type
- Modifying object attributes
- Modifying data types
- Using application functionality to exploit insecure deserialization
- Arbitrary object injection
- Using Pre-built chain tools to exploit magic methods 
# Information Disclosure
### Objective
- Gather useful information
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Start with the easiest step = /robots.txt and build up from there
- Fuzz parameters, directories, HTTP method, etc
- Burp Scanner
- Burp engagement tools: Search, Find comments, Discover content
- Engineering informative responses / Error messages
- Developer tools
### Reconnaissance - Determine the type
- Files for web crawlers: /robots.txt and /sitemap.xml
- Debug page
- Backup Files
- Directory listings
- Developer comments
- Error messages
- Internal headers
- Git history
# Business Logic
### Objective
- Subvert the application logic to elicit malicious actions
- Escalate privileges
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Map the application
- Burp engagement tools: Search, Find comments, Discover content
- API endpoints
- Email change
### Reconnaissance - Determine the type
- Lack of user input validation
- Failing to handle unconventional input
    - Integer overflow
    - String truncation
- Trusted users won't always stay trusworthy
    - Escalate privileges after registering
        - Email change
- Users won't always supply mandatory input
    - Remove parameters one at a time and see what happens
- Users won't always follow the intended sequence
    - Skipping steps
    - Drop requests/Preventing steps
- Domain-specific flaws/Business-specific flaws
- Providing an encryption oracle
# Host Header attacks
### Objective
- Account takeover
- Escalate privileges
- Poison Cache to XSS
- SSRF
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Host header, tamper with it
    - Check if it is being validated. Change .net for .com, or add a collaborator payload
    - Perform all subsequent tests and study how the server responds
- Password reset functionality
- Admin panel
### Reconnaissance - Determine the type
- Password reset functionality
- Admin panel
- Web Cache poisoning
- SSRF
    - Access intranet resources
- Connection reuse
# OAuth authentication
### Objective
- Gain Access to another user's account/information
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Login page
- Attach social profile functionality
- Use oauth service providers' commonly known files to gather information
- Look for missing state parameter
- Oauth flow
- Check the value the parameter "response_type" is set to
### Reconnaissance - Determine the type
- Implicit trust
- OpenID unprotected dynamic client registration + SSRF
- Profile linking
- Redirect - Steal victim's authorization code
# File upload
### Objective
- Re-write critical files in the web application
- RCE
- Exfiltrate data
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- File upload functionalities
- Example of characteristics that should be tested:
    - Name
    - Type
    - Contents
    - Size
### Reconnaissance - Determine the type
- No validation or controls
- Content-Type restriction bypass
- File Upload + Path traversal
- Overriding server configuration files to bypass blacklist
- Obfuscated file extension
- RCE via polyglot web shell
# JWT
### Objective
- Escalate privileges
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- HTTP requests with a JWT
- Check for signature verification
- Check for weak signature secret
### Reconnaissance - Determine the type
- Exploiting flawed JWT signature verification 
- Brute-forcing secret keys
- JWT header parameter injections
    - jwk parameter
    - jwu parameter
    - kid header + directory traversal
# GraphQL
### Objective
- Escalate privileges
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Look for api requests in the HTTP history
- Fuzz for common graphql endpoints
- Determine what methods are allowed
- Send the Introspection query
- Bypassing GraphQL introspection defenses might be required
- Use the graphql visualizer or send the response of the introspection to Burp's site map to visualize the results
### Reconnaissance - Determine the type
- Broken Access Control
- IDOR
- Bypassing rate limiting using aliases
- CSRF via GraphQL
# Race conditions
### Objective
- Exceed business logic
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Single-use or rate-limited functionality 
- Password reset functionality
### Reconnaissance - Determine the type
- Limit overrun
- Bypass rate limits
- Multi-step sequences
- Single endpoint race condition
- Time-sensitive attacks
# NoSQL Injection
### Objective
- Retrieve Data
- Subvert application logic: Login function, and more
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- Start with a single quote '
- URL parameters
- Login form
- JSON body parameters
### Reconnaissance - Determine the type
- NoSQL Syntax Injection
- NoSQL operator injection
# API Testing
### Objective
- Escalate privileges
- Disclose data
### Most Probable Exam Stages to Find This Vulnerability
- Stage 1 or 2
### Reconnaissance - Where to look for it
- API endpoints
### Reconnaissance - Determine the type
- Exploiting an unused API endpoint
- Exploiting a mass assignment vulnerability
- Exploiting server-side parameter pollution in a query string
# Web LLM attacks
### Objective
- Retrieve data that the LLM has access to
- Trigger harmful actions via APIs
- Trigger attacks on other users and systems that query the LLM
### Most Probable Exam Stages to Find This Vulnerability
- Stage 2 or 3
### Reconnaissance - Where to look for it
- In LLM powered functionality
### Reconnaissance - Determine the type
- Prompt Injection
- Prompt Injection + Another Vulnerability
- Indirect Prompt Injection
