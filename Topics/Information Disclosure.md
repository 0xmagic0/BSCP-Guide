# Resources
-[Information Disclosure - Popo Hack](https://www.youtube.com/playlist?list=PLzgroH3_jK2i2tux39hfaG-oDk_BSaOaI)
- Michael Sommer videos
# What is it?
When an application unintentionally reveals sensitive information to its users
- Data about other users
- Commercial or business data
- Technical details about the website and its infrastructure
# How to find it
- Start with the easiest step = /robots.txt and build up from there
- Fuzz parameters, directories, HTTP method, etc
- Burp Scanner
- Burp engagement tools: Search, Find comments, Discover content
- Engineering informative responses / Error messages
- Developer tools
# Common sources of information disclosure
- Files for web crawlers: /robots.txt and /sitemap.xml
- Directory listings
- Developer comments
- Error messages
- Internal headers
- Debug page
- Fuzzing: Fuzz parameters, directories, etc. Use the application in an uninteded way to generate interesting responses
- User account pages: Check for requests or parameters that might be vulnerable to IDOR and reveal sensitive information
- Source code disclosure via backup files:
    - Fuzz and enumerate to find them. To read some backup file you could add the tilde `~`
- Information disclosure due to insecure configuration: Debug mode is enabled, TRACE method is allowed and returns interesting data, etc. There are many examples
- Version control history: If a .git folder is found, download it and inspect it for secrets
    - Get status
    ```bash
    git status
    ```
    - Get git log
    ```bash
    git log
    ```
    - Create a branch with the code of a hash-commit
    ```bash
    git checkout hash-commit
    git branch new-branch-name
    git checkout new-branch-name
    ```
    - Search for commit containing a specified string
    ```bash
    git log -S sting-here
    ```
    - Show the change made to a file in a specific commit
    ```bash
    git show --patch commit-hash filename
    ```
