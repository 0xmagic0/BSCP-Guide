# Resources
- [Business Logic Playlist - Michael Sommer](https://www.youtube.com/playlist?list=PL0W_QjMcqdSDhzfxAgG1-4WeuOGV6Euoy)
# Excessive trust in client side controls, lack of user input validation
- Use Burp Suite to modify the data before is sent to the server
- Lack of data integrity checks and server validation can lead to security issues
- Send unexpected parameter values, mix them, and play with the logic with which these interact with each other
# Failing to handle unconventional input
- Submit unconventional values and try to spot different behavior
    - Replace positive numbers with negative numbers
- Are there any limits imposed on the data?
    - Add multiple instances of the same product, is there integer overflow?
    - Are stings being truncated?
- What happens when you reach those limits? Watch for the errors and how they are handled
- Is any transformation or normalization being performed on your input?
# Making flawed assumptions about user behavior
## Trusted users won't always stay trusworthy
- After passing security controls at the beginning, the user might begin to engage in dangerous behaviour
- The user could register an user with an unexpected email domain
- The user could change his email address to an unexpected demail domain
## Users won't always supply mandatory input
- The presence or absence of a parameter might change what code gets executed
- Try removing parameters one by one and see what happens
- Determine what parameters are mandatory and validated
- For multi step processes, tamper with the parameter in one of the steps and see if it has an effect on other steps
## Users won't always follow the intended sequence
- Study the sequence of steps for a procedure
- Can steps be skipped?
- Break the linear pattern and see how the website reacts when you change the intended workflow
- Can requests be dropped and avoided?
# Domain-specific flaws/Business-specific flaws
- Understand the application and business in depth to spot potential flaws
- These scenarios are specific to the type of application
    - Could an user use multiple coupon codes in a e-commerce store?
    - Could an user use coupon codes more than once in a e-commerce store?
- Burp Macros might come in handy while automating multiple requests to exploit weird behaviour in the applications
# Providing an encryption oracle
- User controlled input is encrypted and made available to the user
- Look for way to trigger functionality that would disclose this encryption oracle: fuzz parameters, cause errors, cookies, etc
- The user could use this encryption orable to craft a payload and send it to data sinks that expect encrypted data using the same format
