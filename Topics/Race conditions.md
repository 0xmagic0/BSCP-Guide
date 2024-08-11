# Resources
- [Smashing the state machine: the true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine)
- [Intigriti Hackademy videos on race conditions](https://www.youtube.com/watch?v=ci5_VmDNAo0&list=PLmqenIp2RQciV955S2rqGAn2UOrR2NX-v&index=55)
- [Popo Hack videos on race conditions](https://www.youtube.com/playlist?list=PLzgroH3_jK2hl7uPH4gXq3bbgNLDYXUlR)
- [Intigriti - Hacker tools turbo intruder](https://blog.intigriti.com/hacking-tools/hacker-tools-turbo-intruder)
# Methodology for identifying and exploiting race conditions
- Predict
    - Is this endpoint security critical?
    - Is there any collision potential?
- Probe for clues
    - Benchmark normal behaviour: Use send group in sequence (separate connections)
    - Test for differences: Use send group in parallel or Turbo Intruder
    - Look for some sort of deviation
- Prove
    - The path for a successful exploitation and maximum impact aren't always obvious
    - Watch the portswigger video Smashing the state machine for a more detailed methodology
# Limit overrun race conditions
- Exceed a limit imposed by the business logic
- This is a subtype of the so-called "time-of-check to time-of-use" flaws
## Detecting and exploiting limit overrun race conditions with Burp Repeater
- Identify a single-use or rate-limited endpoint that has some kind of security impact or other useful purpose.
- Issue multiple requests to this endpoint in quick succession to see if you can overrun this limit.
- Use Repeater Group tabs and send the requests in parallel
## Detecting and exploiting limit overrun race conditions with Turbo Intruder - Bypass rate limits
- Requires Python proficiency
- Turbo Intruder is suited for attacks that require multiple retries, staggered request timing, or an extremely large number of requests
- See the `race-single-packet-attack.py` template and the portswigger documentation to see how to configure it accordingly
- [Documentation](https://portswigger.net/web-security/race-conditions#detecting-and-exploiting-limit-overrun-race-conditions-with-turbo-intruder)
- Modify the script accordingly
# Hidden multi-step sequences
- A request might initiate a multi-step sequence behind the scenes
- Finding these request that cause the application sub-states is an important skill to identify and exploit race conditions
## Multi-endpoint race conditions
- Check if there is a race condition vulnerability in multi-endpoint processes
- Sometimes the connection might need to be warmed-up with a first inconsequential GET request
- Send the requests in parallel
# Single-endpoint race conditions
- Critical functionality that is keyed or tracked to specific user sessions might be vulnerable to race conditions
    - Email change
- Other functionalities might also be vulnerable to race conditions
- See how the endpoint responds to a large amount of requests sent at the same time, does it behave as intended?
    - Follow the predict, probe, and prove methodology
# Session-based locking mechanisms
- Some frameworks attempt to prevent accidental data corruption by using some form of request locking.
# Time-sensitive attacks
- Sometime race conditions are not present but the same techniques to send simultaneous requests at the same time can be used to exploit other vulnerabilities
    - Password reset functionality
