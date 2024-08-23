# Sources
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Jarno Timmermans Youtube Playlist - Web Cache Poisoning](https://www.youtube.com/playlist?list=PLGb2cDlBWRUUvoGqcCF1xe86AaRXGSMT5)
- Michael Sommer videos
# Tools
- Burp Suite Extension - **Param Miner**
    - Automates exploration and detection of cache poisoning vulnerable pages.
    - Add a unique cache key by adding a parameter with a value of $random to the query string.
    - Param Miner adds cache busters to outbound requests from Burp.
# What is it?
- An attacker is able cache a response from the server that delivers a malicious payload to other users
# Key words
- **Cache Keys:**
    - Values in a HTTP request used to to identify the resource being requested.
    - Usually the `PATH` to the resource and the `Host` header are cache keys. 
- **Cache-buster:**
    - Cached responses can mask unkeyed inputs.
    - Cache-busters are used during manual testing to detect and explore vulnerable requests. `Param Miner` can help with this.
# Methodology
- Find a request that functions as a cache oracle. Add cache buster
- Identify unkeyed inputs. This is where the payload will be injected. (Burp Suite extension `Param Miner` can be used to automate it).
- Assess how much damage could be done. The potential impact.
- Inject into cache.
- If that fails, gain a better understanding of how the cache works and find a cacheable target page.
- Retry.
# Possible factors that affect a page being cached
- File extension
- Content-type
- Route
- Status Code
- Response Headers
# Sample unkeyed inputs
- Cookies
- Request headers
```http
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-Proto
Origin
```
# Exploiting Cache Design Flaws
## Unkeyed header
- XSS attack via an unkeyed input that is being reflected
- Malicious resource import due to dynamic URL generation using an unkeyed input value
## Unkeyed cookie
- XSS via unkeyed cookie input
## Exploiting responses that expose too much information
- Some servers might disclose information that helps us understand how the cache works (keyed values for example). Be wary of this and take advantage of any information that's found
# Exploiting Cache Implementation Flaws
- CDNs perform various transformations on keyed components when they are saved in the cache key. This can include:
    - Excluding the query string
    - Filtering out specific query parameters
    - Normalizing input in keyed components
# Cache Probing Methodology
1. Find a cache oracle: A page or endpoint that provides feedback about the cache's behavior
    - An HTTP header that explicitly tells you whether you got a cache hit
    - Observable changes to dynamic content
    - Distinct response times
    - Disclose the specific third-party cache being used: Read the documentation to find more useful information, for example: Akamai supports the header `Pragma: akamai-x-get-cache-key` which displays cache keys in the response
2. Probe key handling: Investigate whether the cache performs any additional processing of your input when generating the cache key
    - Add a cache buster: While exploring for cache busters try to add random values to the:
        - Query String: /?cb=asdfasdsa
        - Origin header: Origin: https://cachebuster-asdfa.example.com
        - Cookie header: Cookie: cb=qweafsa
        - Accept header: Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,text/cachebuster-asdfa
        - Accept-Encoding header: gzip, deflate, br, cachebuster-asdfa
3. Identify an exploitable gadget
    - Unkeyed port
    - Unkeyed query string 
    - Unkeyed query parameters: the `utm_` parameters such as utm_content are good to try. Use Param Miner's "Guess GET Parameter" scan to find useful parameters
    - Cache parameter cloaking
    - Fat GET request: Get requests with a body. This could also be accomplished with a HTTP method override `X-HTTP-Method-Override: POST`
    - Normalized cache keys 
    - Cache key injection 
    - Internal cache poisoning 
