# Resources
- Intigriti Hackademy videos on JWT Vulnerabilities
- JWT Playlist - Emanuele Picariello
- Michael Sommer videos
# Extension & Tools
- JWT Editor - Burp
- JSON Web Tokens - Burp
- jwt.io
- Hashcat
- [JWT Well known secrets wordlist](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)
# JSON Web Token (JWT) Basics
## Format
- header
- payload
- signature
## JWT vs JWS vs JWE
- Both JWS (JSON Web Signature) and JWE (JSON Web Encryption) extend JWT. 
- JWE are encrypted instead of encoded
- JWS are what most people are referring to when they say JWT
# How vulnerabilities arise
- Flawed handling within the application due to faulty implementation
- Improper signature verification
- Secret key leakaged
- Weak secret key vulnerable to guessing/brute-force attacks
# Exploiting flawed JWT signature verification 
- The application might accept arbitrary signatures. Simply modify the payload section and send the request
- Change the content of the payload and see if the signature is properly validated
- Set the `"alg"` to `none`. Check if the token can be sent without signature
- If this fails, try to obfuscate the characters (mixed capitalization or encoding)
# Brute-forcing secret keys
```bash
hashcat -a 0 -m 16500 <jwt> <wordlist>
# If running the command more than once add the --show flag
hashcat -a 0 -m 16500 <jwt> <wordlist> --show
# Output
<jwt>:<identified-secret>
```
- Use the JWT Editor to sign the JWT token after the secret has been found
# JWT header parameter injections
## Key Acronyms
- jwk (JSON Web Key)
- jku (JSON Web Key Set URL)
- kid (Key ID)
## Injecting self-signed JWTS via the jwk parameter
- Some servers are misconfigured to use any key that's embedded in the jwk parameter
- Use the JSON Web Token Extension to include the jwk parameter with a self-generated key
1. Go to the JWT Editor Keys
2. Generate a new RSA key
3. Go the request in repeater and select the JSON Web Token tab
4. Modify the token's payload
5. Click **Attack** and select **Embedded JWK**. Select the  newly created RSA key
6. Send the request and observe the response
## Injecting self-signed JWTs via the jku parameter
- Some servers fail to check if the provided jku belongs to trusted domains
1. Go to the JWT Editor Keys
2. Generate a new RSA key
3. Right click the key and select **Copy Public Key as JWK**
4. Paste the public key in the exploit server and set the file extension to .json
```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "sample",
            "n": "sample"
        }
    ]
}
```
5. Modify the JWT header's `kid` parameter to match the one belonging to the newly created key, and add a `jku` parameter with the value pointin to the file hosted in the exploit server
6. Change the `sub` value
7. Sign the token and ensure the `Don't modify header` option
## Injecting self-signed JWTs via the kid parameter
- The JWS specification doesn't define a specific structure for the kid value
- The kid parameter is used to point the id of the correct key to use to verify the signature
- If this is abused with a path traversal vulnerability that points to the /dev/null directory, we could sign the token with an empty string
- The JWT Editor extension does not allow the usage of an empty string. This can be bypassed by inserting the null byte value in base64 `AA==` in the `k` property
