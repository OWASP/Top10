# A2 Authentication and Session Management

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

Evidence of identity, authentication and session management are critical for separating malicious unauthenticated attackers with users who you might have a legal relationship. 

## Am I vulnerable to attack?

Common authentication attacks vulnerabilities include:

* does not have multi-factor authentication, such as TOTP, token, or risk based authentication
* permits credential stuffing, which is where the attacker has a list of valid usernames and passwords. Applications should monitor and block many login attempts
* permits brute force attacks against default and well known passwords
* permits weak or well known passwords, such as "Password1" or "admin/admin"
* has weak credential recovery and forgot password processes, such as "knowledge-based answers", which cannot be made safe
* Password recovery tools allow the rapid recovery of plain text, encrypted, or weakly hashed passwords in case of password hash disclosure

Common session vulnerabilities include:

* Not providing a logout function
* Not revoking server side session tokens (a common oAuth and JWT pattern)

## How do I prevent

* [Store passwords using a modern one way hash function](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), such as Argon2, with sufficient work factor to prevent realistic GPU cracking attacks
* Implement multi-factor authentication where possible to prevent credential stuffing, brute force, and stolen credential attacks. 
* Implement rate limiting to limit the impact of credential stuffing, brute force, and default password attacks
* Implement weak password checks to prevent users using weak passwords
* Do not ship with default credentials, particularly for admin users
* Permit users to logout, and enforce logout on the server

Larger organizations should consider using a federated identity product or service that includes evidence of identity, common identity attack protections, multi-factor authentication, monitoring and alerting of identity misuse.

Please review the [OWASP Proactive Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls) for high level overview of authentication controls, or the [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home), chapters V2 and V3 for a detailed set of requirements as per the risk level of your application

## Example Scenarios

*Scenario #1:* The primary authentication attack in 2017 is [credential stuffing](https://www.owasp.org/index.php/Credential_stuffing), where billions of valid usernames and passwords are known to attackers. If an application does not rate limit authentication attempts, the application can be used as a password oracle to determine if the credentials are valid within the application, which can then be sold or misused easily.

*Scenario #2:* Most authentication attacks occur due to the continued use of passwords. Common issues with passwords include password rotation and complexity requirements, which encourages users to use weak passwords they use everywhere. Organizations are strongly recommended to stop password rotation and complexity requirements as per NIST 800-63, and mandating the use of multi-factor authentication.

*Scenario #3:* One the issues with storage of passwords is the use of plain text, reversibly encrypted passwords, and weakly hashed passwords (such as using MD5/SHA1 with or without a salt). GPU crackers are immensely powerful and cheap. A recent effort by a small group of researchers cracked [320 million passwords in less than three weeks](https://cynosureprime.blogspot.com.au/2017/08/320-million-hashes-exposed.html), including 60 character passwords. The solution to this is the use of adaptive modern hashing algorithms such as Argon2, with salting and sufficient workfactor to prevent the use of rainbow tables, word lists, and realistic recovery of even weak passwords. 

## References

### OWASP 
* [OWASP Proactive Controls - Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard - V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard - V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
* [OWASP Testing Guide: Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Authentication Cheat Sheet](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Forgot Password Cheat Sheet](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Password Storage Cheat Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Session Management Cheat Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

### External
* [CWE Entry 287 on Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE Entry 384 on Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
