# A2 Authentication and Session Management

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | EASY (3) | Automated tools can exploit all three forms of XSS, and there are freely available exploitation frameworks. |
| Prevalence | WIDESPREAD (3) | XSS is the second most prevalent issue in the OWASP Top 10, and is found in around two thirds of all applications. |
| Detectability | EASY (3) | XSS can be discovered by SAST and DAST tools, as well as anyone with a browser. |
| Impact | MODERATE (2) | The impact of XSS is moderate for reflected and DOM XSS, and severe for stored XSS, with remote code execution on the victim's browser, such as stealing credentials, sessions, or delivering malware to the victim. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 6.0 | MEDIUM |
This issue is easily exploitable by manual means using freely available off the self tools and techniques. This issue is found in 40% of all assessments. The impact of exploitation is compromise of at least one targeted account, and often millions of accounts for undirected attacks.

## Am I vulnerable to attack?

Evidence of identity, authentication and session management are critical for separating malicious unauthenticated attackers with users who you might have a legal relationship. 

Common authentication vulnerabilities include:

* permits credential stuffing, which is where the attacker has a list of valid usernames and passwords
* permits brute force or other automated attacks
* permits default, weak or well-known passwords, such as "Password1" or "admin/admin"
* weak or ineffectual credential recovery and forgot password processes, such as "knowledge-based answers", which cannot be made safe
* plain text, encrypted, or weakly hashed passwords permit the rapid recovery of passwords using GPU crackers or brute force tools
* Missing or ineffective multi-factor authentication


## How do I prevent

* [Store passwords using a modern one way hash function](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), such as Argon2, with sufficient work factor to prevent realistic GPU cracking attacks
* Implement multi-factor authentication where possible to prevent credential stuffing, brute force, automated, and stolen credential attacks
* Implement rate limiting to limit the impact of automated attacks, credential stuffing, brute force, and default password attacks
* Implement weak password checks, such as testing a new password against a list of the top 10000 worst passwords
* Do not ship with default credentials, particularly for admin users
* Permit users to logout, and enforce logout on the server
* Log authentication failures, such that alerting administrators when credential stuffing, brute force or other attacks

Larger organizations should consider using a federated identity product or service that includes evidence of identity, common identity attack protections, multi-factor authentication, monitoring and alerting of identity misuse.

Please review the [OWASP Proactive Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls) for high level overview of authentication controls, or the [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home), chapters V2 and V3 for a detailed set of requirements as per the risk level of your application

## Example Scenarios

*Scenario #1:* The primary authentication attack in 2017 is [credential stuffing](https://www.owasp.org/index.php/Credential_stuffing), where billions of valid usernames and passwords are known to attackers. If an application does not rate limit authentication attempts, the application can be used as a password oracle to determine if the credentials are valid within the application, which can then be sold or misused easily.

*Scenario #2:* Most authentication attacks occur due to the continued use of passwords as a sole factor. Common issues with passwords include password rotation and complexity requirements, which encourages users to use weak passwords they reuse everywhere. Organizations are strongly recommended to stop password rotation and complexity requirements as per NIST 800-63, and mandating the use of multi-factor authentication.

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
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
