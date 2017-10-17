# A2 Authentication

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Attackers have access to hundreds of millions of valid username and password combinations for credential stuffing, default administrative account lists, automated brute force and dictionary attack tools, and advanced GPU cracking tools. | Every application that does not support multi-factor authentication, rate limit login calls, or risk based login controls is vulnerable to attack | Attackers only have to crack access to a few accounts, or even just one administrator level account to access the data held by the system. For financial apps, this may allow money laundering; for tax apps, this might allow social security fraud or identity theft; for health apps, this might disclose legally protected highly sensitive information. |

## Am I vulnerable to attack?

Evidence of identity, authentication and session management are critical for separating malicious unauthenticated attackers with authorized users. 

Common authentication vulnerabilities include:

* permits [credential stuffing](https://www.owasp.org/index.php/Credential_stuffing), which is where the attacker has a list of valid usernames and passwords
* permits brute force or other automated attacks
* permits default, weak or well-known passwords, such as "Password1" or "admin/admin"
* weak or ineffectual credential recovery and forgot password processes, such as "knowledge-based answers", which cannot be made safe
* plain text, encrypted, or weakly hashed passwords permit the rapid recovery of passwords using GPU crackers or brute force tools
* Missing or ineffective multi-factor authentication.

## How do I prevent

* Do not ship or deploy with any default credentials, particularly for admin users
* [Store passwords using a modern one way hash function](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), such as Argon2 or PBKDF2, with sufficient work factor to prevent realistic GPU cracking attacks
* Implement weak password checks, such as testing new or changed passwords against a list of the [top 10000 worst passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
* Remove outdated complexity rules and password rotation controls, replacing with NIST 800-63 controls (minimum 8 and at least 64 character length passwords. The use of password managers should not be blocked to allow advanced users to use long, random passwords 
* Ensure registration, credential recovery, and API pathways are hardened against account enumeration attacks by using the same messages for all outcomes. 
* Where possible, implement multi-factor authentication to prevent credential stuffing, brute force, automated, and stolen credential attacks, or as per NIST 800-63 require longer passwords (at least 12-16 characters minimum) if MFA is not an option
* Permit users to logout, and enforce logout on the server
* Log authentication failures, such that alerting administrators when credential stuffing, brute force or other attacks

Large and high performing organizations should consider using a federated identity product or service that includes evidence of identity, common identity attack protections, multi-factor authentication, monitoring and alerting of identity misuse. Additionally, they may wish to implement rate limiting to limit the impact of automated attacks against APIs, such, credential oracles, credential stuffing, brute force, and default password attacks. Where the use of MFA is universal, the use of weak credential recovery such as "Questions and Answers" should be retired and data expunged from the system. 

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
* [OWASP Credential Stuffing Cheat Sheet](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Forgot Password Cheat Sheet](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Password Storage Cheat Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Session Management Cheat Sheet](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)

### External

* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [Daniel Messier - SecLists - Passwords (find the Top 10000 worst passwords here)] (https://github.com/danielmiessler/SecLists/tree/master/Passwords)

Whilst no longer the main risk in this chapter, session management is foundational that must be right:
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
