# A3:2017 Sensitive Data Exposure

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 3 \| Detectability 2 | Technical 3 \| Business |
| Even anonymous attackers typically don't break crypto directly. They break something else, such as steal keys, do man-in-the-middle attacks, or steal clear text data off the server, while in transit, or from the user's client, e.g. browser. Manual attack is generally required. | Over the last few years, this has been the most common impactful attack. The most common flaw is simply not encrypting sensitive data. When crypto is employed, weak key generation and management, and weak algorithm usage is common, particularly weak password hashing techniques. For data in transit server side weaknesses are mainly easy to detect, but hard for data in rest. Both with very varying exploitability. | Failure frequently compromises all data that should have been protected. Typically, this information includes sensitive personal information (PII) data such as health records, credentials, personal data, credit cards, which often requires protection as defined by laws or regulations such as the EU GDPR or local privacy laws. |

## Am I Vulnerable to Data Exposure?

The first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, and personal information require extra protection, particularly if that data falls under the EU's General Data Protection Regulation (GDPR), local privacy laws or regulations, financial data protection regulations and laws, such as PCI Data Security Standard (PCI DSS), or health records laws, such as the Health Insurance Portability Act (HIPAA). For all such data:

* Is any data of a site transmitted in clear text, internally or externally? Internet traffic is especially dangerous, but from load balancers to web servers or from web servers to back end systems can be problematic.
* Is sensitive data stored in clear text, including backups?
Are any old or weak cryptographic algorithms used either by default or in older code? (see **A6:2017 Security Misconfiguration**)
* Are default crypto keys in use, weak crypto keys generated or re-used, or is proper key management or rotation missing?
* Is encryption not enforced, e.g. are any user agent (browser) security directives or headers missing?

See ASVS areas [Crypto (V7), Data Protection (V9) and SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS)

## How Do I Prevent This?

Do the following, at a minimum and consult the references:

* Classify data processed, stored or transmitted by a system. Apply controls as per the classification.
Review the privacy laws or regulations applicable to sensitive data, and protect as per regulatory requirements
* Don't store sensitive data unnecessarily. Discard it as soon as possible or use PCI DSS compliant tokenization or even truncation. Data you don't retain can't be stolen.
* Make sure you encrypt all sensitive data at rest 
* Encrypt all data in transit, such as using TLS. Enforce this using directives like HTTP Strict Transport Security (HSTS).
* Ensure up-to-date and strong standard algorithms or ciphers, parameters, protocols and keys are used, and proper key management is in place. Consider using [crypto modules](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search).
* Ensure passwords are stored with a strong adaptive algorithm appropriate for password protection, such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) and [PBKDF2](https://wikipedia.org/wiki/PBKDF2). Configure the work factor (delay factor) as high as you can tolerate.
* Disable caching for response that contain sensitive data.
* Verify independently the effectiveness of your settings.

## Example Attack Scenarios

**Scenario #1**:  An application encrypts credit card numbers in a database using automatic database encryption. However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text. 

**Scenario #2**: A site doesn't use or enforce TLS for all pages, or if it supports weak encryption. An attacker simply monitors network traffic, strips or intercepts the TLS (like an open wireless network), and steals the user's session cookie. The attacker then replays this cookie and hijacks the user's (authenticated) session, accessing or modifying the user's private data. Instead of the above he could alter all transported data, e.g. the recipient of a money transfer.

**Scenario #3**: The password database uses unsalted hashes to store everyone's passwords. A file upload flaw allows an attacker to retrieve the password database. All the unsalted hashes can be exposed with a rainbow table of pre-calculated hashes.

## References


* [OWASP Proactive Controls - Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard - V9, V10, V11](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Cheat Sheet - Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet - User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet - Password Storage](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Cheat Sheet - Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
* [OWASP Testing Guide - Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### External

* [CWE-359 Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-220 Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326 Weak Encryption](https://cwe.mitre.org/data/definitions/326.html)
