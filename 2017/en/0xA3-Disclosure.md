# A3 Sensitive Data Exposure

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Manual attack is generally required. This is a core skill of penetration testers and motivated attackers. | Over the last few years, this has been the most common impactful attack, with credit reporting agency breaches of over 150 million records of the most sensitive data possible, the Yahoo breach of over a billion accounts. Manual steps are required to characterize sensitive or legally controlled personally identifiable information, but automated tools can be used to find likely issues. | Failure frequently compromises all data that should have been protected. Typically, this information includes sensitive personal information (PII) data such as health records, credentials, personal data, credit cards, which often requires protection as defined by laws or regulations such as the EU GDPR or local privacy laws. |

## Am I vulnerable to attack?

The first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, and personal information require extra protection, particularly if that data falls under the EU's General Data Protection Regulation (GDPR), local privacy laws or regulations, financial data protection regulations and laws, such as PCI Data Security Standard (PCI DSS) or the US Gramm-Leach-Bliley Act, or health records laws, such as the US Health Insurance and Portability Act (HIPAA).

For all such data:

* Is any data transmitted in clear text, internally or externally? Internet traffic is especially dangerous, but from load balancers to web servers or from web servers to back end systems can also be problematic
* Is sensitive data stored in clear text, including backups of this data?
* Are any old or weak cryptographic algorithms used either by default or in older code? 
* Are default crypto keys in use, weak crypto keys generated or re-used, or is proper key management or rotation missing?
* Is encryption not enforced, e.g. are any user agent (browser) security directives or headers missing?

Passive automated findings from tools, such as version disclosure or stack traces are not sensitive and thus not covered by this risk. For a more complete set of problems to avoid and potential solutions, please see the references below.

## How do I prevent

Do the following, at a minimum and consult the references:

* Classify data processed, stored or transmitted by a system, for example sensitive personal information, health records, PCI DSS in scope data. Apply controls as per the classification.
* Do not collect or store unnecessary sensitive data, or have a data retention plan in place to age out old or unused records. Data you don't retain can't be stolen.
* Encrypt all data in transit, by using TLS. Enforce this using directives like HTTP Strict Transport Security (HSTS). TLS is becoming mandatory with modern browsers, such as [enforcing the use of TLS for many sensitive forms by late 2017](https://blog.chromium.org/2017/04/next-steps-toward-more-connection.html). They are already as alerting users when they attempt to submit login forms over unencrypted links. [Let's Encrypt](https://letsencrypt.org/) provides free renewable 90-day TLS certificates, and there are many commercial certificate authorities to provide standard and extended validation certificates.
* Encrypt all sensitive data at rest 
* Ensure up-to-date and strong standard algorithms or ciphers, parameters, protocols and keys are used, and proper key management is in place. Consider using FIPS 140 validated cryptographic modules.
* Ensure passwords are stored with a strong adaptive algorithm appropriate for password protection, such as Argon2i, scrypt, bcrypt and PBKDF2. Also be sure to set the work factor (delay factor) as high as you can tolerate.
* Disable browser caching of pages and API responses that contain sensitive data. Refer to [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project) for more details.
* Verify independently the efficacy of your settings using services such as [Security Headers](https://securityheaders.io) and [SSL Labs TLS test suite](https://dev.ssllabs.com/ssltest/).

## Example Scenarios

Scenario #1: An application encrypts credit card numbers in a database using automatic database encryption. However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text. Alternatives include not storing credit card numbers or using PCI DSS compliant tokenization and encryption.

Scenario #2: A site doesn't use or enforce TLS for all pages, or if it supports weak encryption. An attacker simply monitors network traffic, strips or intercepts the TLS (like an open wireless network), and steals the user's session cookie. The attacker then replays this cookie and hijacks the user's (authenticated) session, accessing or modifying the user's private data. Instead of the above he could also alter all transported data, e.g. the recipient of a money transfer.

Scenario #3: The password database uses unsalted hashes to store everyone's passwords. A file upload flaw allows an attacker to retrieve the password database. All the unsalted hashes can be exposed with a rainbow table of pre-calculated hashes.

## References

### OWASP

* [OWASP Proactive Controls - Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard - V9 Data Protection](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide - Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)
* [OWASP Cheat Sheet - User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet - Password Storage](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

### External

The primary issue for this finding is protecting sensitive information, and not necessarily if the right algorithms are in place and effective:

* [CWE-359 Exposure of Private Inforamtion (Privacy Violation)](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-220 Exposure of sensitive information through data queries](https://cwe.mitre.org/data/definitions/202.html)

The following CWEs are still very useful in achieving the goal of protecting sensitive data:

* [CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326 Weak Encryption](https://cwe.mitre.org/data/definitions/326.html)

Example of a failure under this finding includes:

* [Detailed analysis of Anthem Insurance data breach of 78.8 million sensitive health records](https://www.bankinfosecurity.com/new-in-depth-analysis-anthem-breach-a-9627)
