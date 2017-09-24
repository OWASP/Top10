# A6 Sensitive Information Disclosure

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

## Am I vulnerable to attack?
The first thing you have to determine is which data is sensitive enough to require extra protection. For example, passwords, credit card numbers, health records, and personal information should be protected. For all such data:
* Is any of this data stored in clear text long term, including backups of this data?
* Is any data of a site transmitted in clear text, internally or externally? Internet traffic is especially dangerous.
* Are any old / weak cryptographic algorithms used? E.g. that may be provided by standard configs (see A5)
* Are weak crypto keys generated, or is proper key management or rotation missing?
* Is encryption not enforced, e.g. are any (browser) security directives or headers missing?

And more … For a more complete set of problems to avoid, see ASVS areas Crypto (V7), Data Prot (V9), and SSL/TLS (V10).

## How do I prevent
The full perils of unsafe cryptography, SSL/TLS usage, and data protection are well beyond the scope of the Top 10. That said, for all sensitive data, do the following, at a minimum:

* Considering the threats you plan to protect this data from (e.g., insider attack, external user), make sure you encrypt all sensitive data at rest and in transit in a manner that defends against these threats.
* Don’t store sensitive data unnecessarily. Discard it as soon as possible. Data you don’t retain can’t be stolen.
* Ensure strong standard algorithms and strong keys are used, and proper key management is in place. Consider using FIPS 140 validated cryptographic modules.
* Ensure passwords are stored with a strong adaptive algorithm appropriate for password protection, such as Argon2i, scrypt, bcrypt and PBKDF2. Also be sure to set the work factor (delay factor) as high as you can tolerate.
* Disable autocomplete on forms requesting sensitive data and disable caching for pages that contain sensitive data.
* Verify independently the efficiency of your settings.


## Example Scenarios
Scenario #1: An application encrypts credit card numbers in a database using automatic database encryption. However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text. Alternatives include not storing credit card numbers, using tokenization, or using public key encryption.

Scenario #2: A site simply doesn’t use or enforce TLS for all authenticated pages. An attacker simply monitors network traffic or strips the TLS (like an open wireless network), and steals the user’s session cookie. The attacker then replays this cookie and hijacks the user’s session, accessing the user’s private data.

Scenario #3: The password database uses unsalted hashes to store everyone’s passwords. A file upload flaw allows an attacker to retrieve the password database. All of the unsalted hashes can be exposed with a rainbow table of precalculated hashes.

## References

### OWASP

* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()

### External

* CWE Entry 310 on Cryptographic Issues
* CWE Entry 312 on Cleartext Storage of Sensitive Information
* CWE Entry 319 on Cleartext Transmission of Sensitive Information
* CWE Entry 326 on Weak Encryption
