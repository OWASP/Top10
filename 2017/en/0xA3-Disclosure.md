# A3 Sensitive Data Exposure

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | AVERAGE (2) | Manual attack is generally required. This is a core skill of penetration testers and motivated attackers. |
| Prevalence | WIDESPREAD (3) | Over the last few years, this has been the most common impactful attack, with credit reporting agency breaches of over 150 million records of the most sensitive data possible, the Yahoo breach of over a billion accounts. |
| Detectability | AVERAGE (2) | Manual steps are required to characterize sensitive or legally controlled personally identifiable information, but automated tools can be used to find likely issues. |
| Impact | SEVERE (3) | Failure frequently compromises all data that should have been protected. Typically, this information includes sensitive personal information (PII) data such as health records, credentials, personal data, credit cards, which often requires protection as defined by laws or regulations such as the EU GDPR or local privacy laws. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 7.0 | HIGH |

## Am I vulnerable to attack?

The first thing you have to determine are the protection needs of all application data in transit and in rest. For example, passwords, credit card numbers, health records, and personal information require extra protection. For all such data:

* Is any of this data stored in clear text long term, including backups of this data?
* Is any data of a site transmitted in clear text, internally or externally? Internet traffic is especially dangerous.
* Are any old / weak cryptographic algorithms used? E.g. that may be provided by standard configs (see A5)
* Are default crypto keys in use, weak crypto keys generated, or is proper key management or rotation missing?
* Is encryption not enforced, e.g. are any user agent (browser) security directives or headers missing?
* Does the user agent (e.g. app, mail client) not verify if the received certificate is valid. 

And more … For a more complete set of problems to avoid, see ASVS areas Crypto (V7), Data Protection (V9), and SSL/TLS (V10).

## How do I prevent
Do the following, at a minimum and consult the references:
* Make sure you encrypt all sensitive data at rest or transferred via clients, e.g. cookies, tokens.
* Encrypt all data in transit on application layer at least if any sensitive data may be transferred, e.g using TLS. Enforce this using directives like HTTP Strict Transport Security (HSTS).
* Don’t store sensitive data unnecessarily. Discard it as soon as possible. Data you don’t retain can’t be stolen.
* Ensure up-to-date and strong standard algorithms or ciphers, parameters, protocols and keys are used, and proper key management is in place. Consider using FIPS 140 validated cryptographic modules.
* Ensure passwords are stored with a strong adaptive algorithm appropriate for password protection, such as Argon2i, scrypt, bcrypt and PBKDF2. Also be sure to set the work factor (delay factor) as high as you can tolerate.
* Disable autocomplete on forms requesting sensitive data and disable caching for pages that contain sensitive data.
* Verify independently the efficiency of your settings.

## Example Scenarios

Scenario #1: An application encrypts credit card numbers in a database using automatic database encryption. However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text. Alternatives include not storing credit card numbers, using tokenization, or using public key encryption.

Scenario #2: A site simply doesn’t use or enforce TLS for all pages, or if it supports weak encryption. An attacker simply monitors network traffic, strips or intercepts the TLS (like an open wireless network), and steals the user’s session cookie. The attacker then replays this cookie and hijacks the user’s (authenticated) session, accessing or modifying the user’s private data. Instead of the above he could also alter all transported data, e.g. the recipient of a money transfer.

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
