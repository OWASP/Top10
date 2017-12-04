# A3:2017 Exposition de données sensibles

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilité | Impacts Techniques |
| -- | -- | -- |
| Niveau d'accès : Exploitation 2 | Fréquence 3 : Détection 2 | Impact 3 : Métier |
| La cryptanalyse (cassage de l’algorithme ou de la clé) reste rare. On préfère obtenir les clefs, effectuer des attaques du type man-in-the-middle, accéder aux données en clair sur le serveur, en transit, ou depuis le client de l'utilisateur, par exemple le navigateur. Une attaque manuelle est requise dans la majorité des cas. Des bases de données de mots de passe précédemment récupérées peuvent étre brute forcées par des processeurs graphiques (GPU). | Au cours des dernières années, cela a été l'attaque impactante la plus courante. La principale erreur est de ne pas chiffrer les données sensibles. Les autres erreurs fréquentes sont: génération de clés faibles, choix et configuration incorrects des algorithmes et protection insuffisante des mots de passe. En ce qui concerne les données en transit, les faiblesses côté serveur sont pour la plupart faciles à détecter. C'est plus difficile pour les données déjà stockées. | L’exploitation peut résulter en la compromission ou la perte de données personnelles, médicales, financières, d’éléments de cartes de crédit ou d’authentification. Ces données nécessitent souvent une protection telle que définie par le Règlement Général sur la Protection des Données ou les lois locales sur la vie privée. |

## Suis-je vulnérable ?

Déterminer d’abord quelles données doivent bénéficier d’une protection cryptographique (mots de passe, données patient, numéros de cartes, données personnelles, etc.), lors de leur transfert et/ou leur stockage. Pour chacune de ces données :

* Is any data transmitted in clear text? This concerns protocols such as HTTP, SMTP, and FTP. External internet traffic is especially dangerous. Verify all internal traffic e.g. between load balancers, web servers, or back-end systems.
* Are any old or weak cryptographic algorithms used either by default or in older code? 
* Are default crypto keys in use, weak crypto keys generated or re-used, or is proper key management or rotation missing?
* Is encryption not enforced, e.g. are any user agent (browser) security directives or headers missing?
* Does the user agent (e.g. app, mail client) not verify if the received server certificate is valid?

See ASVS [Crypto (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [Data Protection (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection) and [SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications).

## How To Prevent

Do the following, at a minimum, and consult the references:

* Classify data processed, stored or transmitted by an application. Identify which data is sensitive according to privacy laws, regulatory requirements, or business needs.
* Apply controls as per the classification.
* Don't store sensitive data unnecessarily. Discard it as soon as possible or use PCI DSS compliant tokenization or even truncation. Data that is not retained cannot be stolen.
* Make sure to encrypt all sensitive data at rest.
* Ensure up-to-date and strong standard algorithms, protocols, and keys are in place; use proper key management.
* Encrypt all data in transit with secure protocols such as TLS with perfect forward secrecy (PFS) ciphers, cipher prioritization by the server, and secure parameters. Enforce encryption using directives like HTTP Strict Transport Security (HSTS).
* Disable caching for response that contain sensitive data.
* Store passwords using strong adaptive and salted hashing functions with a work factor (delay factor), such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) or [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Verify independently the effectiveness of configuration and settings.

## Example Attack Scenarios

**Scenario #1**: An application encrypts credit card numbers in a database using automatic database encryption. However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text. 

**Scenario #2**: A site doesn't use or enforce TLS for all pages or supports weak encryption. An attacker monitors network traffic  (e.g. at an insecure wireless network), downgrades connections from HTTPS to HTTP, intercepts requests, and steals the user's session cookie. The attacker then replays this cookie and hijacks the user's (authenticated) session, accessing or modifying the user's private data. Instead of the above they could alter all transported data, e.g. the recipient of a money transfer.

**Scenario #3**: The password database uses unsalted or simple hashes to store everyone's passwords. A file upload flaw allows an attacker to retrieve the password database. All the unsalted hashes can be exposed with a rainbow table of pre-calculated hashes. Hashes generated by simple or fast hash functions may be cracked by GPUs, even if they were salted.

## References

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) and [Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### External

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
