# A02:2021 – Défaillances cryptographiques    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       29       |       46,44 %        |         4,49 %         |             7,29              |         6,81         |    79,33 %     |      34,85 %       |          233 788           |        3 075         |

## Aperçu

En deuxième position, en progression d'une place. Auparavant connu sous le nom d'*Exposition de données sensibles*, qui est plus un symptôme générique qu'une cause racine. L'accent est mis sur les défaillances liées à la cryptographie (ou son absence). Cela entraîne souvent l'exposition de données sensibles. Les *Common Weakness Enumerations* (CWE) notables incluses sont *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky Crypto Algorithm*, et *CWE-331 Insufficient Entropy*.

## Description 

Déterminer d’abord quelles données doivent bénéficier d’une protection chiffrée (mots de passe, données patients, numéros de cartes, données personnelles, etc.), lors de leur transfert ou leur stockage. Pour chacune de ces données :

- Les données circulent-elles en clair ? Ceci concerne les protocoles tels que HTTP, SMTP et FTP. Le trafic externe sur internet est particulièrement dangereux. Vérifiez tout le réseau interne, par exemple entre les équilibreurs de charge, les serveurs Web ou les systèmes backend.
- Des algorithmes faibles ou désuets sont-ils utilisés, soit par défaut, soit dans le code source existant ?
- Est-ce que des clefs de chiffrement par défaut sont utilisées ? Des clefs de chiffrement faibles sont-elles générées ou réutilisées ? Leur gestion et rotation sont-elles prises en charge ? Est-ce que des clés sont présentes dans l'outil de versionnement de code source ?
- Les réponses transmises au navigateur incluent-elles les directives/en-têtes de sécurité adéquats ?
- Est-ce que le certificat serveur reçu et la chaîne de confiance sont correctement validés ?
- Est-ce que les vecteurs d'initialisation sont ignorés, réutilisés ou générés avec une sécurité insuffisante pour le mode d'opération cryptographique ?
- Est-ce que les mots de passe sont utilisés sans fonction de dérivation de clé ?
- Est-ce que la fonction de génération aléatoire utilisée a été conçue pour répondre aux exigences cryptographiques ? Même si la bonne fonction est utilisée, est-ce que la graine aléatoire doit être fournie par le développeur, et sinon, le développeur a-t-il réécrit la fonction robuste embarquée de génération de graine par une graine aléatoire qui manque d'entropie ou d'imprévisibilité ?
- Est-ce que des fonctions de hachage dépréciées telles que MD5 ou SHA1 sont utilisées ou est-ce que des fonctions de hachage non cryptographiques sont utilisées là où des fonctions de hachage cryptographiques sont nécessaires ?
- Est-ce que des méthodes cryptographiques de remplissage dépréciées, comme PKCS 1 v1.5 sont utilisées ?
- Est-ce que des messages d'erreurs cryptographiques ou des informations par canal auxiliaire sont exploitables, par exemple sous la forme d'attaque par oracle de remplissage ?

Se référer à l'*ASVS* *Crypto* (V7), *Data Protection* (V9), et *SSL/TLS* (V10).

## How to Prevent

Do the following, at a minimum, and consult the references:

-   Classify data processed, stored, or transmitted by an application.
    Identify which data is sensitive according to privacy laws,
    regulatory requirements, or business needs.

-   Don't store sensitive data unnecessarily. Discard it as soon as
    possible or use PCI DSS compliant tokenization or even truncation.
    Data that is not retained cannot be stolen.

-   Make sure to encrypt all sensitive data at rest.

-   Ensure up-to-date and strong standard algorithms, protocols, and
    keys are in place; use proper key management.

-   Encrypt all data in transit with secure protocols such as TLS with
    forward secrecy (FS) ciphers, cipher prioritization by the
    server, and secure parameters. Enforce encryption using directives
    like HTTP Strict Transport Security (HSTS).

-   Disable caching for response that contain sensitive data.

-   Apply required security controls as per the data classification.

-   Do not use legacy protocols such as FTP and SMTP for transporting
    sensitive data.

-   Store passwords using strong adaptive and salted hashing functions
    with a work factor (delay factor), such as Argon2, scrypt, bcrypt or
    PBKDF2.

-   Initialization vectors must be chosen appropriate for the mode of
    operation.  For many modes, this means using a CSPRNG (cryptographically
    secure pseudo random number generator).  For modes that require a
    nonce, then the initialization vector (IV) does not need a CSPRNG.  In all cases, the IV
    should never be used twice for a fixed key.

-   Always use authenticated encryption instead of just encryption.

-   Keys should be generated cryptographically randomly and stored in
    memory as byte arrays. If a password is used, then it must be converted
    to a key via an appropriate password base key derivation function.

-   Ensure that cryptographic randomness is used where appropriate, and
    that it has not been seeded in a predictable way or with low entropy.
    Most modern APIs do not require the developer to seed the CSPRNG to
    get security.

-   Avoid deprecated cryptographic functions and padding schemes, such as
    MD5, SHA1, PKCS number 1 v1.5 .

-   Verify independently the effectiveness of configuration and
    settings.

## Example Attack Scenarios

**Scenario #1**: An application encrypts credit card numbers in a
database using automatic database encryption. However, this data is
automatically decrypted when retrieved, allowing a SQL injection flaw to
retrieve credit card numbers in clear text.

**Scenario #2**: A site doesn't use or enforce TLS for all pages or
supports weak encryption. An attacker monitors network traffic (e.g., at
an insecure wireless network), downgrades connections from HTTPS to
HTTP, intercepts requests, and steals the user's session cookie. The
attacker then replays this cookie and hijacks the user's (authenticated)
session, accessing or modifying the user's private data. Instead of the
above they could alter all transported data, e.g., the recipient of a
money transfer.

**Scenario #3**: The password database uses unsalted or simple hashes to
store everyone's passwords. A file upload flaw allows an attacker to
retrieve the password database. All the unsalted hashes can be exposed
with a rainbow table of pre-calculated hashes. Hashes generated by
simple or fast hash functions may be cracked by GPUs, even if they were
salted.

## References

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)


## List of Mapped CWEs

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
