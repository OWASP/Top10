---
source:  "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
title:   "A02:2021 – Cryptographic Failures"
id:      "A02:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".2" -%}
#A02:2021 – Cryptographic Failures     ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Cryptographic Failures", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.3") }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Shifting up one position to #2, previously known as *Sensitive Data
Exposure*, which is more of a broad symptom rather than a root cause,
the focus is on failures related to cryptography (or lack thereof).
Which often lead to exposure of sensitive data. Notable Common Weakness Enumerations (CWEs) included
are *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky
Crypto Algorithm*, and *CWE-331 Insufficient Entropy*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

The first thing is to determine the protection needs of data in transit
and at rest. For example, passwords, credit card numbers, health
records, personal information, and business secrets require extra
protection, mainly if that data falls under privacy laws, e.g., EU's
General Data Protection Regulation (GDPR), or regulations, e.g.,
financial data protection such as PCI Data Security Standard (PCI DSS).
For all such data:

-   Is any data transmitted in clear text? This concerns protocols such
    as HTTP, SMTP, FTP also using TLS upgrades like STARTTLS. External 
    internet traffic is hazardous. Verify all internal traffic, e.g., 
    between load balancers, web servers, or back-end systems.

-   Are any old or weak cryptographic algorithms or protocols used either 
    by default or in older code?

-   Are default crypto keys in use, weak crypto keys generated or
    re-used, or is proper key management or rotation missing?
    Are crypto keys checked into source code repositories?

-   Is encryption not enforced, e.g., are any HTTP headers (browser)
    security directives or headers missing?

-   Is the received server certificate and the trust chain properly validated? 

-   Are initialization vectors ignored, reused, or not generated
    sufficiently secure for the cryptographic mode of operation?
    Is an insecure mode of operation such as ECB in use? Is encryption
    used when authenticated encryption is more appropriate?

-   Are passwords being used as cryptographic keys in absence of a
    password base key derivation function?

-   Is randomness used for cryptographic purposes that was not designed
    to meet cryptographic requirements? Even if the correct function is
    chosen, does it need to be seeded by the developer, and if not, has
    the developer over-written the strong seeding functionality built into
    it with a seed that lacks sufficient entropy/unpredictability?

-   Are deprecated hash functions such as MD5 or SHA1 in use, or are
    non-cryptographic hash functions used when cryptographic hash functions
    are needed?

-   Are deprecated cryptographic padding methods such as PKCS number 1 v1.5
    in use?

-   Are cryptographic error messages or side channel information
    exploitable, for example in the form of padding oracle attacks?

See {{ osib_link(link="osib.owasp.asvs.4-0.6", prefix="ASVS ", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.8", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.9", doc="", osib=osib) }}<!--- ASVS Crypto (V7), Data Protection (V9), and SSL/TLS (V10)--->

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

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

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

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

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.opc.3." ~ "8", osib=osib) }} <!-- [OWASP Proactive Controls: Protect Data Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.6", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.8", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.9", doc="", osib=osib) }} <!--- [OWASP Application Security Verification Standard (V7, 9, 10)](https://owasp.org/www-project-application-security-verification-standard) --->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Transport Layer Protection", osib=osib) }} <!-- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "User Privacy Protection", osib=osib) }} <!-- [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Password Storage", osib=osib) }} <!-- [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Cryptographic Storage", osib=osib) }} <!-- [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "HSTS", osib=osib) }} <!-- [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.9", osib=osib) }} <!-- [OWASP Testing Guide: Testing for weak cryptography ](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README) -->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.261", doc="", osib=osib) }} <!-- [CWE-261: Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.296", doc="", osib=osib) }} <!-- [CWE-296: Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.310", doc="", osib=osib) }} <!-- [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.319", doc="", osib=osib) }} <!-- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.321", doc="", osib=osib) }} <!-- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.322", doc="", osib=osib) }} <!-- [CWE-322: Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.323", doc="", osib=osib) }} <!-- [CWE-323: Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.324", doc="", osib=osib) }} <!-- [CWE-324: Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.325", doc="", osib=osib) }} <!-- [CWE-325: Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.326", doc="", osib=osib) }} <!-- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.327", doc="", osib=osib) }} <!-- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.328", doc="", osib=osib) }} <!-- [CWE-328: Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.329", doc="", osib=osib) }} <!-- [CWE-329: Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.330", doc="", osib=osib) }} <!-- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.331", doc="", osib=osib) }} <!-- [CWE-331: Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.335", doc="", osib=osib) }} <!-- [CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.336", doc="", osib=osib) }} <!-- [CWE-336: Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.337", doc="", osib=osib) }} <!-- [CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.338", doc="", osib=osib) }} <!-- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.340", doc="", osib=osib) }} <!-- [CWE-340: Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.347", doc="", osib=osib) }} <!-- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.523", doc="", osib=osib) }} <!-- [CWE-523: Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.720", doc="", osib=osib) }} <!-- [CWE-720: OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.757", doc="", osib=osib) }} <!-- [CWE-757: Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.759", doc="", osib=osib) }} <!-- [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.760", doc="", osib=osib) }} <!-- [CWE-760: Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.780", doc="", osib=osib) }} <!-- [CWE-780: Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.818", doc="", osib=osib) }} <!-- [CWE-818: Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.916", doc="", osib=osib) }} <!-- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) -->
