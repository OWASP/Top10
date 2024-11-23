---
source:  "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
title:   "A07:2021 – Identification and Authentication Failures"
id:      "A07:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".7" -%}
#A07:2021 – Identification and Authentication Failures     ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Identification and Authentication Failures", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.2") }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 7.40                 | 6.50                | 79.51%       | 45.72%       | 132,195           | 3,897      |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Previously known as *Broken Authentication*, this category slid down
from the second position and now includes Common Weakness 
Enumerations (CWEs) related to identification
failures. Notable CWEs included are *CWE-297: Improper Validation of
Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, and
*CWE-384: Session Fixation*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Confirmation of the user's identity, authentication, and session
management is critical to protect against authentication-related
attacks. There may be authentication weaknesses if the application:

-   Permits automated attacks such as credential stuffing, where the
    attacker has a list of valid usernames and passwords.

-   Permits brute force or other automated attacks.

-   Permits default, weak, or well-known passwords, such as "Password1"
    or "admin/admin".

-   Uses weak or ineffective credential recovery and forgot-password
    processes, such as "knowledge-based answers", which cannot be made
    safe.

-   Uses plain text, encrypted, or weakly hashed passwords data stores (see
    [A02:2021-Cryptographic Failures](A02_2021-Cryptographic_Failures.md)).

-   Has missing or ineffective multi-factor authentication.

-   Exposes session identifier in the URL.

-   Reuse session identifier after successful login.

-   Does not correctly invalidate Session IDs. User sessions or
    authentication tokens (mainly single sign-on (SSO) tokens) aren't
    properly invalidated during logout or a period of inactivity.

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   Where possible, implement multi-factor authentication to prevent
    automated credential stuffing, brute force, and stolen credential
    reuse attacks.

-   Do not ship or deploy with any default credentials, particularly for
    admin users.

-   Implement weak password checks, such as testing new or changed
    passwords against the top 10,000 worst passwords list.

-   Align password length, complexity, and rotation policies with
    National Institute of Standards and Technology (NIST)
    800-63b's guidelines in section 5.1.1 for Memorized Secrets or other
    modern, evidence-based password policies.

-   Ensure registration, credential recovery, and API pathways are
    hardened against account enumeration attacks by using the same
    messages for all outcomes.

-   Limit or increasingly delay failed login attempts, but be careful not to create a denial of service scenario. Log all failures
    and alert administrators when credential stuffing, brute force, or
    other attacks are detected.

-   Use a server-side, secure, built-in session manager that generates a
    new random session ID with high entropy after login. Session identifier
    should not be in the URL, be securely stored, and invalidated after
    logout, idle, and absolute timeouts.

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** Credential stuffing, the use of lists of known
passwords, is a common attack. Suppose an application does not implement
automated threat or credential stuffing protection. In that case, the
application can be used as a password oracle to determine if the
credentials are valid.

**Scenario #2:** Most authentication attacks occur due to the continued
use of passwords as a sole factor. Once considered best practices,
password rotation and complexity requirements encourage users to use
and reuse weak passwords. Organizations are recommended to stop these
practices per NIST 800-63 and use multi-factor authentication.

**Scenario #3:** Application session timeouts aren't set correctly. A
user uses a public computer to access an application. Instead of
selecting "logout", the user simply closes the browser tab and walks
away. An attacker uses the same browser an hour later, and the user is
still authenticated.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.opc.3.6", osib=osib) }} <!-- [OWASP Proactive Controls: Implement Digital Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.2", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V2 authentication](https://owasp.org/www-project-application-security-verification-standard) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.3", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V3 Session Management](https://owasp.org/www-project-application-security-verification-standard) -->
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.3", osib=osib) }}, <!-- [OWASP Testing Guide: Identity ](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README) --> {{ osib_link(link= "osib.owasp.wstg.4-2.4.4", doc="", osib=osib) }} <!-- [Authentication ](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Authentication", osib=osib) }} <!-- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Credential Stuffing Prevention", osib=osib) }} <!-- [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Forgot Password", osib=osib) }} <!-- [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Session Management", osib=osib) }} <!-- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.oat", osib=osib) }} <!--- OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)a --->
-   {{ osib_link(link="osib.nist.csrc.sp.800-63b.5.1.1", doc="osib.nist.csrc.sp.800-63b", osib=osib) }} <!--- [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.255", doc="", osib=osib) }} <!-- [CWE-255: Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.259", doc="", osib=osib) }} <!-- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.287", doc="", osib=osib) }} <!-- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.288", doc="", osib=osib) }} <!-- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.290", doc="", osib=osib) }} <!-- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.294", doc="", osib=osib) }} <!-- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.295", doc="", osib=osib) }} <!-- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.297", doc="", osib=osib) }} <!-- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.300", doc="", osib=osib) }} <!-- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.302", doc="", osib=osib) }} <!-- [CWE-302: Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.304", doc="", osib=osib) }} <!-- [CWE-304: Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.306", doc="", osib=osib) }} <!-- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.307", doc="", osib=osib) }} <!-- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.346", doc="", osib=osib) }} <!-- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.384", doc="", osib=osib) }} <!-- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.521", doc="", osib=osib) }} <!-- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.613", doc="", osib=osib) }} <!-- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.620", doc="", osib=osib) }} <!-- [CWE-620: Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.640", doc="", osib=osib) }} <!-- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.798", doc="", osib=osib) }} <!-- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.940", doc="", osib=osib) }} <!-- [CWE-940: Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1216", doc="", osib=osib) }} <!-- [CWE-1216: Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html) -->
