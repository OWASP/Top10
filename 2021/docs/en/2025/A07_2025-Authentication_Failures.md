<link rel="stylesheet" href="../../assets/css/RC-stylesheet.css" />

# A07:2025 Authentication Failures ![icon](../../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## Background. 

Authentication Failures maintains its position at #7 with a slight name change to more accurately reflect the 36 CWEs in this category. Despite benefits from standardized frameworks, this category has kept its #7 rank from 2021. Notable CWEs included are *CWE-259 Use of Hard-coded Password*, *CWE-297: Improper Validation of Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, *CWE-384: Session Fixation*, and *CWE-798 Use of Hard-coded Credentials*.


## Score table.


<table>
  <tr>
   <td>CWEs Mapped 
   </td>
   <td>Max Incidence Rate
   </td>
   <td>Avg Incidence Rate
   </td>
   <td>Max Coverage
   </td>
   <td>Avg Coverage
   </td>
   <td>Avg Weighted Exploit
   </td>
   <td>Avg Weighted Impact
   </td>
   <td>Total Occurrences
   </td>
   <td>Total CVEs
   </td>
  </tr>
  <tr>
   <td>36
   </td>
   <td>15.80%
   </td>
   <td>2.92%
   </td>
   <td>100.00%
   </td>
   <td>37.14%
   </td>
   <td>7.69
   </td>
   <td>4.44
   </td>
   <td>1,120,673
   </td>
   <td>7,147
   </td>
  </tr>
</table>



## Description. 

When an attacker is able to trick a system into recognizing an invalid or incorrect user as legitimate, this vulnerability is present. There may be authentication weaknesses if the application:

* Permits automated attacks such as credential stuffing, where the attacker has a breached list of valid usernames and passwords. More recently this type of attack has been expanded to include hybrid password attacks credential stuffing (also known as password spray attacks), where the attacker uses variations or increments of spilled credentials to gain access, for instance trying Password1!, Password2!, Password3! and so on.

* Permits brute force or other automated, scripted attacks that are not quickly blocked.

* Permits default, weak, or well-known passwords, such as "Password1" or "admin" username with an "admin" password.

* Allows users to create new accounts with already known-breached credentials.

* Allows use of weak or ineffective credential recovery and forgot-password processes, such as "knowledge-based answers," which cannot be made safe.

* Uses plain text, encrypted, or weakly hashed passwords data stores (see[ A02:2021-Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)).

* Has missing or ineffective multi-factor authentication.

* Allows use of weak or ineffective fallbacks if multi-factor authentication is not available. 

* Exposes session identifier in the URL, a hidden field, or another insecure location that is accessible to the client.

* Reuses the same session identifier after successful login.

* Does not correctly invalidate user sessions or authentication tokens (mainly single sign-on (SSO) tokens) during logout or a period of inactivity.


## How to prevent. 

* Where possible, implement and enforce use of multi-factor authentication to prevent automated credential stuffing, brute force, and stolen credential reuse attacks.

* Where possible, encourage and enable the use of password managers, to help users make better choices.

* Do not ship or deploy with any default credentials, particularly for admin users.

* Implement weak password checks, such as testing new or changed passwords against the top 10,000 worst passwords list.

* During new account creation and password changes validate against lists of known breached credentials (eg: using [haveibeenpwned.com](https://haveibeenpwned.com)).

* Align password length, complexity, and rotation policies with [National Institute of Standards and Technology (NIST) 800-63b's guidelines in section 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) for Memorized Secrets or other modern, evidence-based password policies.

* Do not force human beings to rotate passwords unless you suspect breach. If you suspect breach, force password resets immediately. 

* Ensure registration, credential recovery, and API pathways are hardened against account enumeration attacks by using the same messages for all outcomes (“Invalid username or password.”).

* Limit or increasingly delay failed login attempts but be careful not to create a denial of service scenario. Log all failures and alert administrators when credential stuffing, brute force, or other attacks are detected or suspected.

* Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login. Session identifiers should not be in the URL, be securely stored in a secure cookie, and invalidated after logout, idle, and absolute timeouts. 

* Ideally, use a premade, well-trusted system to handle authentication, identity, and session management. Transfer this risk whenever possible by buying and utilizing a hardened and well tested system.


## Example attack scenarios. 

**Scenario #1:** Credential stuffing, the use of lists of known username and password combinations, is now a very common attack. More recently attackers have been found to ‘increment’ or otherwise adjust passwords, based on common human behavior. For instance, changing ‘Winter2025’ to ‘Winter2026’, or ‘ILoveMyDog6’ to ‘ILoveMyDog7’ or ‘ILoveMyDog5’. This adjusting of password attempts is called a hybrid credential stuffing attack or a password spray attack, and they can be even more effective than the traditional version. If an application does not implement defences against automated threats (brute force, scripts, or bots) or credential stuffing, the application can be used as a password oracle to determine if the credentials are valid and gain unauthorized access.

**Scenario #2:** Most successful authentication attacks occur due to the continued use of passwords as the sole authentication factor. Once considered best practices, password rotation and complexity requirements encourage users to both reuse passwords and use weak passwords. Organizations are recommended to stop these practices per NIST 800-63 and to enforce use of multi-factor authentication on all important systems.

**Scenario #3:** Application session timeouts aren't implemented correctly. A user uses a public computer to access an application and instead of selecting "logout," the user simply closes the browser tab and walks away. Another Example for this is, if a Single Sign on (SSO) session can not be closed by a Single Logout (SLO). That is, a single login logs you into, for example, your mail reader, your document system, and your chat system. But logging out happens only to the current system. If an attacker uses the same browser after the victim thinks they have successfully logged out, but with the user still authenticated to some of the applications, then can access the victim's account. The same issue can happen in offices and enterprises when a sensitive application has not been properly exited and a colleague has (temporary) access to the unlocked computer.

## References.

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## List of Mapped CWEs

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)
