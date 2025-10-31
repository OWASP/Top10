# A08:2025 Software or Data Integrity Failures (NGS)

## Background. 

Software or Data Integrity Failures continues at #8 in the list. This category is focused on the failure to maintain trust boundaries and verify the integrity of software, code, and data artifacts at a lower level than Software Supply Chain Failures. This category focuses on making assumptions related to software updates and critical data, without verifying integrity. Notable Common Weakness Enumerations (CWEs) include *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, *CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes*, and *CWE-502: Deserialization of Untrusted Data*.


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
   <td>14
   </td>
   <td>8.98%
   </td>
   <td>2.75%
   </td>
   <td>78.52%
   </td>
   <td>45.49%
   </td>
   <td>7.11
   </td>
   <td>4.79
   </td>
   <td>501,327
   </td>
   <td>3,331
   </td>
  </tr>
</table>



## Description. 

Software and data integrity failures relate to code and infrastructure that does not protect against invalid or untrusted code or data being treated as trusted and valid. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs). An insecure CI/CD pipeline without consuming and providing software integety checks can introduce the potential for unauthorized access, insecure or malicious code, or system compromise. OneAnother example for this is a CI/CD that pulls code or artifacts from untrusted places and/or doesn’t verify them before use (by checking the signature or similar mechanism). Lastly, many applications now include auto-update functionality, where updates are downloaded without sufficient integrity verification and applied to the previously trusted application. Attackers could potentially upload their own updates to be distributed and run on all installations. Another example is where objects or data are encoded or serialized into a structure that an attacker can see and modify is vulnerable to insecure deserialization.


## How to prevent. 



* Use digital signatures or similar mechanisms to verify the software or data is from the expected source and has not been altered.
* Ensure libraries and dependencies, such as npm or Maven, are only consuming trusted repositories. If you have a higher risk profile, consider hosting an internal known-good repository that's vetted.
* Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced into your software pipeline.
* Ensure that your CI/CD pipeline has proper segregation, configuration, and access control to ensure the integrity of the code flowing through the build and deploy processes.
* Ensure that unsigned or unencrypted serialized data is not received from untrusted clients and subsequently used without some form of integrity check or digital signature to detect tampering or replay of the serialized data.


## Example attack scenarios. 

**Scenario #1 Inclusion of Web Functionality from an Untrusted Source:** A company uses an external service provider to provide support functionality. For convenience, it has a DNS mapping for `myCompany.SupportProvider.com` to `support.myCompany.com`. This means that all cookies, including authentication cookies, set on the `myCompany.com` domain will now be sent to the support provider. Anyone with access to the support provider’s infrastructure can steal the cookies of all of your users that have visited <code>[support.myCompany.com](support.myCompany.com)</code> and perform a session hijacking attack.

**Scenario #1 Update without signing:** Many home routers, set-top boxes, device firmware, and others do not verify updates via signed firmware. Unsigned firmware is a growing target for attackers and is expected to only get worse. This is a major concern as many times there is no mechanism to remediate other than to fix in a future version and wait for previous versions to age out.

Scenario #2 A developer has trouble finding the updated version of a package they are looking for, so they download it not from the regular, trusted package manager, but from a website online. The package is not signed, and thus there is no opportunity to ensure integrity. The package includes malicious code. 

**Scenario #3 Insecure Deserialization:** A React application calls a set of Spring Boot microservices. Being functional programmers, they tried to ensure that their code is immutable. The solution they came up with is serializing the user state and passing it back and forth with each request. An attacker notices the "rO0" Java object signature (in base64) and uses the [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) to gain remote code execution on the application server.


## References.



* [OWASP Cheat Sheet: Software Supply Chain Security]
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)


## List of Mapped CWEs

[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

[CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

[CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
