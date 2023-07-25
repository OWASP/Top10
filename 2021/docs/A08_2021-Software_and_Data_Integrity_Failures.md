---
source:  "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
title:   "A08:2021 – Software and Data Integrity Failures"
id:      "A08:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".8" -%}
#A08:2021 – Software and Data Integrity Failures     ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Software and Data Integrity Failures", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.8") }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 6.94                 | 7.94                | 75.04%       | 45.35%       | 47,972            | 1,152      |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

A new category for 2021 focuses on making assumptions related to
software updates, critical data, and CI/CD pipelines without verifying
integrity. One of the highest weighted impacts from 
Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) 
data. Notable Common Weakness Enumerations (CWEs) include
*CWE-829: Inclusion of Functionality from Untrusted Control Sphere*,
*CWE-494: Download of Code Without Integrity Check*, and 
*CWE-502: Deserialization of Untrusted Data*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Software and data integrity failures relate to code and infrastructure
that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content
delivery networks (CDNs). An insecure CI/CD pipeline can introduce the
potential for unauthorized access, malicious code, or system compromise.
Lastly, many applications now include auto-update functionality, where
updates are downloaded without sufficient integrity verification and
applied to the previously trusted application. Attackers could
potentially upload their own updates to be distributed and run on all
installations. Another example is where
objects or data are encoded or serialized into a structure that an
attacker can see and modify is vulnerable to insecure deserialization.

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   Use digital signatures or similar mechanisms to verify the software or data is from the expected source and has not been altered.

-   Ensure libraries and dependencies, such as npm or Maven, are
    consuming trusted repositories. If you have a higher risk profile, consider hosting an internal known-good repository that's vetted.

-   Ensure that a software supply chain security tool, such as OWASP
    Dependency Check or OWASP CycloneDX, is used to verify that
    components do not contain known vulnerabilities

-   Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced into your software pipeline.

-   Ensure that your CI/CD pipeline has proper segregation, configuration, and access
    control to ensure the integrity of the code flowing through the
    build and deploy processes.

-   Ensure that unsigned or unencrypted serialized data is not sent to
    untrusted clients without some form of integrity check or digital
    signature to detect tampering or replay of the serialized data

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1 Update without signing:** Many home routers, set-top
boxes, device firmware, and others do not verify updates via signed
firmware. Unsigned firmware is a growing target for attackers and is
expected to only get worse. This is a major concern as many times there
is no mechanism to remediate other than to fix in a future version and
wait for previous versions to age out.

**Scenario #2 SolarWinds malicious update**: Nation-states have been
known to attack update mechanisms, with a recent notable attack being
the SolarWinds Orion attack. The company that develops the software had
secure build and update integrity processes. Still, these were able to
be subverted, and for several months, the firm distributed a highly
targeted malicious update to more than 18,000 organizations, of which
around 100 or so were affected. This is one of the most far-reaching and
most significant breaches of this nature in history.

**Scenario #3 Insecure Deserialization:** A React application calls a
set of Spring Boot microservices. Being functional programmers, they
tried to ensure that their code is immutable. The solution they came up
with is serializing the user state and passing it back and forth with
each request. An attacker notices the "`rO0`" Java object signature (in base64) and
uses the Java Serial Killer tool to gain remote code execution on the
application server.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.software supply chain security", osib=osib) }} <!-- \[OWASP Cheat Sheet: Software Supply Chain Security\](Coming Soon) --> 
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Secure build and deployment", osib=osib) }} <!--- \[OWASP Cheat Sheet: Secure build and deployment\](Coming Soon) --->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Infrastructure as Code Security", osib=osib) }} <!--- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)  --->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.deserialization", osib=osib) }} <!-- [OWASP Cheat Sheet: Deserialization]( <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>) --> 
-   {{ osib_link(link="osib.safecode.publication.software integrity controls.pdf", osib=osib) }} <!--- [SAFECode Software Integrity Controls]( https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)  -->
-   {{ osib_link(link="osib.npr.news.SolarWinds Hack", osib=osib) }} <!--- [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>) --->
-   {{ osib_link(link="osib.codecov.bash uploader compromise", doc="osib.codecov", osib=osib) }} <!--- [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)  --->
-   {{ osib_link(link="osib.julien vehent.securing devops", doc="osib.julien vehent", osib=osib) }} <!--- [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)  --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.345", doc="", osib=osib) }} <!-- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.353", doc="", osib=osib) }} <!-- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.426", doc="", osib=osib) }} <!-- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.494", doc="", osib=osib) }} <!-- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.502", doc="", osib=osib) }} <!-- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.565", doc="", osib=osib) }} <!-- [CWE-565: Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.784", doc="", osib=osib) }} <!-- [CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.829", doc="", osib=osib) }} <!-- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.830", doc="", osib=osib) }} <!-- [CWE-830: Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.915", doc="", osib=osib) }} <!-- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html) -->
