---
source:  "https://owasp.org/Top10/A04_2021-Insecure_Design/"
title:   "A04:2021 – Insecure Design"
id:      "A04:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".4" -%}
#A04:2021 – Insecure Design    ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}  {{ osib_anchor(osib=osib, id=id, name="Insecure Design", lang=lang, source=source, parent=parent) }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

A new category for 2021 focuses on risks related to design and architectural flaws, with a call for more use of threat modeling, secure design patterns, and reference architectures. As a community we need to move beyond  "shift-left" in the coding space to pre-code activities that are critical for the principles of Secure by Design. Notable Common Weakness Enumerations (CWEs) include *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation*, and *CWE-522: Insufficiently Protected Credentials*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Insecure design is a broad category representing different weaknesses, expressed as “missing or ineffective control design.” Insecure design is not the source for all other Top 10 risk categories. There is a difference between insecure design and insecure implementation. We differentiate between design flaws and implementation defects for a reason, they have different root causes and remediation. A secure design can still have implementation defects leading to vulnerabilities that may be exploited. An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks. One of the factors that contribute to insecure design is the lack of business risk profiling inherent in the software or system being developed, and thus the failure to determine what level of security design is required.

### Requirements and Resource Management

Collect and negotiate the business requirements for an application with the business, including the protection requirements concerning confidentiality, integrity, availability, and authenticity of all data assets and the expected business logic. Take into account how exposed your application will be and if you need segregation of tenants (additionally to access control). Compile the technical requirements, including functional and non-functional security requirements. Plan and negotiate the budget covering all design, build, testing, and operation, including security activities.

### Secure Design

Secure design is a culture and methodology that constantly evaluates threats and ensures that code is robustly designed and tested to prevent known attack methods. Threat modeling should be integrated into refinement sessions (or similar activities); look for changes in data flows and access control or other security controls. In the user story development determine the correct flow and failure states, ensure they are well understood and agreed upon by responsible and impacted parties. Analyze assumptions and conditions for expected and failure flows, ensure they are still accurate and desirable. Determine how to validate the assumptions and enforce conditions needed for proper behaviors. Ensure the results are documented in the user story. Learn from mistakes and offer positive incentives to promote improvements. Secure design is neither an add-on nor a tool that you can add to software.

### Secure Development Lifecycle

Secure software requires a secure development lifecycle, some form of secure design pattern, paved road methodology, secured component library, tooling, and threat modeling. Reach out for your security specialists at the beginning of a software project throughout the whole project and maintenance of your software. Consider leveraging the [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) to help structure your secure software development efforts.

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   Establish and use a secure development lifecycle with AppSec
    professionals to help evaluate and design security and
    privacy-related controls

-   Establish and use a library of secure design patterns or paved road
    ready to use components

-   Use threat modeling for critical authentication, access control,
    business logic, and key flows

-   Integrate security language and controls into user stories

-   Integrate plausibility checks at each tier of your application
    (from frontend to backend)

-   Write unit and integration tests to validate that all critical flows 
    are resistant to the threat model. Compile use-cases *and* misuse-cases
    for each tier of your application.

-   Segregate tier layers on the system and network layers depending on the
    exposure and protection needs

-   Segregate tenants robustly by design throughout all tiers

-   Limit resource consumption by user or service

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** A credential recovery workflow might include “questions
and answers,” which is prohibited by NIST 800-63b, the OWASP ASVS, and
the OWASP Top 10. Questions and answers cannot be trusted as evidence of
identity as more than one person can know the answers, which is why they
are prohibited. Such code should be removed and replaced with a more
secure design.

**Scenario #2:** A cinema chain allows group booking discounts and has a
maximum of fifteen attendees before requiring a deposit. Attackers could
threat model this flow and test if they could book six hundred seats and
all cinemas at once in a few requests, causing a massive loss of income.

**Scenario #3:** A retail chain’s e-commerce website does not have
protection against bots run by scalpers buying high-end video cards to
resell auction websites. This creates terrible publicity for the video
card makers and retail chain owners and enduring bad blood with
enthusiasts who cannot obtain these cards at any price. Careful anti-bot
design and domain logic rules, such as purchases made within a few
seconds of availability, might identify inauthentic purchases and
rejected such transactions.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Secure Product Design", osib=osib) }} <!-- [OWASP Cheat Sheet: Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.samm.2-0." ~ "Design.Security Architecture", osib=osib) }} <!-- [OWASP SAMM:: Design Security Architecture](https://owaspsamm.org/model/design/security-architecture/) -->
-   {{ osib_link(link="osib.owasp.samm.2-0." ~ "Design.Threat Assessment", osib=osib) }} <!-- [OWASP SAMM:: Design Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) --> 
-   {{ osib_link(link="osib.nist.publications.guidelines minimum standards developer verification software", osib=osib) }} <!--- [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software) --->
-   {{ osib_link(link="osib.threatmodelingmanifesto", doc="", osib=osib) }} <!--- [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org) --->
-   {{ osib_link(link="osib.hysnsec.awesome threat modelling", doc="", osib=osib) }} <!---[Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling) --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.73", doc="", osib=osib) }} <!-- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.183", doc="", osib=osib) }} <!-- [CWE-183: Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.209", doc="", osib=osib) }} <!-- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.213", doc="", osib=osib) }} <!-- [CWE-213: Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.235", doc="", osib=osib) }} <!-- [CWE-235: Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.256", doc="", osib=osib) }} <!-- [CWE-256: Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.257", doc="", osib=osib) }} <!-- [CWE-257: Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.266", doc="", osib=osib) }} <!-- [CWE-266: Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.269", doc="", osib=osib) }} <!-- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.280", doc="", osib=osib) }} <!-- [CWE-280: Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.311", doc="", osib=osib) }} <!-- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.312", doc="", osib=osib) }} <!-- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.313", doc="", osib=osib) }} <!-- [CWE-313: Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.316", doc="", osib=osib) }} <!-- [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.419", doc="", osib=osib) }} <!-- [CWE-419: Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.430", doc="", osib=osib) }} <!-- [CWE-430: Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.434", doc="", osib=osib) }} <!-- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.444", doc="", osib=osib) }} <!-- [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.451", doc="", osib=osib) }} <!-- [CWE-451: User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.472", doc="", osib=osib) }} <!-- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.501", doc="", osib=osib) }} <!-- [CWE-501: Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.522", doc="", osib=osib) }} <!-- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.525", doc="", osib=osib) }} <!-- [CWE-525: Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.539", doc="", osib=osib) }} <!-- [CWE-539: Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.579", doc="", osib=osib) }} <!-- [CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.598", doc="", osib=osib) }} <!-- [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.602", doc="", osib=osib) }} <!-- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.642", doc="", osib=osib) }} <!-- [CWE-642: External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.646", doc="", osib=osib) }} <!-- [CWE-646: Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.650", doc="", osib=osib) }} <!-- [CWE-650: Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.653", doc="", osib=osib) }} <!-- [CWE-653: Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.656", doc="", osib=osib) }} <!-- [CWE-656: Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.657", doc="", osib=osib) }} <!-- [CWE-657: Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.799", doc="", osib=osib) }} <!-- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.807", doc="", osib=osib) }} <!-- [CWE-807: Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.840", doc="", osib=osib) }} <!-- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.841", doc="", osib=osib) }} <!-- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.927", doc="", osib=osib) }} <!-- [CWE-927: Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1021", doc="", osib=osib) }} <!-- [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1173", doc="", osib=osib) }} <!-- [CWE-1173: Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html) -->
