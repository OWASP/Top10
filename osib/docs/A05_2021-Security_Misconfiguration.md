---
source:  "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
title:   "A05:2021 – Security Misconfiguration"
id:      "A05:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".5" -%}
#A05:2021 – Security Misconfiguration     ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Security Misconfiguration", lang=lang, source=source, parent=parent, merged_from=[extra.osib.document ~ ".2017.4", extra.osib.document ~ ".2017.6"]) }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 8.12                 | 6.56                | 89.58%       | 44.84%       | 208,387           | 789        |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Moving up from #6 in the previous edition, 90% of applications were
tested for some form of misconfiguration, with an average incidence rate of 4.%, and over 208k occurrences of a Common Weakness Enumeration (CWE) in this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up.
Notable CWEs included are *CWE-16 Configuration* and *CWE-611 Improper
Restriction of XML External Entity Reference*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

The application might be vulnerable if the application is:

-   Missing appropriate security hardening across any part of the
    application stack or improperly configured permissions on cloud
    services.

-   Unnecessary features are enabled or installed (e.g., unnecessary
    ports, services, pages, accounts, or privileges).

-   Default accounts and their passwords are still enabled and
    unchanged.

-   Error handling reveals stack traces or other overly informative
    error messages to users.

-   For upgraded systems, the latest security features are disabled or
    not configured securely.

-   The security settings in the application servers, application
    frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases,
    etc., are not set to secure values.

-   The server does not send security headers or directives, or they are
    not set to secure values.

-   The software is out of date or vulnerable (see [A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)). 
Without a concerted, repeatable application security configuration
process, systems are at a higher risk.

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Secure installation processes should be implemented, including:

-   A repeatable hardening process makes it fast and easy to deploy
    another environment that is appropriately locked down. Development,
    QA, and production environments should all be configured
    identically, with different credentials used in each environment.
    This process should be automated to minimize the effort required to
    set up a new secure environment.

-   A minimal platform without any unnecessary features, components,
    documentation, and samples. Remove or do not install unused features
    and frameworks.

-   A task to review and update the configurations appropriate to all
    security notes, updates, and patches as part of the patch management
    process (see [A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)). Review     cloud storage permissions (e.g., S3 bucket permissions).

-   A segmented application architecture provides effective and secure
    separation between components or tenants, with segmentation,
    containerization, or cloud security groups (ACLs).

-   Sending security directives to clients, e.g., Security Headers.

-   An automated process to verify the effectiveness of the
    configurations and settings in all environments.

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** The application server comes with sample applications
not removed from the production server. These sample applications have
known security flaws attackers use to compromise the server. Suppose one
of these applications is the admin console, and default accounts weren't
changed. In that case, the attacker logs in with default passwords and
takes over.

**Scenario #2:** Directory listing is not disabled on the server. An
attacker discovers they can simply list directories. The attacker finds
and downloads the compiled Java classes, which they decompile and
reverse engineer to view the code. The attacker then finds a severe
access control flaw in the application.

**Scenario #3:** The application server's configuration allows detailed
error messages, e.g., stack traces, to be returned to users. This
potentially exposes sensitive information or underlying flaws such as
component versions that are known to be vulnerable.

**Scenario #4:** A cloud service provider (CSP) has default sharing
permissions open to the Internet by other CSP users. This allows
sensitive data stored within cloud storage to be accessed.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.wstg.4-2.4.2", osib=osib) }} <!-- [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README) -->
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.8", osib=osib) }} <!-- [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.14", osib=osib) }} <!--- [Application Security Verification Standard V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md) --->
-   {{ osib_link(link="osib.nist.csrc.sp.800-123", osib=osib) }} <!--- [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final) --->
-   {{ osib_link(link="osib.cis.benchmarks", osib=osib) }} <!--- [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)  --->
-   {{ osib_link(link="osib.websecurify.aws s3 bucket discovery", doc="osib.websecurify", osib=osib) }} <!--- Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)  --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.2", doc="", osib=osib) }} <!-- [CWE-2: 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.11", doc="", osib=osib) }} <!-- [CWE-11: ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.13", doc="", osib=osib) }} <!-- [CWE-13: ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.15", doc="", osib=osib) }} <!-- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.16", doc="", osib=osib) }} <!-- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.260", doc="", osib=osib) }} <!-- [CWE-260: Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.315", doc="", osib=osib) }} <!-- [CWE-315: Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.520", doc="", osib=osib) }} <!-- [CWE-520: .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.526", doc="", osib=osib) }} <!-- [CWE-526: Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.537", doc="", osib=osib) }} <!-- [CWE-537: Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.541", doc="", osib=osib) }} <!-- [CWE-541: Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.547", doc="", osib=osib) }} <!-- [CWE-547: Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.611", doc="", osib=osib) }} <!-- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.614", doc="", osib=osib) }} <!-- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.756", doc="", osib=osib) }} <!-- [CWE-756: Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.776", doc="", osib=osib) }} <!-- [CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.942", doc="", osib=osib) }} <!-- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1004", doc="", osib=osib) }} <!-- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1032", doc="", osib=osib) }} <!-- [CWE-1032: OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1174", doc="", osib=osib) }} <!-- [CWE-1174: ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html) -->
