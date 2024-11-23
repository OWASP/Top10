---
source:  "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
title:   "A06:2021 – Vulnerable and Outdated Components"
id:      "A06:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".6" -%}
#A06:2021 – Vulnerable and Outdated Components     ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Vulnerable and Outdated Components", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.9") }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

It was #2 from the Top 10 community survey but also had enough data to make the
Top 10 via data. Vulnerable Components are a known issue that we
struggle to test and assess risk and is the only category to not have
any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploits/impact
weight of 5.0 is used. Notable CWEs included are *CWE-1104: Use of
Unmaintained Third-Party Components* and the two CWEs from Top 10 2013
and 2017.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

You are likely vulnerable:

-   If you do not know the versions of all components you use (both
    client-side and server-side). This includes components you directly
    use as well as nested dependencies.

-   If the software is vulnerable, unsupported, or out of date. This
    includes the OS, web/application server, database management system
    (DBMS), applications, APIs and all components, runtime environments,
    and libraries.

-   If you do not scan for vulnerabilities regularly and subscribe to
    security bulletins related to the components you use.

-   If you do not fix or upgrade the underlying platform, frameworks,
    and dependencies in a risk-based, timely fashion. This commonly
    happens in environments when patching is a monthly or quarterly task
    under change control, leaving organizations open to days or months
    of unnecessary exposure to fixed vulnerabilities.

-   If software developers do not test the compatibility of updated,
    upgraded, or patched libraries.

-   If you do not secure the components’ configurations (see
    [A05:2021-Security Misconfiguration](A05_2021-Security_Misconfiguration.md)).

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

There should be a patch management process in place to:

-   Remove unused dependencies, unnecessary features, components, files,
    and documentation.

-   Continuously inventory the versions of both client-side and
    server-side components (e.g., frameworks, libraries) and their
    dependencies using tools like versions, OWASP Dependency Check,
    retire.js, etc. Continuously monitor sources like Common Vulnerability and 
    Exposures (CVE) and National Vulnerability Database (NVD) for
    vulnerabilities in the components. Use software composition analysis
    tools to automate the process. Subscribe to email alerts for
    security vulnerabilities related to components you use.

-   Only obtain components from official sources over secure links.
    Prefer signed packages to reduce the chance of including a modified,
    malicious component (See A08:2021-Software and Data Integrity
    Failures).

-   Monitor for libraries and components that are unmaintained or do not
    create security patches for older versions. If patching is not
    possible, consider deploying a virtual patch to monitor, detect, or
    protect against the discovered issue.

Every organization must ensure an ongoing plan for monitoring, triaging,
and applying updates or configuration changes for the lifetime of the
application or portfolio.

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** Components typically run with the same privileges as
the application itself, so flaws in any component can result in serious
impact. Such flaws can be accidental (e.g., coding error) or intentional
(e.g., a backdoor in a component). Some example exploitable component
vulnerabilities discovered are:

-   CVE-2017-5638, a Struts 2 remote code execution vulnerability that
    enables the execution of arbitrary code on the server, has been
    blamed for significant breaches.

-   While the internet of things (IoT) is frequently difficult or
    impossible to patch, the importance of patching them can be great
    (e.g., biomedical devices).

There are automated tools to help attackers find unpatched or
misconfigured systems. For example, the Shodan IoT search engine can
help you find devices that still suffer from Heartbleed vulnerability
patched in April 2014.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}
-   {{ osib_link(link="osib.owasp.asvs.4-0." ~ "1", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](/www-project-application-security-verification-standard) -->
-   {{ osib_link(link="osib.owasp.dependency check", osib=osib) }} <!--- [OWASP Dependency Check (for Java and .NET libraries)](/www-project-dependency-check) --->
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.1.10", osib=osib) }} <!--- [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture) --->
-   {{ osib_link(link="osib.owasp.community.0.other.virtual patching best practices", osib=osib) }} <!--- [OWASP Virtual Patching Best Practices](/www-community/Virtual_Patching_Best_Practices) --->
-   {{ osib_link(link="osib.contrast.insecure libraries.2014", doc="osib.contrast", osib=osib) }} <!--- [The Unfortunate Reality of Insecure Libraries](https://cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf) --->
-   {{ osib_link(link="osib.cvedetails.search", osib=osib) }} <!--- [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php) --->
-   {{ osib_link(link="osib.nist.nvd", osib=osib) }} <!--- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) --->
-   {{ osib_link(link="osib.retirejs", osib=osib) }} <!--- [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/) --->
-   {{ osib_link(link="osib.github.advisories", osib=osib) }} <!--- [GitHub Advisory Database](https://github.com/advisories) --->
-   {{ osib_link(link="osib.rubysec", osib=osib) }} <!--- [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/) --->
-   {{ osib_link(link="osib.safecode.publications.Software Integrity Controls.0.pdf", doc="osib.safecode", osib=osib) }} <!--- [SAFECode Software Integrity Controls \[PDF\]](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf) --->


## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.937", doc="", osib=osib) }} <!-- [CWE-937: OWASP Top 10 2013: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/937.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1035", doc="", osib=osib) }} <!-- [CWE-1035: 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1104", doc="", osib=osib) }} <!-- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) -->
