---
source:  "https://owasp.org/Top10/09_2021-Security_Logging_and_Monitoring_Failures/"
title:   "A09:2021 – Security Logging and Monitoring Failures"
id:      "A09:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".9" -%}
#A09:2021 – Security Logging and Monitoring Failures     ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Security Logging and Monitoring Failures", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.10") }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Security logging and monitoring came from the Top 10 community survey (#3), up
slightly from the tenth position in the OWASP Top 10 2017. Logging and
monitoring can be challenging to test, often involving interviews or
asking if attacks were detected during a penetration test. There isn't
much CVE/CVSS data for this category, but detecting and responding to
breaches is critical. Still, it can be very impactful for accountability, visibility,
incident alerting, and forensics. This category expands beyond *CWE-778
Insufficient Logging* to include *CWE-117 Improper Output Neutralization
for Logs*, *CWE-223 Omission of Security-relevant Information*, and
*CWE-532* *Insertion of Sensitive Information into Log File*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Returning to the OWASP Top 10 2021, this category is to help detect,
escalate, and respond to active breaches. Without logging and
monitoring, breaches cannot be detected. Insufficient logging,
detection, monitoring, and active response occurs any time:

-   Auditable events, such as logins, failed logins, and high-value
    transactions, are not logged.

-   Warnings and errors generate no, inadequate, or unclear log
    messages.

-   Logs of applications and APIs are not monitored for suspicious
    activity.

-   Logs are only stored locally.

-   Appropriate alerting thresholds and response escalation processes
    are not in place or effective.

-   Penetration testing and scans by dynamic application security testing (DAST) tools (such as OWASP ZAP) do
    not trigger alerts.

-   The application cannot detect, escalate, or alert for active attacks
    in real-time or near real-time.

You are vulnerable to information leakage by making logging and alerting
events visible to a user or an attacker (see [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Developers should implement some or all the following controls, 
depending on the risk of the application:

-   Ensure all login, access control, and server-side input validation
    failures can be logged with sufficient user context to identify
    suspicious or malicious accounts and held for enough time to allow
    delayed forensic analysis.

-   Ensure that logs are generated in a format that log management
    solutions can easily consume.

-   Ensure log data is encoded correctly to prevent injections or
    attacks on the logging or monitoring systems.

-   Ensure high-value transactions have an audit trail with integrity
    controls to prevent tampering or deletion, such as append-only
    database tables or similar.

-   DevSecOps teams should establish effective monitoring and alerting
    such that suspicious activities are detected and responded to
    quickly.

-   Establish or adopt an incident response and recovery plan, such as
    National Institute of Standards and Technology (NIST) 800-61r2 or later.

There are commercial and open-source application protection frameworks
such as the OWASP ModSecurity Core Rule Set, and open-source log
correlation software, such as the Elasticsearch, Logstash, Kibana (ELK)
stack, that feature custom dashboards and alerting.

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** A children's health plan provider's website operator
couldn't detect a breach due to a lack of monitoring and logging. An
external party informed the health plan provider that an attacker had
accessed and modified thousands of sensitive health records of more than
3.5 million children. A post-incident review found that the website
developers had not addressed significant vulnerabilities. As there was
no logging or monitoring of the system, the data breach could have been
in progress since 2013, a period of more than seven years.

**Scenario #2:** A major Indian airline had a data breach involving more
than ten years' worth of personal data of millions of passengers,
including passport and credit card data. The data breach occurred at a
third-party cloud hosting provider, who notified the airline of the
breach after some time.

**Scenario #3:** A major European airline suffered a GDPR reportable
breach. The breach was reportedly caused by payment application security
vulnerabilities exploited by attackers, who harvested more than 400,000
customer payment records. The airline was fined 20 million pounds as a
result by the privacy regulator.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.opc.3." ~ "9", osib=osib) }} <!-- [OWASP Proactive Controls: Implement Logging and Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html) --> 
-   {{ osib_link(link="osib.owasp.asvs.4-0." ~ "7", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V7 Logging and Monitoring](https://owasp.org/www-project-application-security-verification-standard) --> 
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.8.1", osib=osib) }} <!--- was: [OWASP Testing Guide: Testing for Detailed Error Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code) --->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Logging Vocabulary", osib=osib) }} <!-- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html) --> 
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Logging", osib=osib) }} <!-- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) --> 
-   {{ osib_link(link="osib.nist.csrc.sp.1800-11", osib=osib) }} <!--- [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final) --->
-   {{ osib_link(link="osib.nist.csrc.sp.1800-25", osib=osib) }} <!--- [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final) --->
-   {{ osib_link(link="osib.nist.csrc.sp.1800-26", osib=osib) }} <!--- [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final) --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.117", doc="", osib=osib) }} <!-- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.223", doc="", osib=osib) }} <!-- [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.532", doc="", osib=osib) }} <!-- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.778", doc="", osib=osib) }} <!-- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html) -->
