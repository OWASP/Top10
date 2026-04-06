# A09:2025 Security Logging & Alerting Failures ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## Background. 

Security Logging & Alerting Failures retains its position at #9. This category has a slight name change to emphasize the alerting function needed to induce action on relevant logging events. This category will always be underrepresented in the data, and for the third time voted into a position in the list from the community survey participants. This category is incredibly difficult to test for, and has minimal representation in the CVE/CVSS data (only 723 CVEs); but can be very impactful for visibility and incident alerting and forensics. This category includes issues with *properly handling output encoding to log files (CWE-117), inserting sensitive data into log files (CWE-532), and insufficient logging (CWE-778).*


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
   <td>5
   </td>
   <td>11.33%
   </td>
   <td>3.91%
   </td>
   <td>85.96%
   </td>
   <td>46.48%
   </td>
   <td>7.19
   </td>
   <td>2.65
   </td>
   <td>260,288
   </td>
   <td>723
   </td>
  </tr>
</table>



## Description. 

Without logging and monitoring, attacks and breaches cannot be detected, and without alerting it is very difficult to respond quickly and effectively during a security incident. Insufficient logging, continuous monitoring, detection, and alerting to initiate active responses occurs any time:


* Auditable events, such as logins, failed logins, and high-value transactions, are not logged or logged inconsistently (for instance, only logging successful logins, but not failed attempts).
* Warnings and errors generate no, inadequate, or unclear log messages.
* The integrity of logs is not properly protected from tampering.
* Logs of applications and APIs are not monitored for suspicious activity.
* Logs are only stored locally, and not properly backedup.
* Appropriate alerting thresholds and response escalation processes are not in place or effective. Alerts are not received or reviewed within a reasonable amount of time.
* Penetration testing and scans by dynamic application security testing (DAST) tools (such as Burp or ZAP) do not trigger alerts.
* The application cannot detect, escalate, or alert for active attacks in real-time or near real-time.
* You are vulnerable to sensitive information leakage by making logging and alerting events visible to a user or an attacker (see [A01:2025-Broken Access Control](A01_2025-Broken_Access_Control.md)), or by logging sensitive information that should not be logged (such as PII or PHI).
* You are vulnerable to injections or attacks on the logging or monitoring systems if log data is not correctly encoded.
* The application is missing or mishandling errors and other exceptional conditions, such that the system is unaware there was an error, and is therefore unable to log there was a problem.
* Adequate ‘use cases’ for issuing alerts are missing or outdated to recognize a special situation.
* Too many false positive alerts make it impossible to distinguish important alerts from unimportant ones, resulting in them being recognized too late or not at all (physical overload of the SOC team).
* Detected alerts cannot be processed correctly because the playbook for the use case is incomplete, out of date, or missing.


## How to prevent.

Developers should implement some or all the following controls, depending on the risk of the application:


* Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts and held for enough time to allow delayed forensic analysis.
* Ensure that every part of your app that contains a security control is logged, whether it succeeds or fails.
* Ensure that logs are generated in a format that log management solutions can easily consume.
* Ensure log data is encoded correctly to prevent injections or attacks on the logging or monitoring systems.
* Ensure all transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar.
* Ensure all transactions that throw an error are rolled back and started over. Always fail closed.
* If your application or its users behave suspiciously, issue an alert. Create guidance for your developers on this topic so they can code against this or buy a system for this.
* DevSecOps and security teams should establish effective monitoring and alerting use cases including playbooks such that suspicious activities are detected and responded to quickly by the Security Operations Center (SOC) team.
* Add ‘honeytokens’ as traps for attackers into your application e.g. into the database, data, as real and/or technical user identity. As they are not used in normal business, any access generates logging data that can be alerted with nearly no false positives.
* Behavior analysis and AI support could be optionally an additional technique to support low rates of false positives for alerts.
* Establish or adopt an incident response and recovery plan, such as National Institute of Standards and Technology (NIST) 800-61r2 or later. Teach your software developers what application attacks and incidents look like, so they can report them.

There are commercial and open-source application protection products such as the OWASP ModSecurity Core Rule Set, and open-source log correlation software, such as the Elasticsearch, Logstash, Kibana (ELK) stack, that feature custom dashboards and alerting that may help you combat these issues. There are also commercial observability tools that can help you respond to or block attacks in close to real-time.


## Example attack scenarios.

**Scenario #1:** A children's health plan provider's website operator couldn't detect a breach due to a lack of monitoring and logging. An external party informed the health plan provider that an attacker had accessed and modified thousands of sensitive health records of more than 3.5 million children. A post-incident review found that the website developers had not addressed significant vulnerabilities. As there was no logging or monitoring of the system, the data breach could have been in progress since 2013, a period of more than seven years.

**Scenario #2:** A major Indian airline had a data breach involving more than ten years' worth of personal data of millions of passengers, including passport and credit card data. The data breach occurred at a third-party cloud hosting provider, who notified the airline of the breach after some time.

**Scenario #3:** A major European airline suffered a GDPR reportable breach. The breach was reportedly caused by payment application security vulnerabilities exploited by attackers, who harvested more than 400,000 customer payment records. The airline was fined 20 million pounds as a result by the privacy regulator.


## References.

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## List of Mapped CWEs

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
