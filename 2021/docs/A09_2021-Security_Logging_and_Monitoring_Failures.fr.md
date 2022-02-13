# A09:2021 – Carence des systèmes de contrôle et de journalisation    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       4        |       19,23 %        |         6,51 %         |             6,87              |         4,99         |    53,67 %     |      39,97 %       |           53 615           |         242          |

## Aperçu

La journalisation et la surveillance de la sécurité sont issues de l'enquête de la communauté Top 10 (n°3), en légère hausse par rapport à la dixième position dans le Top 10 2017 de l'OWASP. La journalisation et la surveillance peuvent être difficiles à tester, impliquant souvent des entretiens ou demandant si des attaques ont été détectées lors d'un test d'intrusion. Il n'y a pas beaucoup de données CVE/CVSS pour cette catégorie, mais la détection et la réponse aux brèches sont essentielles. Il n'en reste pas moins qu'elle peut avoir un impact considérable sur la responsabilité, la visibilité, l'alerte en cas d'incident et la forensique. Cette catégorie s'étend au-delà de *CWE-778 Insufficient Logging* pour inclure *CWE-117 Improper Output Neutralization for Logs*, *CWE-223 Omission of Security-relevant Information*, et *CWE-532* *Insertion of Sensitive Information into Log File*.

## Description 

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

## How to Prevent

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

## Example Attack Scenarios

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

## References

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP Application Security Verification Standard: V8 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## List of Mapped CWEs

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
