# A10:2017 Insufficient Logging, Detection and Active Response

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 3 \| Detectability 1 | Technical 2 \| Business |
| Exploitation of insufficient logging and monitoring is the bedrock of nearly every major incident. Attackers rely on the lack of monitoring and timely response to achieve their goals without being detected. | This issue is included in the Top 10 based on an [industry survey](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). One strategy for determining if you have sufficient monitoring is to examine your logs following penetration testing. The testers actions should be recorded sufficiently to understand what damages they may have inflicted. | Most successful attacks start with vulnerability probing. Allowing such probes to continue can raise the likelihood of successful exploit to nearly 100%. |

## Is the Application Vulnerable?

Insufficient logging, detection, monitoring and active response occurs any time:

* Auditable events, such as logins, failed logins, and high value transactions are not logged.
* Logs of applications and APIs are not monitored for suspicious activity.
* Alerting thresholds and response escalation as per the risk of the data held by the application is not in place or effective.

For larger and high performing organizations, the lack of active response, such as real time alerting and response activities such as blocking automated attacks on web apps and particularly APIs would place the organization at risk from extended compromise. The response does not necessarily need to be visible to the attacker, only that the application and associated infrastructure, frameworks, service layers, etc. can detect and alert humans or tools to respond in near real time.

## How To Prevent?

As per the risk of the data stored or processed by the application:

* Ensure all login, access control failures, server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis.
* Ensure high value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append only database tables or similar.
* Establish effective monitoring and alerting such that suspicious activities are detected and responded within acceptable time periods.
* Establish or adopt an incident response and recovery plan, such as [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) or later.

There are commercial and open source application protection frameworks such as [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), web application firewalls such as [mod_security with the OWASP Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), and log correlation software such as [ELK](https://www.elastic.co/products) with custom dashboards and alerting. Penetration testing and scans by DAST tools (such as OWASP ZAP) should always trigger alerts.

## Example Attack Scenarios

**Scenario 1**: An open source project forum software run by a small team was hacked using a flaw in its software. The attackers managed to wipe out the internal source code repository containing the next version, and all of the forum contents. Although source could be recovered, the lack of monitoring, logging or alerting led to a far worse breach. The forum software project is no longer active as a result of this issue.

**Scenario 2**: An attacker uses scans for users using a common password. He can take over all accounts using this password. For all other users this scan leaves only 1 false login behind. After some days this may be repeated with a different password.

**Scenario 3**: A major US retailer reportedly had an internal malware analysis sandbox analyzing attachments. The sandbox software had detected potentially unwanted software, but no one responded to this detection. The sandbox had been producing warnings for some time before the breach was detected due to fraudulent card transactions by an external bank.

## References

### OWASP

* [OWASP Proactive Controls - Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard - V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide - Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet - Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### External

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
