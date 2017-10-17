# A10 Insufficient Logging, Detection and Active Response

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Exploitation of insufficient logging and monitoring is the bedrock of every major incident. Attackers rely on the lack of monitoring and timely response to achieve their goals without being detected. Generally, dynamic testing would detect active response, such as being blocked. This is often not visible to tools. | There is little data on the prevalence of this issue, and so this issue has been selected by the community. | The impact of this issue is moderate to severe, due to delays in activating incident response, allowing the attacker more time to attack, and impairs understanding of what was disclosed or breached. |

## Am I vulnerable to attack?

Insufficient logging, detection, monitoring and active response occurs anytime:

* Auditable events, such as logins, failed logins, and high value transactions are not logged
* Logs of applications and APIs are not monitored for suspicious activity
* Alerting thresholds and response escalation as per the risk of the data held by the application is not in place or effective.

For larger and high performing organizations, the lack of active response, such as real time alerting and response activities such as blocking automated attacks on web apps and particularly APIs would place the organization at risk from extended compromise. The response does not necessarily need to be visible to the attacker, only that the application and associated infrastructure, frameworks, service layers, etc can detect, alert and humans or tools respond in near real time or real time. 

## How do I prevent

As per the risk of the data stored or processed by the application:

* Ensure all login, access control failures, input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts
* Ensure high value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append only database tables or similar
* Ensure sensitive and private information is not logged, or masked or truncated as per privacy laws and regulations
* Ensure stack traces and detailed errors are not sent to the screen, but to logs
* Ensure logs cannot easily be deleted or cleared without authorization
* If a web application firewall (WAF) or API gateway is in place, consider the use of virtual patches where code cannot be fixed
* Establish effective monitoring and alerting, such that suspicious activities such as brute force attacks or business loss (such as transaction exceeding daily or hourly limits) are detected and responded within acceptable time periods.
* Establish or adopt an incident response and recovery plan, such as [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) or later

Large or high performing organizations should consider the use of web application firewalls, internal application protection, API gateways with security and rate limiting functionality as appropriate per the risk of the data assets being protected. Development and DevOps teams should agree on a common log format or labelling standard to assist in identifying security related events. Applications should assist in detecting and alerting in near or real time, by having sufficient logging and alerting in place, or the ability to ship logs to a service or system can centrally log, discover and alert security breaches. Even if tooling is not used, application security incident response and recovery plans should be place, and tested across web apps and API services, with tooling integrated into processes, people and training. 

There are commercial and open source application protection frameworks such as [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), web application firewalls such as [mod_security with the OWASP Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), and log correlation software such as [ELK](https://www.elastic.co/products) with custom dashboards and alerting. 

Organizations of all sizes should run a DAST tool, such as [OWASP Zap](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) or a web application or API scanner over their application or API to ensure that it triggers the logging through alerting functionality. Penetration testers should always trigger  alerting and response, but they should be whitelisted so as to ensure an effective penetration test can be take place.

## Example Scenarios

Target, a large US retailer, had an internal malware analysis sandbox analyzing attachments. The sandbox software had detected potentially unwanted software, but no one responded to this detection. By the time the point of sale breach was discovered, the sandbox had been alerting on this issue for over six months. Since this time, Target has invested heavily in security operations, including training, and network and application oversight.

An open source project forum software run by a small team was hacked using a flaw in its software. The attackers managed to wipe out the internal source code repository containing the next version, and all of the forum contents. Although source could be recovered, the lack of monitoring, logging or alerting led to a far worse breach. The forum software project is no longer active as a result of this issue.

## References

### OWASP

* [OWASP Proactive Controls - Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard - V7 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide - Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet - Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### External

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
