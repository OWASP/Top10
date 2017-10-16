# A10 Insufficient Logging and Monitoring

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalance \| Detectability | Technical \| Business |
| Exploitation of insufficient logging and monitoring is the bedrock of every major incident. Attackers rely on the lack of monitoring to achieve their goals without being detected. This issue is not easily detectable. Generally, dynamic testing would detect active response, such as being blocked. This is often not visible to tools. | There is little data on the prevalence of this issue, and so this issue has been selected by the community. | The impact of this issue is moderate to severe, due to delays in activating incident response, allowing the attacker more time to attack, and impairs understanding of what was disclosed or breached. |

## Am I vulnerable to attack?

Insufficient logging and monitoring occurs anytime:

* Auditable events, such as logins, failed logins, and high value transactions are not logged
* Logs are not monitored for suspicious activity
* Alerting or escalation as per the risk of the data held by the application is not in place or effective.

## How do I prevent

As per the risk of the data stored or processed by the application:

* Ensure all login and high value transactions can be logged
* Ensure sensitive and private information is not logged, or masked or truncated as per privacy laws and regulations
* Ensure stack traces and detailed errors are not sent to the screen, but to logs
* Ensure logs cannot easily be deleted or cleared without authorization
* Establish effective monitoring and alerting, such that suspicious activities such as brute force attacks or business loss are detected and responded within acceptable time periods.

Large or high performing organizations should have application security incident response plans in place, and tested across web apps and API services, with tooling integrated into processes, people and training. Such organizations may wish to invest in log correlation and analysis or security event incident management (SIEM) software or services. Open source and commercial offerings should be considered in light of organizational objectives and budget.

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
