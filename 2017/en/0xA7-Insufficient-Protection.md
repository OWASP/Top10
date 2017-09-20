# A7 Insufficient Attack Protection 

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

## Am I vulnerable to 
Detecting, responding to, and blocking attacks makes applications dramatically harder to exploit yet almost no applications or APIs have such protection. Critical vulnerabilities in both custom code and components are also discovered all the time, yet organizations frequently take weeks or even months to roll out new defenses.
It should be very obvious if attack detection and response isn’t in place. Simply try manual attacks or run a scanner against the application. The application or API should identify the attacks, block any viable attacks, and provide details on the attacker and characteristics of the attack. If you can’t quickly roll out virtual and/or actual patches when a critical vulnerability is discovered, you are left exposed to attack.
Be sure to understand what types of attacks are covered by attack protection. Is it only XSS and SQL Injection? You can use technologies like WAFs, RASP, and OWASP AppSensor to detect or block attacks, and/or virtually patch vulnerabilities.

## How do I prevent

There are three primary goals for sufficient attack protection:
* Detect Attacks. Did something occur that is impossible for legitimate users to cause (e.g., an input a legitimate client can’t generate)? Is the application being used in a way that an ordinary user would never do (e.g., tempo too high, atypical input, unusual usage patterns, repeated requests)?
* Respond to Attacks. Logs and notifications are critical to timely response. Decide whether to automatically block requests, IP addresses, or IP ranges. Consider disabling or monitoring misbehaving user accounts.
Patch Quickly. If your dev process can’t push out critical patches in a day, deploy a virtual patch that analyzes HTTP traffic, data flow, and/or code execution and prevents vulnerabilities from being exploited.
* How quickly can you deploy a real or virtual patch to block continued exploitation of this vulnerability?
## Example Scenarios
Scenario #1: Attacker uses automated tool like OWASP ZAP or SQLMap to detect vulnerabilities and possibly exploit them.
Attack detection should recognize the application is being targeted with unusual requests and high volume. Automated scans should be easy to distinguish from normal traffic.
Scenario #2: A skilled human attacker carefully probes for potential vulnerabilities, eventually finding an obscure flaw.
While more difficult to detect, this attack still involves requests that a normal user would never send, such as input not allowed by the UI. Tracking this attacker may require building a case over time that demonstrates malicious intent.
Scenario #3: Attacker starts exploiting a vulnerability in your application that your current attack protection fails to block.

## References

### OWASP
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()

External
 WASC Article on Insufficient Anti-automation
 CWE Entry 778 - Insufficient Logging
 CWE Entry 799 - Improper Control of Interaction Frequency
