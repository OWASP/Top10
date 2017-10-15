# A4 XML External Entities (XXE)

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | AVERAGE (2) | Penetration testers should be capable of exploiting XXE once trained. DAST tools require additional manual steps to exploit this issue. |
| Prevalence | COMMON (2) | XXE was found in a significant number of apps and web services. |
| Detectability | EASY (3) | Automated detection of XXE is possible by DAST tools by inspecting for XML documents or data used, or by setting up a web server or tool to receive connections from the victim XML processor. SAST tools can discover this issue by inspecting dependencies and configuration. |
| Impact | SEVERE (3) | XXE can be used for internal port scanning, internal remote and local file inclusion, and for denial of service. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 7.0 | HIGH |

## Am I vulnerable to attack?

TBA

## How do I prevent

TBA

## Example Scenarios

TBA

## References

### OWASP
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()

### External

TBA
