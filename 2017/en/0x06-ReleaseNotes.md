# RN Release Notes

## What changed from 2013 to 2017?

Over the last decade, and in particularly these last few years, the fundamental architecture of applications has changed significantly:

* JavaScript is now the primary language of the web. node.js and modern web frameworks such as Bootstrap, Electron, Angular, React amongst many others, means source that was once on the server is now running on untrusted browsers. 
* Single page applications, written in modern frameworks such as Angular and React, allow the creation of highly modular front end user experiences.
* Microservices written in node.js and Spring Boot are replacing older enterprise service bus applications using EJBs and so on. Old code that never expected to be communicated with directly from the Internet is now sitting behind an API or RESTful web service. The assumptions that underlie this code, such as trusted callers, is simply not valid. 

Change has accelerated over the last five years, and the OWASP Top 10 needed to change. We've completely refactored the OWASP Top 10, revamped the methodology, utilized a new data call process, worked with the community, re-ordered our risks, re-written each risk from the ground up, and added modern references to frameworks and languages that are now commonly used. 

In this 2017 release, we made the following changes:

| OWASP Top 10 2013 | OWASP Top 10 2017 |
| -- | -- |
| A1 - Injection | A1:2017 Injection |
| A2 - Broken authentication and session management | A2:2017-Authentication |
| A3 - Cross-site scripting | A3:2017-Sensitive Information Disclosure |
| A4 - Insecure direct object references | A4:2017-XML External Entities [NEW] |
| A5 - Security Misconfiguration | A5:2017-Security Misconfiguration |
| A6 - Sensitive Data Exposure | A6:2017-Access Control |
| A7 - Missing Function Level Access Control | A7:2017-XSS |
| A8 - Cross-site Request Forgery (CSRF) | A8:2017-Deserialization [NEW, Community] |
| A9 - Known Vulnerabilities | A9:2017-Known Vulnerabilities |
| A10 - Unvalidated redirects and forwards | A10:2017-Insufficient Logging and Monitoring [NEW, Community] |

NB: Although most of these issues are weaknesses, Insufficient Logging and Monitoring is a missing or ineffective controls. It has two CWE entries, but in this case, not only did the community rank this issue, we felt if we did not include detection and response in the OWASP Top 10 2017, we'd be negligent in our duties to the wider development community. With firewalls, logging, network IPS and endpoint protection systems unable to detect web hacks, it falls on web apps themselves to be the new firewall, especially for cloud-based microservices, where there is no firewall, no IPS, and no end points.

## New issues, supported by data

A4:2017-XML External Entity (XXE) is a new category primarily supported by SAST data sets, but when discovered by penetration testers and dynamic tools, this new issue allows attackers to disclose internal information, scan internal systems, and possibly perform denial of service attacks.

## New issues, supported by the community

We asked the community to provide insight into two forward looking weakness categories. After 550 peer submissions, and after removing issues that were already supported by data (such as Sensitive Data Exposure and XXE), the two new issues are A8:2017-Deserialization, responsible for one of the worst breaches of all time, and A10:2017-Insufficient Logging and Monitoring, the lack of which can prevent or significantly delay malicious activity and breach detection, incident response and digital forensics.

## Retired, but not forgotten

* **A4 Insecure direct object references** and A7 Missing function level access control. We have merged these two issues into a single access control finding, as the impacts and prevention recommendations are more or less identical. This allows us to free up room for an additional issue, which is XXE.
* **A8 CSRF** - When added to the OWASP Top 10 2007, nearly every application was vulnerable to CSRF. As the weakness is now found in less than 2% of all applications, it has fallen off the bottom of the list. 
* **A10 Unvalidated redirects and forwards**. Although this issue is a relative of XSS, and injections more broadly, the actual CWE issue has fallen out of the 10 positions available. As this issue is automatically detected by both DAST and SAST tools, we encourage organizations and vendors to keep on reporting on this issue.
