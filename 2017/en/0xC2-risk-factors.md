# +F Details about Risk factors

## Top 10 Risk Factor Summary

The following table presents a summary of the 2017 Top 10 Application Security Risks, and the risk factors we have assigned to each risk. These factors were determined based on the available statistics and the experience of the OWASP Top 10 team. To understand these risks for a particular application or organization, you must consider your own specific threat agents and business impacts. Even egregious software weaknesses may not present a serious risk if there are no threat agents in a position to perform the necessary attack or the business impact is negligible for the assets involved.

| Risk | Threat Agents | Exploitability | Prevalence | Detectability | Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- | --- | 
| A1-Injection | App Specific | EASY | COMMON | AVERAGE | SEVERE | App Specific |
| A2-Authentication | App Specific | AVERAGE | COMMON | AVERAGE | SEVERE | App Specific |
| A3-XSS | App Specific | AVERAGE | VERY WIDESPREAD | AVERAGE | MODERATE | App Specific |
| A4-Access Control | App Specific | EASY | WIDESPREAD   |  EASY | MODERATE | App Specific |
| A5-Misconfig | App Specific | EASY | COMMON | EASY | SEVERE | App Specific |
| A6-Sensitive Data | App Specific | DIFFICULT | UNCOMMON | AVERAGE | SEVERE | App Specific |
| A7-Attack Protection | App Specific | EASY | COMMON | AVERAGE | MODERATE | App Specific |
| A8-CSRF | App Specific | AVERAGE | UNCOMMON | EASY | MODERATE | App Specific |
| A9-Components | App Specific | AVERAGE | COMMON | AVERAGE | MODERATE | App Specific |
| A10-API Protection| App Specific | AVERAGE | COMMON | DIFFICULT | MODERATE | App Specific |

## Additional Risks To Consider

The OWASP Top 10 2017 Release Candidate 1 (RC1) contained two missing controls: 
* A7 Missing Attack Protection
* A10 Missing API Protection

These controls should be in place, in use, and effective in any mature application security program. However, as the OWASP Top 10 2017 is a vulnerability view, we have incorporated the idea of these controls into each recommendation as necessary, rather than call them out separately. These missing controls have a place in the OWASP Proactive Controls and a forthcoming OWASP Top 10 Defences.

The Top 10 covers a lot of ground, but there are many other risks you should consider and evaluate in your organization. Some of these have appeared in previous versions of the Top 10, and others have not, including new attack techniques that are being identified all the time. 

During the preparation of the OWASP Top 10 2017, a survey of information security professionals was conducted, with over 500 responses. Coupled with the data call, the following issues should be considered as part of your application security program, and indeed has either previously appeared in previous OWASP Top 10 editions, or might end up in a future OWASP Top 10:

* TBA - replace with the survey list
