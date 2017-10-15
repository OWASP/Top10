# +R About Risks

## Defining our terms

One of the long standing tensions within the information security industry is the misunderstanding or misuse of common terms, such as threats, threat agents, weaknesses, defects, flaws, vulnerabilities, and risks. As such, we are defining our terms to ensure that there is no confusion. 

| Term | Description | 
| --- | --- |
| Data asset | A data asset is something tangible processed and stored by an application or API, such as an identity store, customer database, health records, tax returns, bank or mortgage accounts, and so on. |  
| Threat agent | Threat agents can be humans, with or or without motives, or even in some cases, scripts (such as botnets or worms). Outside of criminal prosecutions and state response, the identity of a threat actor is only important in terms of understanding the sorts of targets and actions the threat agent is likely to target to assist in forensics and incident response. |
| Weakness | A weakness is a software architectural or design flaw or technical defect that allows a threat agent to exploit a vulnerability within the code. The likelihood of this occuring is well understood within the application security industry. |
| Flaw | A flaw is a requirements, architecture, or design mistake that will take considerable effort to refactor or mitigate |
| Defect | A defect is a bug or a piece of code that fails to properly use an effective control |
| Control | A control is a piece of code, process or people that mitigates  
| Impact | The impact of a threat agent exploiting a vulnerability is highly dependant on the data asset being processed, stored or protected by the application or API. However, for these 10 vulnerability classes, we can estimate a baseline impact based upon public breach information, such as Dataloss DB, media coverage, and financial impact for publicly listed companies. 

The ISO standard for Risk Management is ISO 31000, which defines risks as likelihood x impact. Risk managers worldwide use this working definition to triage, prioritize, and mitigate, transfer or accept risks to the organization. 

As no two applications has the same business requirements, is likely built very differently, and integrated with different systems, it's impossible to define a universal impact that would be valid under ISO 31000. Even the same application, such as a CMS would have very different impacts depending on the data assets processed or stored within the CMS. For example, a public wiki containing non-confidential information might need integrity controls, but has no intrinsic value, and thus the disclosure of inforamtion from the wiki is desirable rather than a risk. However, if this same software was used to store sensitive medical records, the data asset has attached legal, privacy and regulatory protection that requires data to be encrypted and access to be audited. Any data leak, tampering or data loss would be a critical risk to the organization. 

So how do we judge risks in the ISO 31000 context? Simply, we can't. However, to assist organizations, we use our judgement based upon past experience in the finance, health, government, mining, logistics and other fields to give a rough estimate as to a baseline likelihood and baseline impact. 

These baselines are derived in two ways:

* Through a data call, which analyzes real world security test results

* Through a survey of over 500 security professionals

We use these results to inform the OWASP Top 10 regarding likelihood, and we inspect data breach databases to determine typical breach impacts resulting from that type of vulnerability. 

Our methodology includes three likelihood factors for each weakness (prevalence, detectability, and ease of exploit) and one impact factor (technical impact). The prevalence of a weakness is a factor that you typically don't have to calculate. For prevalence data, we have been supplied prevalence statistics from a number of different organizations (as referenced in the Attribution section on page 4) and we have averaged their data together to come up with a Top 10 likelihood of existence list by prevalence. This data was then combined with the other two likelihood factors (detectability and ease of exploit) to calculate a likelihood rating for each weakness. The likelihood rating was then multiplied by our estimated average technical impact for each item to come up with an overall risk ranking for each item in the Top 10.

Note that this approach does not take the likelihood of the threat agent into account. Nor does it account for any of the various technical details associated with your particular application. Any of these factors could significantly affect the overall likelihood of an attacker finding and exploiting a particular vulnerability. This rating also does not take into account the actual impact on your business. Your organization will have to decide how much security risk from applications and APIs the organization is willing to accept given your culture, industry, and regulatory environment. The purpose of the OWASP Top 10 is not to do this risk analysis for you.

The following illustrates our calculation of the risk for A3: Cross-Site Scripting, as an example. XSS is so prevalent it warranted the only ‘VERY WIDESPREAD' prevalence value of 0. All other risks ranged from widespread to uncommon (value 1 to 3).

