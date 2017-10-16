# +R About Risks

## About risks

During the creation of the OWASP Top 10 2017, we asked the community how they would like the issues to be presented. The overwhelming majority of respondents asked for risk-based ranking. It would be simpler for us to use prevalence only, or breach only ordering, because we have solid access data on that, but then we wouldn't be presenting risks.

ISO 31000 is the international standard for risk management. We aim to adhere to that standard, but we only include technical impact, and not business impact. Every ISO 31000 compliant organization adopting the OWASP Top 10 should add their business impact to our calculations. Why is this important? Consider the case where a CMS is used as a public website by one organization, and as a health records system by another. The data asset, risks and threats are very different, and yet the software is the same.

We present three likelihood factors:
* Exploitability - based upon our combined experience of if the issue is difficult to exploit requiring advanced skills uncommon in the industry, average, or easy (automated)
* Prevalence - comes unmodified from the 114,000 application data set
* Detectability - difficult or blind, average or easy (automated) detection

Impact is purely a technical impact, which we based upon our experience, history of breaches using this issue, and reputable sources such as the annual Verizon Data Breach Incident Report.

## Defining our terms

One of the long standing tensions within the information security industry is the misunderstanding or misuse of common terms, such as threats, threat agents, weaknesses, defects, flaws, vulnerabilities, and risks. As such, we are defining our terms to ensure that there is no confusion.

| Term | Description | 
| --- | --- |
| Data asset | A data asset is something tangible processed and stored by an application or API, such as an identity store, customer database, health records, tax returns, bank or mortgage accounts, and so on. |  
| Threat agent | Threat agents can be humans, with or or without motives, or even in some cases, scripts (such as botnets or worms). Outside of criminal prosecutions and state response, the identity of a threat actor is only important in terms of understanding the sorts of targets and actions the threat agent is likely to target to assist in forensics and incident response. |
| Weakness | A weakness is a software architectural or design flaw or technical defect that allows a threat agent to exploit a vulnerability within the code. The likelihood of this occurring is well understood within the application security industry. |
| Flaw | A flaw is a requirements, architecture, or design mistake that will take considerable effort to refactor or mitigate |
| Defect | A defect is a bug or a piece of code that fails to properly use an effective control |
| Control | A control is a piece of code, process or people that mitigates  
| Impact | The impact of a threat agent exploiting a vulnerability is highly dependant on the data asset being processed, stored or protected by the application or API. However, for these 10 vulnerability classes, we can estimate a baseline impact based upon public breach information, such as Dataloss DB, media coverage, and financial impact for publicly listed companies. 

Our methodology includes three likelihood factors for each weakness (prevalence, detectability, and ease of exploit) and one impact factor (technical impact). The prevalence of a weakness is a factor that you typically don't have to calculate. For prevalence data, we have been supplied prevalence statistics from a number of different organizations (as referenced in the Attribution section on page 4) and we have averaged their data together to come up with a Top 10 likelihood of existence list by prevalence. This data was then combined with the other two likelihood factors (detectability and ease of exploit) to calculate a likelihood rating for each weakness. The likelihood rating was then multiplied by our estimated average technical impact for each item to come up with an overall risk ranking for each item in the Top 10.

Note that this approach does not take the likelihood of the threat agent into account. Nor does it account for any of the various technical details associated with your particular application. Any of these factors could significantly affect the overall likelihood of an attacker finding and exploiting a particular vulnerability. This rating also does not take into account the actual impact on your business. Your organization will have to decide how much security risk from applications and APIs the organization is willing to accept given your culture, industry, and regulatory environment. The purpose of the OWASP Top 10 is not to do this risk analysis for you.

The following illustrates our calculation of the risk for A5:2017 Security Misconfiguration, as an example. Misconfiguration is so prevalent it warranted the only 'PREVALENT' prevalence value of 4. All other risks ranged from uncommon to common (values 1 to 3).
