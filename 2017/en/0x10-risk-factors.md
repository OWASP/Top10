# +F Details about Risk factors

## About risks

During the creation of the OWASP Top 10 2017, we asked the community how they would like the issues to be presented. The overwhelming majority of respondants asked for risk-based ranking. It would be simpler for us to use prevalance only, or breach only ordering, because we have solid access data on that, but then we wouldn't be presenting risks. 

ISO 31000 is the international standard for risk management. We aim to adhere to that standard, but we only include technical impact, and not business impact. Every organization adopting the OWASP Top 10 will need to add their business impact to our calculations. Why is this important? Consider the case where a CMS is used as a public website by one organization, and as a health records system by another. The data asset, risks and threats are very different, and yet the software is the same. 

We present three likelihood factors:
* Exploitability - based upon our combined experience of if the issue is difficult to exploit requiring advanced skills uncommon in the industry, average, or easy (automated)
* Prevalence - comes unmodified from the 114,000 application data set
* Detectability - difficult or blind, average or easy (automated) detection

Impact is purely a technical impact, which we based upon our experience, history of breaches using this issue, and sources such as the Verizon Data Breach Incident Report.

## Top 10 Risk Factor Summary

The following table presents a summary of the 2017 Top 10 Application Security Risks, and the risk factors we have assigned to each risk. These factors were determined based on the available statistics and the experience of the OWASP Top 10 team. 

| Risk | Exploitability | Prevalence | Detectability | Impact | Score |
| --- | --- | --- | --- | --- | --- | 
| A1:2017 Injection |  EASY | COMMON | EASY | SEVERE | 8.0 |
| A2:2017 Authentication |  EASY | COMMON | AVERAGE | SEVERE | 7.0 |
| A3:2017 Sensitive data exposure |  AVERAGE | WIDESPREAD | AVERAGE | SEVERE | 7.0 |
| A4:2017 XXE |  AVERAGE | COMMON | EASY | SEVERE | 7.0 |
| A5:2017 Misconfig |  EASY | PREVALENT | EASY | MODERATE | 6.7 |
| A6:2017 Access Control |  AVERAGE | COMMON |  AVERAGE | SEVERE | 6.0 |
| A7:2017 XSS |  EASY | WIDESPREAD | EASY | MODERATE | 6.0 |
| A8:2017 Deserialization |  DIFFICULT | COMMON | AVERAGE | SEVERE | 5.0 |
| A9:2017 Components |  AVERAGE | WIDESPREAD | AVERAGE | MODERATE | 4.7 |
| A10:2017 Logging and monitoring|  AVERAGE | WIDESPREAD | DIFFICULT | MODERATE | 4.0 |

A8 and A10 come from survey data, which is discussed in the TBA chapter. The two residual issues that did not have data to be included in their own right were deserialization (514/740) and insufficient logging and monitoring (440/740). The other survey items entered the OWASP Top 10 in their own right. 

To understand these risks for a particular application or organization, you must consider your own specific threat agents and business impacts. Even major software weaknesses may not present a serious risk if there are no threat agents in a position to perform the necessary attack or the business impact is negligible for the assets involved.

## Additional Risks To Consider

Every Top 10 requires us to make a judgement call as to what is included, and how far we can include other associated weaknesses into a single risk. This year is no different. If you want to look further, consider the following weaknesses for which we have significant data:

**High Privacy impacts**

* [Cryptographic Issues (CWEs-310/326/327/etc)](https://cwe.mitre.org/data/definitions/310.html)
* [Cleartext Transmission of Sensitive Information (CWE-319)](https://cwe.mitre.org/data/definitions/319.html)
* [Cleartext Storage of Sensitive Information (CWE-312)](https://cwe.mitre.org/data/definitions/312.html)

See the [OWASP Top 10 Privacy Risks](https://www.owasp.org/index.php/OWASP_Top_10_Privacy_Risks_Project) for more information. 

**High technical impacts**

We do not have strong evidence for these issues, but the impact can be high:

* [Server-Side Request Forgery (SSRF) (CWE-918)](https://cwe.mitre.org/data/definitions/918.html)
* [Unrestricted Upload of File with Dangerous Type (CWE-434)](https://cwe.mitre.org/data/definitions/434.html)

**Technical impacts**

* [Clickjacking (CWE-451)](https://cwe.mitre.org/data/definitions/451.html) or [CAPEC 103](https://capec.mitre.org/data/definitions/103.html)
* [Cross-Site Request Forgery (CSRF) (CWE-352)](https://cwe.mitre.org/data/definitions/352.html)
* [Session Fixation (CWE-384)](https://cwe.mitre.org/data/definitions/384.html)
* [Path Traversal (CWE-22)](https://cwe.mitre.org/data/definitions/22.html)
* [Insufficient Anti-automation (CWE-799)](https://cwe.mitre.org/data/definitions/799.html)
* [Denial of Service (DOS) (CWE-400)](https://cwe.mitre.org/data/definitions/400.html)
* [Mass Assignment (CWE-915)](https://cwe.mitre.org/data/definitions/915.html)

