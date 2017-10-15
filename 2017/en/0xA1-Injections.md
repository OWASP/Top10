# A1 Injections

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| Application Specific |  EASY | COMMON | AVERAGE | Impact Severe | Application Business Specific | 
| Consider anyone who can send untrusted data to the system, including external users, business partners, other systems, internal users, and administrators. | Attackers send simple text-based attacks that exploit the syntax of the targeted interpreter. Almost any source of data can be an injection vector, including internal sources. | Injection flaws occur when an application sends untrusted data to an interpreter. Injection flaws are very prevalent, particularly in legacy code.  They are often found in SQL, LDAP, XPath, or NoSQL queries; OS commands; XML parsers, SMTP Headers, expression languages, etc. Injection flaws are easy to discover when examining code, but frequently hard to discover via testing. Scanners and fuzzers can help attackers find injection flaws. | TBA. | Injection can result in data loss or corruption, lack of accountability, or denial of access. Injection can sometimes lead to complete host takeover. | Consider the business value of the affected data and the platform running the interpreter. All data could be stolen, modified, or deleted.  Could your reputation be harmed? |

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | EASY (3) | Automated tools can exploit all three forms of XSS, and there are freely available exploitation frameworks. |
| Prevalence | WIDESPREAD (3) | XSS is the second most prevalent issue in the OWASP Top 10, and is found in around two thirds of all applications. |
| Detectability | EASY (3) | XSS can be discovered by SAST and DAST tools, as well as anyone with a browser. |
| Impact | MODERATE (2) | The impact of XSS is moderate for reflected and DOM XSS, and severe for stored XSS, with remote code execution on the victim's browser, such as stealing credentials, sessions, or delivering malware to the victim. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 6.0 | MEDIUM |


## Am I vulnerable to attack?

The best way to find out if an application is vulnerable to injection is to verify that all use of interpreters clearly separates untrusted data from the command or query. In many cases, it is recommended to avoid the interpreter, or disable it (e.g., XXE), if possible. For SQL calls, use bind variables in all prepared statements and stored procedures, or avoid dynamic queries.

Checking the code is a fast and accurate way to see if the application uses interpreters safely. Code analysis tools can help a security analyst find use of interpreters and trace data flow through the application. Penetration testers can validate these issues by crafting exploits that confirm the vulnerability.

Automated dynamic scanning which exercises the application may provide insight into whether some exploitable injection flaws exist. Scanners cannot always reach interpreters and have difficulty detecting whether an attack was successful. Poor error handling makes injection flaws easier to discover.

## How do I prevent 

Preventing injection requires keeping untrusted data separate from commands and queries.

1. The preferred option is to use a safe API which avoids the use of the interpreter entirely or provides a parameterized interface.  Be careful with APIs, such as stored procedures, that are parameterized, but can still introduce injection under the hood.

2. If (1) is not available, you should escape special characters using the specific escape syntax for that interpreter. OWASP's Java Encoder and similar libraries provide such escaping routines.

3. Positive or "white list" input validation is also recommended, but is not a complete defense as many situations require special characters be allowed. If special characters are required, only approaches (1) and (2) above will make their use safe. 

## Example Scenarios

Scenario #1: An application uses untrusted data in the construction of the following vulnerable SQL call:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

Scenario #2: Similarly, an application's blind trust in frameworks may result in queries that are still vulnerable, (e.g., Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

In both cases, the attacker modifies the ‘id' parameter value in her browser to send:  `' or '1'='1`. For example: 

`http://example.com/app/accountView?id=' or '1'='1`

This changes the meaning of both queries to return all the records from the accounts table.  More dangerous attacks could modify data or even invoke stored procedures.

## References

### OWASP
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide: Chapter on SQL Injection Testing]()
* [OWASP SQL Injection Prevention Cheat Sheet]()
* [OWASP Query Parameterization Cheat Sheet]()
* [OWASP Command Injection Article]()
* [OWASP XXE Prevention Cheat Sheet]()

### External
* [CWE Entry 77 on Command Injection]()
* [CWE Entry 89 on SQL Injection]()
* [CWE Entry 564 on Hibernate Injection]()
* [CWE Entry 611 on Improper Restriction of XXE]()
* [CWE Entry 917 on Expression Language Injection]()
* Do we have a non-vendor reference for this? [PortSwigger: Server-side template injection](https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection)
