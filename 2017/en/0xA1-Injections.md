# A1 Injections

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Almost any source of data can be an injection vector, including users, parameters, external and internal web services, and all types of users. | Injection flaws occur when an attacker can send hostile data to an interpreter. Injection flaws are very prevalent, particularly in legacy code. They are often found in SQL, LDAP, XPath, or NoSQL queries; OS commands; XML parsers, SMTP Headers, expression languages, etc. Injection flaws are easy to discover when examining code, but frequently hard to discover via testing. Scanners and fuzzers can help attackers find injection flaws. | Injection can result in data loss or corruption, lack of accountability, or denial of access. Injection can sometimes lead to complete host takeover. The business impact depends on the protection needs of your application and data. |

## Am I vulnerable to attack?

An application is vulnerable to attack where:

* User suppled data is not validated, filtered or sanitized by the application
* Hostile data is used directly with dynamic queries or non-parameterized calls for the interpreter without context-aware escaping
* Hostile data is used within ORM search parameters such that the search evaluates out to include sensitive or all records
* Hostile data is directly used or concealed, such that the SQL or command contains both structure and hostile data either in dynamic queries or in stored procedures. 

The most common injections are SQL injection, OS command injection, ORM injection, LDAP injection, Expression Language (EL) or OGNL injection, and many more. The concept is identical between all interpreters, including HTML / JavaScript injection, also known as XSS. 

Large organizations and high performing organizations should include SAST and DAST tooling into the CI/CD pipeline, to alert if existing or newly checked in code has injection prior to production deployment. Manual and automated source code is the best method of detecting if you are vulnerable to injections, closely followed by thorough DAST scans of all parameters, fields, headers, cookies, JSON, and XML data inputs. 

## How do I prevent 

Preventing injection requires keeping data separate from commands and queries.

1. The preferred option is to use a safe API which avoids the use of the interpreter entirely or provides a parameterized interface, or uses ORMs or similar. **NB:** Whilst parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data, or executes hostile data with EXECUTE IMMEDIATE or exec()

2. Positive or "white list" input validation, but this is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications

3. For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter. OWASP's Java Encoder and similar libraries provide such escaping routines. **NB**: SQL structure such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report writing software. 

4. Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.


## Example Scenarios

Scenario #1: An application uses untrusted data in the construction of the following vulnerable SQL call:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

Scenario #2: Similarly, an application's blind trust in frameworks may result in queries that are still vulnerable, (e.g., Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

In both cases, the attacker modifies the 'id' parameter value in her browser to send:  `' or '1'='1`. For example: 

`http://example.com/app/accountView?id=' or '1'='1`

This changes the meaning of both queries to return all the records from the accounts table.  More dangerous attacks could modify data or even invoke stored procedures.

## References

### OWASP

* [OWASP Proactive Controls - Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP Application Security Verification Standard - V5 Input Validation and Encoding](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005))
* [OWASP Testing Guide: Testing for Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013))
* [OWASP Testing Guide: Testing for ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Injection Cheat Sheet for Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Query Parameterization Cheat Sheet](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Command Injection Defense Cheat Sheet](https://www.owasp.org/index.php/Command_Injection_Defense_Cheat_Sheet)

### External

* [CWE-77 Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89 SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564 Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917 Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection)
