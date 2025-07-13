---
source:  "https://owasp.org/Top10/A03_2021-Injection/"
title:   "A03:2021 – Injection"
id:      "A03:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".3" -%}
#A03:2021 – Injection     ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}  {{ osib_anchor(osib=osib, id=id, name="Injection", lang=lang, source=source, parent=parent, merged_from=[extra.osib.document ~ ".2017.1", extra.osib.document ~ ".2017.7"] ) }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 7.25                 | 7.15                | 94.04%       | 47.90%       | 274,228           | 32,078     |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Injection slides down to the third position. 94% of the applications
were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3%, and 274k occurrences. Notable Common Weakness Enumerations (CWEs) included are
*CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, and *CWE-73:
External Control of File Name or Path*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

An application is vulnerable to attack when:

-   User-supplied data is not validated, filtered, or sanitized by the
    application.

-   Dynamic queries or non-parameterized calls without context-aware
    escaping are used directly in the interpreter.

-   Hostile data is used within object-relational mapping (ORM) search
    parameters to extract additional, sensitive records.

-   Hostile data is directly used or concatenated. The SQL or command
    contains the structure and malicious data in dynamic queries,
    commands, or stored procedures.

Some of the more common injections are SQL, NoSQL, OS command, Object
Relational Mapping (ORM), LDAP, and Expression Language (EL) or Object
Graph Navigation Library (OGNL) injection. The concept is identical
among all interpreters. Source code review is the best method of
detecting if applications are vulnerable to injections. Automated
testing of all parameters, headers, URL, cookies, JSON, SOAP, and XML
data inputs is strongly encouraged. Organizations can include
static (SAST), dynamic (DAST), and interactive (IAST) application security testing tools into the CI/CD
pipeline to identify introduced injection flaws before production
deployment.

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Preventing injection requires keeping data separate from commands and queries:

-   The preferred option is to use a safe API, which avoids using the
    interpreter entirely, provides a parameterized interface, or
    migrates to Object Relational Mapping Tools (ORMs).<br/>
    **Note:** Even when parameterized, stored procedures can still introduce
    SQL injection if PL/SQL or T-SQL concatenates queries and data or
    executes hostile data with EXECUTE IMMEDIATE or exec().

-   Use positive server-side input validation. This is
    not a complete defense as many applications require special
    characters, such as text areas or APIs for mobile applications.

-   For any residual dynamic queries, escape special characters using
    the specific escape syntax for that interpreter.<br/>
    **Note:** SQL structures such as table names, column names, and so on
    cannot be escaped, and thus user-supplied structure names are
    dangerous. This is a common issue in report-writing software.

-   Use LIMIT and other SQL controls within queries to prevent mass
    disclosure of records in case of SQL injection.

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** An application uses untrusted data in the construction
of the following vulnerable SQL call:
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Scenario #2:** Similarly, an application’s blind trust in frameworks
may result in queries that are still vulnerable, (e.g., Hibernate Query
Language (HQL)):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

In both cases, the attacker modifies the ‘id’ parameter value in their
browser to send: ' UNION SLEEP(10);--. For example:
```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

This changes the meaning of both queries to return all the records from
the accounts table. More dangerous attacks could modify or delete data
or even invoke stored procedures.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.opc.3." ~ "3", osib=osib) }} <!-- [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.5", osib=osib) }} <!--- [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard) --->
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.7.5", osib=osib) }}, <!-- [OWASP Testing Guide: SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) --> {{ osib_link(link="osib.owasp.wstg.4-2.4.7.12", doc="", osib=osib) }}, <!-- [Command Injection ](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection) -->
 {{ osib_link(link="osib.owasp.wstg.4-2.4.7.5.7", doc="", osib=osib) }} <!-- [ORM Injection ](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Injection Prevention", osib=osib) }} <!-- [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "SQL Injection Prevention", osib=osib) }} <!-- [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Injection Prevention in Java", osib=osib) }} <!-- [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Query Parameterization", osib=osib) }} <!-- [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.oat.0.14", osib=osib) }} <!--- [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/) --->
-   {{ osib_link(link="osib.portswigger.kb.issues.serversidetemplateinjection", doc="osib.portswigger.kb.issues", osib=osib) }} <!--- [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection) --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.20", doc="", osib=osib) }} <!-- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.74", doc="", osib=osib) }} <!-- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.75", doc="", osib=osib) }} <!-- [CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.77", doc="", osib=osib) }} <!-- [CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.78", doc="", osib=osib) }} <!-- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.79", doc="", osib=osib) }} <!-- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.80", doc="", osib=osib) }} <!-- [CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.83", doc="", osib=osib) }} <!-- [CWE-83: Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.87", doc="", osib=osib) }} <!-- [CWE-87: Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.88", doc="", osib=osib) }} <!-- [CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.89", doc="", osib=osib) }} <!-- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.90", doc="", osib=osib) }} <!-- [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.91", doc="", osib=osib) }} <!-- [CWE-91: XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.93", doc="", osib=osib) }} <!-- [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.94", doc="", osib=osib) }} <!-- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.95", doc="", osib=osib) }} <!-- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.96", doc="", osib=osib) }} <!-- [CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.97", doc="", osib=osib) }} <!-- [CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.98", doc="", osib=osib) }} <!-- [CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.99", doc="", osib=osib) }} <!-- [CWE-99: Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.100", doc="", osib=osib) }} <!-- [CWE-100: Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.113", doc="", osib=osib) }} <!-- [CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.116", doc="", osib=osib) }} <!-- [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.138", doc="", osib=osib) }} <!-- [CWE-138: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.184", doc="", osib=osib) }} <!-- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.470", doc="", osib=osib) }} <!-- [CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.471", doc="", osib=osib) }} <!-- [CWE-471: Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.564", doc="", osib=osib) }} <!-- [CWE-564: SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.610", doc="", osib=osib) }} <!-- [CWE-610: Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.643", doc="", osib=osib) }} <!-- [CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.644", doc="", osib=osib) }} <!-- [CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.652", doc="", osib=osib) }} <!-- [CWE-652: Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.917", doc="", osib=osib) }} <!-- [CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html) -->
