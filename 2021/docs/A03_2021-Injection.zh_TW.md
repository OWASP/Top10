# A03:2021 – 注入式攻擊

## 對照因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權弱點 | 平均加權影響 | 出現次數 | 所有有關 CVEs 數量|
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 94.04%       | 47.90%       | 7.25                 | 7.15                | 274,228           | 32,078     |

## 概述

Injection slides down to the third position. 94% of the applications
were tested for some form of injection. Notable CWEs included are
*CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, and *CWE-73:
External Control of File Name or Path*.

## 描述 

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
data inputs is strongly encouraged. Organizations can include the static
source (SAST) and dynamic application test (DAST) tools into the CI/CD
pipeline to identify introduced injection flaws before production
deployment.

## 如何預防

-   Preventing injection requires keeping data separate from commands
    and queries.

-   The preferred option is to use a safe API, which avoids using the
    interpreter entirely, provides a parameterized interface, or
    migrates to Object Relational Mapping Tools (ORMs).

-   Note: Even when parameterized, stored procedures can still introduce
    SQL injection if PL/SQL or T-SQL concatenates queries and data or
    executes hostile data with EXECUTE IMMEDIATE or exec().

-   Use positive or "whitelist" server-side input validation. This is
    not a complete defense as many applications require special
    characters, such as text areas or APIs for mobile applications.

-   For any residual dynamic queries, escape special characters using
    the specific escape syntax for that interpreter.

-   Note: SQL structures such as table names, column names, and so on
    cannot be escaped, and thus user-supplied structure names are
    dangerous. This is a common issue in report-writing software.

-   Use LIMIT and other SQL controls within queries to prevent mass
    disclosure of records in case of SQL injection.

## 攻擊情境範例

**情境 #1:** An application uses untrusted data in the construction
of the following vulnerable SQL call:

String query = "SELECT \* FROM accounts WHERE custID='" +
request.getParameter("id") + "'";

**情境 #2:** Similarly, an application’s blind trust in frameworks
may result in queries that are still vulnerable, (e.g., Hibernate Query
Language (HQL)):

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" +
> request.getParameter("id") + "'");

In both cases, the attacker modifies the ‘id’ parameter value in their
browser to send: ‘ or ‘1’=’1. For example:

http://example.com/app/accountView?id=' or '1'='1

This changes the meaning of both queries to return all the records from
the accounts table. More dangerous attacks could modify or delete data
or even invoke stored procedures.

## 參考

-   [OWASP Proactive Controls: Secure Database
    Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and
    Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL
    Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in
    Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query
    Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications –
    OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template
    injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## 對應的 CWE 列表

CWE-20 Improper Input Validation

CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')

CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)

CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')

CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')

CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')

CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)

CWE-83 Improper Neutralization of Script in Attributes in a Web Page

CWE-87 Improper Neutralization of Alternate XSS Syntax

CWE-88 Improper Neutralization of Argument Delimiters in a Command
('Argument Injection')

CWE-89 Improper Neutralization of Special Elements used in an SQL
Command ('SQL Injection')

CWE-90 Improper Neutralization of Special Elements used in an LDAP Query
('LDAP Injection')

CWE-91 XML Injection (aka Blind XPath Injection)

CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')

CWE-94 Improper Control of Generation of Code ('Code Injection')

CWE-95 Improper Neutralization of Directives in Dynamically Evaluated
Code ('Eval Injection')

CWE-96 Improper Neutralization of Directives in Statically Saved Code
('Static Code Injection')

CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a
Web Page

CWE-98 Improper Control of Filename for Include/Require Statement in PHP
Program ('PHP Remote File Inclusion')

CWE-99 Improper Control of Resource Identifiers ('Resource Injection')

CWE-100 Deprecated: Was catch-all for input validation issues

CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP
Response Splitting')

CWE-116 Improper Encoding or Escaping of Output

CWE-138 Improper Neutralization of Special Elements

CWE-184 Incomplete List of Disallowed Inputs

CWE-470 Use of Externally-Controlled Input to Select Classes or Code
('Unsafe Reflection')

CWE-471 Modification of Assumed-Immutable Data (MAID)

CWE-564 SQL Injection: Hibernate

CWE-610 Externally Controlled Reference to a Resource in Another Sphere

CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath
Injection')

CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax

CWE-652 Improper Neutralization of Data within XQuery Expressions
('XQuery Injection')

CWE-917 Improper Neutralization of Special Elements used in an
Expression Language Statement ('Expression Language Injection')
