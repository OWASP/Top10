# A03:2021 – 注入式攻击

## 对照因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权弱点 | 平均加权影点 | 出现次数 | 所有有关 CVEs 数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :----------------: |
|        33        |   19.09%   |   3.37%    |    94.04%    |    47.90%    |     7.25     |     7.15     | 274,228  |       32,078       |

## 概述

植入式攻击下滑到了第三名。 94% 被测试的应用程式都有验测到某种类型的注入式攻击问题。值得注意的 CWEs 包括了 CWE-79：跨网站攻击、CWE-89：SQL 注入式攻击以及 CWE-73：在外部控制档案名称或路径

## 描述

应用程式在以下情况容易遭受攻击：

- 应用程式未验证、过滤或清理使用者提供的资料。

- 在直译器中未使用上下文感知转义的动态查询或无参数呼叫。

- 在物件关系对映 (ORM) 的搜寻参数中，使用恶意的资料来提取额外的敏感纪录。

- 在动态查询、命令或储存的程序，SQL、指令或储存的程序中，直接使用或连结了恶意资料。

一些常见的注入式攻击是 SQL、NoSQL、OS 指令、物件关系对映 (ORM)、LDAP 以及表达式语言 (EL) 或对象导航图语言 (OGNL) 注入。这个概念在所有的直译器都是相同的。假若应用程式存在注入式攻击的弱点，源码检测是最好的方式。强烈建议对所有输入的参数、标头、URL、cookies、JSON、SOAP 以及 XML 的资料进行自动化测试。组织可以将静态源码测试 (SAST) 以及动态应用程式检测 (DAST) 工具，包含到持续整合与持续部署 (CI/CD)管道中，以达成在上线部署前能识别注入攻击的缺陷。

## 如何预防

- 需要将命令与查询资料分开，以防止注入式攻击。

- 首要的选项是使用安全的应用程式界面 (API)，完全避免使用直译器，以提供参数化的界面或整合到物件关系对映 (ORMs) 工具中。

- 注意：即使已经参数化了，在储存的程序中仍然可以引入 SQL 注入攻击，如果透过 PL/SQL 或 T-SQL 连接查询与资料，并使用 EXECUTE IMMEDIATE 或 exec() 执行恶意资料。

- 使用正面或白名单在服务器端验证输入的资料。这并不是一个完整的防御机制，因许多应用程序需要使用特殊的字符，例如：应用程式的文本区域或应用程式界面 (API)应用于行动装置上的应用程式。

- 对于任何剩余的动态查询，在转译中使用特殊符号进行查询将对查询语法带来不同的涵义。

- 注意：在 SQL 结构中，例如：资料表名称、栏位名称是无法被转译的，因此使用者提供资料结构的名称是危险的，这是一个在编写软体时常见的问题。

- 在查询中使用 LIMIT 以及其它的 SQL 控制器，可以防止当遭受 SQL 注入式攻击时被大量泄露纪录。

## 攻击情境范例

**情境 #1:** 应用程式使用了不被信任的资料在脆弱的 SQL 呼叫中：

String query = "SELECT \* FROM accounts WHERE custID='" +
request.getParameter("id") + "'";

**情境 #2:** 类似地，应用程式对框架的盲目信任，可能导致仍然在漏洞的查询，(例如：Hibernate 查询语言 (HQL))：

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" +
> request.getParameter("id") + "'");

在这两个情境中，攻击者在他们的浏览器修改了 "id" 参数值，送出 ‘ or ‘1’=’1，例如：

http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--

这两个查询的含义将产生改变，而回应所有帐户资料表中的纪录，更危险的攻击将可能修改或删除资料，以及影点资料的储存过程。

## 參考

- [OWASP Proactive Controls: Secure Database
  Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

- [OWASP ASVS: V5 Input Validation and
  Encoding](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: SQL
  Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command
  Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
  and [ORM
  Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

- [OWASP Cheat Sheet: Injection
  Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

- [OWASP Cheat Sheet: SQL Injection
  Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Injection Prevention in
  Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

- [OWASP Cheat Sheet: Query
  Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

- [OWASP Automated Threats to Web Applications –
  OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

- [PortSwigger: Server-side template
  injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## 对應的 CWE 列表

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
