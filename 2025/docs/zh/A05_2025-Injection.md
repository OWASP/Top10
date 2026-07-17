# A05:2025 注入 ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## 背景

注入在排名中从第3位下降两位至第5位，相对于 A04:2025-加密失败 和 A06:2025-不安全设计 保持了其位置。注入是测试最多的类别之一，100% 的应用程序都针对某种形式的注入进行了测试。它在所有类别中拥有最多的 CVE 数量，该类别包含 37 个 CWE。注入包括跨站脚本（高频率/低影响），拥有超过 3 万个 CVE，以及 SQL 注入（低频率/高影响），拥有超过 1.4 万个 CVE。CWE-79（网页生成过程中输入的不当中和，即“跨站脚本”）报告的大量 CVE 拉低了该类别的平均加权影响。

## 评分表

<table>
  <tr>
   <td>映射的 CWE 数量
   </td>
   <td>最大发生率
   </td>
   <td>平均发生率
   </td>
   <td>最大覆盖率
   </td>
   <td>平均覆盖率
   </td>
   <td>平均加权利用
   </td>
   <td>平均加权影响
   </td>
   <td>总发生次数
   </td>
   <td>总 CVE 数量
   </td>
  </tr>
  <tr>
   <td>37
   </td>
   <td>13.77%
   </td>
   <td>3.08%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.15
   </td>
   <td>4.32
   </td>
   <td>1,404,249
   </td>
   <td>62,445
   </td>
  </tr>
</table>

## 描述

注入漏洞是一种应用程序缺陷，允许将不受信任的用户输入发送到解释器（例如浏览器、数据库、命令行），并导致解释器将输入的部分内容作为命令执行。

当以下情况发生时，应用程序容易受到攻击：

* 用户提供的数据未经过应用程序的验证、过滤或清理。
* 动态查询或非参数化调用（未使用上下文感知的转义）直接用于解释器。
* 在对象关系映射（ORM）搜索参数中使用未清理的数据，以提取额外的敏感记录。
* 潜在恶意数据被直接使用或拼接。SQL 或命令在动态查询、命令或存储过程中包含结构和恶意数据。

一些更常见的注入类型包括 SQL、NoSQL、OS 命令、对象关系映射（ORM）、LDAP 以及表达式语言（EL）或对象图导航库（OGNL）注入。所有解释器的概念都是相同的。检测的最佳方法是将源代码审查与对所有参数、标头、URL、Cookie、JSON、SOAP 和 XML 数据输入的自动化测试（包括模糊测试）相结合。在 CI/CD 流水线中加入静态（SAST）、动态（DAST）和交互式（IAST）应用程序安全测试工具，也有助于在生产部署前识别注入缺陷。

一类相关的注入漏洞在大型语言模型中变得常见。这些漏洞在 [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) 中单独讨论，特别是 [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)。

## 如何预防

预防注入的最佳方法是将数据与命令和查询分开：

* 首选方案是使用安全的 API，这完全避免使用解释器，提供参数化接口，或迁移到对象关系映射工具（ORM）。
**注意：** 即使参数化了，如果 PL/SQL 或 T-SQL 拼接查询和数据，或使用 EXECUTE IMMEDIATE 或 exec() 执行恶意数据，存储过程仍然可能引入 SQL 注入。

当无法将数据与命令分开时，可以使用以下技术来降低威胁：

* 使用正向的服务器端输入验证。这不是一个完整的防御措施，因为许多应用程序需要特殊字符，例如文本区域或移动应用程序的 API。
* 对于任何残留的动态查询，使用该解释器的特定转义语法来转义特殊字符。
**注意：** SQL 结构（如表名、列名等）无法转义，因此用户提供的结构名称是危险的。这在报表编写软件中是一个常见问题。

**警告** 这些技术涉及解析和转义复杂字符串，容易出错，并且在底层系统发生微小变化时不够健壮。

## 示例攻击场景

**场景 #1：** 应用程序在构建以下易受攻击的 SQL 调用时使用了不受信任的数据：

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

攻击者修改浏览器中的 'id' 参数值，发送：`' OR '1'='1`。例如：

```
http://example.com/app/accountView?id=' OR '1'='1
```

这会改变查询的含义，返回 accounts 表中的所有记录。更危险的攻击可能会修改或删除数据，甚至调用存储过程。

**场景 #2：** 应用程序对框架的盲目信任可能导致查询仍然易受攻击。例如，Hibernate 查询语言（HQL）：

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

攻击者提供：`' OR custID IS NOT NULL OR custID='`。这绕过了过滤器并返回所有账户。虽然 HQL 的危险函数比原始 SQL 少，但当用户输入被拼接到查询中时，它仍然允许未经授权的数据访问。

**场景 #3：** 应用程序将用户输入直接传递给 OS 命令：

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

攻击者提供 `example.com; cat /etc/passwd` 以在服务器上执行任意命令。

## 参考文献

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection) 和 [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing)

## 映射的 CWE 列表

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

* [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)

* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

* [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

* [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)

* [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

* [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

* [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

* [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

* [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

* [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

* [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

* [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

* [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)

* [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)

* [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)

* [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

* [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)

* [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)

* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

* [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)

* [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)

* [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

* [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)

* [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)

* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

* [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

* [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)