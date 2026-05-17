# A05:2025 注入 ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## 背景

注入排名从第 3 位下降两位到第 5 位，相对于 A04:2025-加密机制失效和 A06:2025-不安全设计的位置保持不变。注入是测试最充分的类别之一，100% 的应用都被测试过某种形式的注入。它是所有类别中 CVE 数量最多的类别，本类别包含 37 个 CWE。注入包括跨站脚本（高频率/低影响，超过 3 万个 CVE）和 SQL 注入（低频率/高影响，超过 1.4 万个 CVE）。CWE-79“Web 页面生成期间输入中和不当（跨站脚本）”的大量已报告 CVE 拉低了该类别的平均加权影响。

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
   <td>平均加权可利用性
   </td>
   <td>平均加权影响
   </td>
   <td>发生总数
   </td>
   <td>CVE 总数
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

注入漏洞是应用缺陷，使不可信用户输入能够被发送给解释器（例如浏览器、数据库、命令行），并导致解释器将输入的一部分作为命令执行。

当出现以下情况时，应用容易受到攻击：

* 用户提供的数据没有被应用验证、过滤或清理。
* 动态查询或非参数化调用在没有上下文感知转义的情况下直接用于解释器。
* 未清理的数据被用于对象关系映射（ORM）搜索参数，从而提取额外的敏感记录。
* 可能有害的数据被直接使用或拼接。SQL 或命令在动态查询、命令或存储过程中同时包含结构和恶意数据。

较常见的注入包括 SQL、NoSQL、OS 命令、对象关系映射（ORM）、LDAP，以及表达式语言（EL）或对象图导航库（OGNL）注入。所有解释器中的概念都是一样的。最佳检测方式是结合源代码审查与自动化测试（包括模糊测试），覆盖所有参数、头、URL、cookie、JSON、SOAP 和 XML 数据输入。将静态（SAST）、动态（DAST）和交互式（IAST）应用安全测试工具加入 CI/CD 流水线，也有助于在生产部署前识别注入缺陷。

一类相关的注入漏洞在 LLM 中已经变得常见。它们在 [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) 中单独讨论，尤其是 [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)。

## 如何预防

预防注入的最佳方法是让数据与命令和查询保持分离：

* 首选方式是使用安全 API，完全避免使用解释器，或提供参数化接口，或迁移到对象关系映射工具（ORM）。
**注意：** 即使已参数化，如果 PL/SQL 或 T-SQL 拼接查询和数据，或用 EXECUTE IMMEDIATE 或 exec() 执行有害数据，存储过程仍可能引入 SQL 注入。

当无法将数据与命令分离时，可以使用以下技术降低威胁。

* 使用服务端正向输入验证。这不是完整防御，因为许多应用需要特殊字符，例如文本区域或移动应用 API。
* 对任何残留的动态查询，使用该解释器专用的转义语法转义特殊字符。
**注意：** 表名、列名等 SQL 结构无法被转义，因此用户提供的结构名称是危险的。这在报表编写软件中很常见。

**警告：** 这些技术涉及复杂字符串的解析和转义，容易出错，并且对底层系统的细微变化不够稳健。

## 攻击场景示例

**场景 #1：** 应用在构造以下易受攻击的 SQL 调用时使用了不可信数据：

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

攻击者在浏览器中把 `id` 参数值修改为：`' OR '1'='1`。例如：

```
http://example.com/app/accountView?id=' OR '1'='1
```

这会改变查询含义，返回 accounts 表中的所有记录。更危险的攻击还可能修改或删除数据，甚至调用存储过程。

**场景 #2：** 应用盲目信任框架，仍可能生成易受攻击的查询。例如 Hibernate Query Language（HQL）：

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

攻击者提供：`' OR custID IS NOT NULL OR custID='`。这会绕过过滤器并返回所有账户。虽然 HQL 的危险函数少于原始 SQL，但当用户输入被拼接进查询时，仍会允许未经授权的数据访问。

**场景 #3：** 应用把用户输入直接传给 OS 命令：

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

攻击者提供 `example.com; cat /etc/passwd`，从而在服务器上执行任意命令。

## 参考资料

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications - OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing)

## 映射的 CWE 列表

* [CWE-20 输入验证不当](https://cwe.mitre.org/data/definitions/20.html)
* [CWE-74 下游组件所用输出中特殊元素中和不当（注入）](https://cwe.mitre.org/data/definitions/74.html)
* [CWE-76 等价特殊元素中和不当](https://cwe.mitre.org/data/definitions/76.html)
* [CWE-77 命令中特殊元素中和不当（命令注入）](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-78 操作系统命令中特殊元素中和不当（操作系统命令注入）](https://cwe.mitre.org/data/definitions/78.html)
* [CWE-79 网页生成期间输入中和不当（跨站脚本）](https://cwe.mitre.org/data/definitions/79.html)
* [CWE-80 网页中脚本相关标记标签中和不当（基础跨站脚本）](https://cwe.mitre.org/data/definitions/80.html)
* [CWE-83 网页属性中的脚本中和不当](https://cwe.mitre.org/data/definitions/83.html)
* [CWE-86 网页标识符中的无效字符中和不当](https://cwe.mitre.org/data/definitions/86.html)
* [CWE-88 命令中参数分隔符中和不当（参数注入）](https://cwe.mitre.org/data/definitions/88.html)
* [CWE-89 SQL 命令中特殊元素中和不当（SQL 注入）](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-90 LDAP 查询中特殊元素中和不当（LDAP 注入）](https://cwe.mitre.org/data/definitions/90.html)
* [CWE-91 XML 注入（又称盲 XPath 注入）](https://cwe.mitre.org/data/definitions/91.html)
* [CWE-93 CRLF 序列中和不当（CRLF 注入）](https://cwe.mitre.org/data/definitions/93.html)
* [CWE-94 代码生成控制不当（代码注入）](https://cwe.mitre.org/data/definitions/94.html)
* [CWE-95 动态求值代码中指令中和不当（动态求值注入）](https://cwe.mitre.org/data/definitions/95.html)
* [CWE-96 静态保存代码中指令中和不当（静态代码注入）](https://cwe.mitre.org/data/definitions/96.html)
* [CWE-97 网页中服务端包含（SSI）中和不当](https://cwe.mitre.org/data/definitions/97.html)
* [CWE-98 PHP 程序中 `include`/`require` 语句文件名控制不当（PHP 远程文件包含）](https://cwe.mitre.org/data/definitions/98.html)
* [CWE-99 资源标识符控制不当（资源注入）](https://cwe.mitre.org/data/definitions/99.html)
* [CWE-103 Struts：`validate()` 方法定义不完整](https://cwe.mitre.org/data/definitions/103.html)
* [CWE-104 Struts：表单 Bean 未扩展验证类](https://cwe.mitre.org/data/definitions/104.html)
* [CWE-112 缺少 XML 验证](https://cwe.mitre.org/data/definitions/112.html)
* [CWE-113 HTTP 头中 CRLF 序列中和不当（HTTP 响应拆分）](https://cwe.mitre.org/data/definitions/113.html)
* [CWE-114 进程控制](https://cwe.mitre.org/data/definitions/114.html)
* [CWE-115 输出解释错误](https://cwe.mitre.org/data/definitions/115.html)
* [CWE-116 输出编码或转义不当](https://cwe.mitre.org/data/definitions/116.html)
* [CWE-129 数组索引验证不当](https://cwe.mitre.org/data/definitions/129.html)
* [CWE-159 特殊元素无效使用处理不当](https://cwe.mitre.org/data/definitions/159.html)
* [CWE-470 使用外部可控输入选择类或代码（不安全反射）](https://cwe.mitre.org/data/definitions/470.html)
* [CWE-493 关键 `public` 变量缺少 `final` 修饰符](https://cwe.mitre.org/data/definitions/493.html)
* [CWE-500 `public static` 字段未标记为 `final`](https://cwe.mitre.org/data/definitions/500.html)
* [CWE-564 SQL 注入：Hibernate](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-610 对另一范围中资源的外部可控引用](https://cwe.mitre.org/data/definitions/610.html)
* [CWE-643 XPath 表达式中数据中和不当（XPath 注入）](https://cwe.mitre.org/data/definitions/643.html)
* [CWE-644 脚本语法的 HTTP 头中和不当](https://cwe.mitre.org/data/definitions/644.html)
* [CWE-917 表达式语言语句中特殊元素中和不当（表达式语言注入）](https://cwe.mitre.org/data/definitions/917.html)
