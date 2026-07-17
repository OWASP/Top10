#  A01:2025 访问控制失效 ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}



## 背景

访问控制失效在十大安全风险中仍位居榜首，100% 的受测应用被发现存在某种形式的访问控制失效。值得注意的 CWE 包括 *CWE-200：将敏感信息暴露给未授权行为者*、*CWE-201：通过发送数据暴露敏感信息*、*CWE-918：服务器端请求伪造 (SSRF)* 以及 *CWE-352：跨站请求伪造 (CSRF)*。此类问题在贡献数据中出现次数最多，相关 CVE 数量也位居第二。


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
   <td>平均加权利用难度
   </td>
   <td>平均加权影响
   </td>
   <td>总出现次数
   </td>
   <td>总 CVE 数量
   </td>
  </tr>
  <tr>
   <td>40
   </td>
   <td>20.15%
   </td>
   <td>3.74%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.04
   </td>
   <td>3.84
   </td>
   <td>1,839,701
   </td>
   <td>32,654
   </td>
  </tr>
</table>



## 描述

访问控制用于强制执行策略，确保用户不能超出其预期权限范围行事。失效通常会导致未授权信息泄露、所有数据的修改或破坏，或执行超出用户权限的业务功能。常见的访问控制漏洞包括：



* 违反最小权限原则（通常称为默认拒绝），即访问权限本应仅授予特定功能、角色或用户，但实际上对所有人开放。
* 通过修改 URL（参数篡改或强制浏览）、内部应用状态或 HTML 页面，或使用修改 API 请求的攻击工具来绕过访问控制检查。
* 通过提供他人账户的唯一标识符（不安全的直接对象引用）来允许查看或编辑他人账户。
* 可访问的 API 缺少对 POST、PUT 和 DELETE 操作的访问控制。
* 权限提升。在未登录的情况下以用户身份操作，或获取超出登录用户预期权限的权限（例如管理员权限）。
* 元数据篡改，例如重放或篡改 JSON Web Token (JWT) 访问控制令牌、操纵 Cookie 或隐藏字段以提升权限，或滥用 JWT 失效机制。
* CORS 配置错误导致来自未授权或不可信来源的 API 访问。
* 未认证用户强制浏览（猜测 URL）到需认证的页面，或普通用户强制浏览到特权页面。


## 如何防范

访问控制仅在受信任的服务器端代码或无服务器 API 中实施时才有效，因为攻击者无法修改访问控制检查或元数据。



* 除公共资源外，默认拒绝访问。
* 一次性实施访问控制机制，并在整个应用中重复使用，包括尽量减少跨源资源共享 (CORS) 的使用。
* 模型访问控制应强制实施记录所有权，而不是允许用户创建、读取、更新或删除任何记录。
* 独特的应用业务限制要求应由领域模型强制执行。
* 禁用 Web 服务器目录列表，并确保文件元数据（例如 .git）和备份文件不存在于 Web 根目录中。
* 记录访问控制失败事件，并在适当时（例如重复失败）向管理员发出警报。
* 对 API 和控制器访问实施速率限制，以最大程度减少自动化攻击工具造成的危害。
* 有状态会话标识符应在注销后在服务器上失效。无状态 JWT 令牌应具有较短的有效期，以缩小攻击者的可利用窗口。对于长期有效的 JWT，考虑使用刷新令牌并遵循 OAuth 标准来撤销访问权限。
* 使用成熟的工具包或模式，提供简单、声明式的访问控制。

开发人员和 QA 人员应将功能访问控制纳入其单元测试和集成测试中。


## 示例攻击场景

**场景 #1：** 应用程序在访问账户信息的 SQL 调用中使用了未经验证的数据：


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```


攻击者可以简单地修改浏览器的 'acct' 参数，发送任意所需的账号。如果未正确验证，攻击者可以访问任何用户的账户。


```
https://example.com/app/accountInfo?acct=notmyacct
```


**场景 #2：** 攻击者强制浏览器访问目标 URL。访问管理页面需要管理员权限。


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


如果未认证用户可以访问任一页面，则存在缺陷。如果非管理员用户可以访问管理页面，这也是一个缺陷。

**场景 #3：** 应用程序将所有访问控制放在前端。虽然攻击者由于浏览器中运行的 JavaScript 代码无法直接访问 `https://example.com/app/admin_getappInfo`，但他们可以简单地在命令行中执行：


```
$ curl https://example.com/app/admin_getappInfo
```


## 参考文献

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## 映射的 CWE 列表

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)

* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)

* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)

* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)

* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)

* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)

* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)

* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)

* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)