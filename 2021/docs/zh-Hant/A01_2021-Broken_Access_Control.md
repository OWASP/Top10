# A01:2021 – 权限控制失效

## 对照因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 所有相关 CVEs 数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :----------------: |
|        34        |   55.97%   |   3.81%    |    94.55%    |    47.72%    |     6.92     |     5.93     | 318,487  |       19,013       |

## 概述

从第五名晋升至第一名，94% 被测试的应用程式，都有被验测到某种类別权限控制失效的问题。著名的 CWE 包括 _CWE-200：Exposure of Sensitive Information to an Unauthorized Actor_，_CWE-201：Exposure of Sensitive Information Through Sent Data_ 和 \*CWE-352 Cross-Site Request Forgery。

## 描述

存取控制強化政策，使用户不能采取在预期权限之外的行动。控制失效通常会导致未经授权的资讯泄漏、修改或损坏所有资料，或执行超出用户权限的业务功能。常见的存取控制弱点包括：

- 通过修改 URL、內部应用程式状态或 HTML 页面，或仅使用自定义 API 攻击工具來绕过存取控制检查。

- 容许主键被更改为其他用户的记录，允许查看或编辑其他人的账户。

- 特权提升。未登入即成为用户，或以用户身份登入即成为管理员。

- 元数据操作，例如重放或篡改 JSON 网站令牌(JWT)之存取控制令牌，或被操纵以提升特权或滥用 JWT 失效的 cookie 或隐藏域内容。

- CORS 错误配置允许未经授权的 API 存取。

- 以未经身份验证的用户身份強制浏览已验证的页面或以标准用户身份存取特权页面。存取缺少存取控制的 API 以进行 POST、PUT 和 DELETE 操作。

## 如何预防

存取控制仅在受信任的服务器端代码或无服务器的 API 有效，攻击者无法修改这里的存取控制检查或元数据。

- 除公开的资源外，默认为拒绝存取。

- 一次性地建置存取控制机制，之后在整个应用程式中重复使用它们，包括最大限度地減少使用 CORS。

- 模型的存取控制措施应该強化记录所有权，而不是让用户可以创建、读取、更新或刪除任何记录。

- 独特的应用程式业务限制要求应由领域模型予以強化。

- 停用 Web 服务器目录列表，并确保档案元数据（例如，.git)和备份档案不在 web 根目录中。

- 记录存取控制失效，并在适当的时间警示管理员（例如，重覆性失效）。

- 对 API 和控制器存取进行流量限制，以最小化自动攻击工具所帶來的损害。

- JWT 令牌于登出后，在服务器端应使其失效。

开发人员和 QA 品保人员应纳入与功能有关之存取控制的单元和整合测试。

## 攻击情境范例

**情境 #1：** 应用程式在存取账户资讯的 SQL 呼叫中使用未经验证的资料：

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

攻击者只需修改浏览器的“acct”參数即可发送他们想要的任何账号。如果沒有正确验证，攻击者可以存取任何用户的账户。

https://example.com/app/accountInfo?acct=notmyacct

**情境#2：** 攻击者仅強迫浏览某些目标网址。存取管理页面需要管理员权限。

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

如果未经身份验证的用户可以存取任一页面，那就是一个缺陷。 如果一个非管理员可以存取管理页面，这也是一个缺陷。

## 參考

- [OWASP Proactive Controls: Enforce Access
  Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

- [OWASP Application Security Verification Standard: V4 Access
  Control](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: Authorization
  Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

- [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

- [PortSwigger: Exploiting CORS
  misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## 对应的 CWE 列表

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
