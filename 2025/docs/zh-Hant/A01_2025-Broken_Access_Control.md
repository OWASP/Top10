#  A01:2025 失效的访问控制 ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## 背景

失效的访问控制保持 Top Ten 第 1 位。100% 的受测应用都被发现存在某种形式的访问控制失效。该类别中值得关注的 CWE 包括 *CWE-200：向未授权主体暴露敏感信息*、*CWE-201：通过已发送数据暴露敏感信息*、*CWE-918：服务端请求伪造（SSRF）* 和 *CWE-352：跨站请求伪造（CSRF）*。在贡献数据中，本类别的发生次数最高，相关 CVE 数量位居第二。

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

访问控制用于执行策略，确保用户不能执行超出其预期权限的操作。访问控制失效通常会导致未经授权的信息披露，所有数据被修改或销毁，或者执行超出用户限制的业务功能。常见访问控制漏洞包括：

* 违反最小权限原则，也就是通常所说的默认拒绝。访问权限应只授予特定能力、角色或用户，却对任何人可用。
* 通过修改 URL（参数篡改或强制浏览）、内部应用状态或 HTML 页面，或使用修改 API 请求的攻击工具绕过访问控制检查。
* 通过提供某账户的唯一标识符，允许查看或编辑他人账户（不安全的直接对象引用）。
* 可访问的 API 对 POST、PUT 和 DELETE 缺少访问控制。
* 权限提升。未登录时以用户身份操作，或获得超出已登录用户预期的权限（例如管理员访问权限）。
* 元数据操纵，例如重放或篡改 JSON Web Token（JWT）访问控制令牌，通过 cookie 或隐藏字段提升权限，或滥用 JWT 失效机制。
* CORS 配置错误允许来自未经授权或不受信任来源的 API 访问。
* 作为未认证用户强制浏览（猜测 URL）已认证页面，或作为普通用户访问特权页面。

## 如何预防

访问控制只有在可信的服务端代码或 Serverless API 中实现时才有效，因为攻击者无法修改其中的访问控制检查或元数据。

* 除公共资源外，默认拒绝。
* 只实现一次访问控制机制，并在整个应用中复用，同时尽量减少跨源资源共享（CORS）的使用。
* 模型访问控制应强制执行记录所有权，而不是允许用户创建、读取、更新或删除任何记录。
* 由领域模型强制执行应用特有的业务限制要求。
* 禁用 Web 服务器目录列表，确保文件元数据（例如 .git）和备份文件不出现在 Web 根目录中。
* 记录访问控制失败，并在适当时告警管理员（例如重复失败）。
* 对 API 和控制器访问实施速率限制，以降低自动化攻击工具造成的危害。
* 有状态会话标识符应在用户登出后由服务器失效。无状态 JWT 令牌应设置较短生命周期，以缩短攻击者可利用的时间窗口。对于生命周期较长的 JWT，可考虑使用刷新令牌，并遵循 OAuth 标准撤销访问权限。
* 使用成熟的工具包或模式，提供简单、声明式的访问控制。

开发人员和 QA 人员应在单元测试和集成测试中包含功能性访问控制测试。

## 攻击场景示例

**场景 #1：** 应用在访问账户信息的 SQL 调用中使用了未经验证的数据：

```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```

攻击者只需修改浏览器中的 `acct` 参数，就可以发送任意账户编号。如果没有正确验证，攻击者就能访问任意用户账户。

```
https://example.com/app/accountInfo?acct=notmyacct
```

**场景 #2：** 攻击者直接强制浏览器访问目标 URL。访问管理页面需要管理员权限。

```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```

如果未认证用户可以访问任一页面，这就是缺陷。如果非管理员可以访问管理页面，也属于缺陷。

**场景 #3：** 应用把所有访问控制都放在前端。虽然浏览器中运行的 JavaScript 代码阻止攻击者访问 `https://example.com/app/admin_getappInfo`，但攻击者可以直接在命令行执行：

```
$ curl https://example.com/app/admin_getappInfo
```

## 参考资料

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## 映射的 CWE 列表

* [CWE-22 对受限目录路径名限制不当（路径遍历）](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-23 相对路径遍历](https://cwe.mitre.org/data/definitions/23.html)
* [CWE-36 绝对路径遍历](https://cwe.mitre.org/data/definitions/36.html)
* [CWE-59 文件访问前链接解析不当（跟随链接）](https://cwe.mitre.org/data/definitions/59.html)
* [CWE-61 跟随 UNIX 符号链接](https://cwe.mitre.org/data/definitions/61.html)
* [CWE-65 Windows 硬链接](https://cwe.mitre.org/data/definitions/65.html)
* [CWE-200 向未授权主体暴露敏感信息](https://cwe.mitre.org/data/definitions/200.html)
* [CWE-201 通过已发送数据暴露敏感信息](https://cwe.mitre.org/data/definitions/201.html)
* [CWE-219 在网站根目录下存储含敏感数据的文件](https://cwe.mitre.org/data/definitions/219.html)
* [CWE-276 默认权限错误](https://cwe.mitre.org/data/definitions/276.html)
* [CWE-281 权限保留不当](https://cwe.mitre.org/data/definitions/281.html)
* [CWE-282 所有权管理不当](https://cwe.mitre.org/data/definitions/282.html)
* [CWE-283 未验证所有权](https://cwe.mitre.org/data/definitions/283.html)
* [CWE-284 访问控制不当](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285 授权不当](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-352 跨站请求伪造（CSRF）](https://cwe.mitre.org/data/definitions/352.html)
* [CWE-359 向未授权主体暴露私人个人信息](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-377 不安全的临时文件](https://cwe.mitre.org/data/definitions/377.html)
* [CWE-379 在权限不安全的目录中创建临时文件](https://cwe.mitre.org/data/definitions/379.html)
* [CWE-402 将私有资源传输到新的范围（资源泄漏）](https://cwe.mitre.org/data/definitions/402.html)
* [CWE-424 备用路径保护不当](https://cwe.mitre.org/data/definitions/424.html)
* [CWE-425 直接请求（强制浏览）](https://cwe.mitre.org/data/definitions/425.html)
* [CWE-441 非预期代理或中介（混淆代理）](https://cwe.mitre.org/data/definitions/441.html)
* [CWE-497 向未授权控制范围暴露敏感系统信息](https://cwe.mitre.org/data/definitions/497.html)
* [CWE-538 将敏感信息写入外部可访问文件或目录](https://cwe.mitre.org/data/definitions/538.html)
* [CWE-540 源代码中包含敏感信息](https://cwe.mitre.org/data/definitions/540.html)
* [CWE-548 通过目录列表暴露信息](https://cwe.mitre.org/data/definitions/548.html)
* [CWE-552 文件或目录可被外部方访问](https://cwe.mitre.org/data/definitions/552.html)
* [CWE-566 通过用户可控 SQL 主键绕过授权](https://cwe.mitre.org/data/definitions/566.html)
* [CWE-601 网址重定向到不可信站点（开放重定向）](https://cwe.mitre.org/data/definitions/601.html)
* [CWE-615 源代码注释中包含敏感信息](https://cwe.mitre.org/data/definitions/615.html)
* [CWE-639 通过用户可控键绕过授权](https://cwe.mitre.org/data/definitions/639.html)
* [CWE-668 将资源暴露到错误范围](https://cwe.mitre.org/data/definitions/668.html)
* [CWE-732 关键资源权限分配错误](https://cwe.mitre.org/data/definitions/732.html)
* [CWE-749 暴露危险方法或函数](https://cwe.mitre.org/data/definitions/749.html)
* [CWE-862 缺少授权](https://cwe.mitre.org/data/definitions/862.html)
* [CWE-863 授权错误](https://cwe.mitre.org/data/definitions/863.html)
* [CWE-918 服务端请求伪造（SSRF）](https://cwe.mitre.org/data/definitions/918.html)
* [CWE-922 敏感信息存储不安全](https://cwe.mitre.org/data/definitions/922.html)
* [CWE-1275 敏感 Cookie 的 `SameSite` 属性设置不当](https://cwe.mitre.org/data/definitions/1275.html)
