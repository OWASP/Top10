# A02:2025 安全配置错误 ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## 背景

安全配置错误从上一版第 5 位上升。100% 的受测应用都被发现存在某种形式的配置错误，平均发生率为 3.00%，本风险类别中通用弱点枚举（CWE）的发生次数超过 71.9 万次。随着软件越来越多地转向高度可配置的形态，本类别排名上升并不意外。值得关注的 CWE 包括 *CWE-16：配置* 和 *CWE-611：XML 外部实体引用限制不当（XXE）*。

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
   <td>16
   </td>
   <td>27.70%
   </td>
   <td>3.00%
   </td>
   <td>100.00%
   </td>
   <td>52.35%
   </td>
   <td>7.96
   </td>
   <td>3.97
   </td>
   <td>719,084
   </td>
   <td>1,375
   </td>
  </tr>
</table>

## 描述

安全配置错误是指系统、应用或云服务从安全角度被错误设置，从而产生漏洞。

如果出现以下情况，应用可能存在风险：

* 应用栈任一部分缺少适当的安全加固，或云服务权限配置不当。
* 启用或安装了不必要的功能（例如不必要的端口、服务、页面、账户、测试框架或权限）。
* 默认账户及其密码仍处于启用状态，且未被修改。
* 缺少集中配置来拦截过多错误消息。错误处理向用户暴露堆栈跟踪或其他信息过于详细的错误消息。
* 对已升级系统，最新安全功能被禁用或没有安全配置。
* 过度优先考虑向后兼容，导致不安全配置。
* 应用服务器、应用框架（例如 Struts、Spring、ASP.NET）、库、数据库等的安全设置未设为安全值。
* 服务器没有发送安全头或安全指令，或者它们未设为安全值。

如果没有协调一致、可重复的应用安全配置加固流程，系统会面临更高风险。

## 如何预防

应实施安全安装流程，包括：

* 建立可重复的加固流程，能够快速、轻松地部署另一个经过适当锁定的环境。开发、QA 和生产环境应以相同方式配置，但各环境使用不同凭据。该流程应自动化，以减少搭建新安全环境所需的工作量。
* 使用最小化平台，不包含任何不必要的功能、组件、文档或示例。移除或不要安装未使用的功能和框架。
* 将审查和更新配置作为补丁管理流程的一部分，确保配置符合所有安全公告、更新和补丁要求（参见 [A03 软件供应链失效](A03_2025-Software_Supply_Chain_Failures.md)）。审查云存储权限（例如 S3 bucket 权限）。
* 采用分段应用架构，通过分段、容器化或云安全组（ACL）在组件或租户之间实现有效且安全的隔离。
* 向客户端发送安全指令，例如安全头。
* 建立自动化流程，验证所有环境中的配置和设置是否有效。
* 主动增加集中配置，作为拦截过多错误消息的备用措施。
* 如果这些验证没有自动化，至少应每年手动验证一次。
* 使用底层平台提供的身份联合、短期凭据或基于角色的访问机制，而不是在代码、配置文件或流水线中嵌入静态密钥或 secret。

## 攻击场景示例

**场景 #1：** 应用服务器附带的示例应用没有从生产服务器中移除。这些示例应用存在已知安全缺陷，攻击者可利用它们攻陷服务器。假设其中一个示例应用是管理控制台，且默认账户没有修改。攻击者就能使用默认密码登录并接管系统。

**场景 #2：** 服务器未禁用目录列表。攻击者发现可以直接列出目录。他找到并下载编译后的 Java 类文件，反编译并逆向工程查看代码。随后攻击者在应用中发现严重访问控制缺陷。

**场景 #3：** 应用服务器配置允许向用户返回详细错误消息，例如堆栈跟踪。这可能暴露敏感信息或底层缺陷，例如已知易受攻击的组件版本。

**场景 #4：** 云服务提供商（CSP）默认将共享权限开放到互联网。这会允许云存储中的敏感数据被访问。

## 参考资料

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration

## 映射的 CWE 列表

* [CWE-5 J2EE 配置错误：数据传输未加密](https://cwe.mitre.org/data/definitions/5.html)
* [CWE-11 ASP.NET 配置错误：创建调试二进制文件](https://cwe.mitre.org/data/definitions/11.html)
* [CWE-13 ASP.NET 配置错误：配置文件中包含密码](https://cwe.mitre.org/data/definitions/13.html)
* [CWE-15 系统或配置设置受外部控制](https://cwe.mitre.org/data/definitions/15.html)
* [CWE-16 配置](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-260 配置文件中包含密码](https://cwe.mitre.org/data/definitions/260.html)
* [CWE-315 在 Cookie 中明文存储敏感信息](https://cwe.mitre.org/data/definitions/315.html)
* [CWE-489 激活的调试代码](https://cwe.mitre.org/data/definitions/489.html)
* [CWE-526 通过环境变量暴露敏感信息](https://cwe.mitre.org/data/definitions/526.html)
* [CWE-547 使用硬编码的安全相关常量](https://cwe.mitre.org/data/definitions/547.html)
* [CWE-611 XML 外部实体引用限制不当](https://cwe.mitre.org/data/definitions/611.html)
* [CWE-614 HTTPS 会话中的敏感 Cookie 缺少 `Secure` 属性](https://cwe.mitre.org/data/definitions/614.html)
* [CWE-776 DTD 中递归实体引用限制不当（XML 实体扩展）](https://cwe.mitre.org/data/definitions/776.html)
* [CWE-942 对不可信域使用过宽松的跨域策略](https://cwe.mitre.org/data/definitions/942.html)
* [CWE-1004 敏感 Cookie 缺少 `HttpOnly` 标志](https://cwe.mitre.org/data/definitions/1004.html)
* [CWE-1174 ASP.NET 配置错误：模型验证不当](https://cwe.mitre.org/data/definitions/1174.html)
