# A02:2025 安全配置错误 ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## 背景

相比上一版从第5位上升至此，所有被测试的应用程序均被发现存在某种形式的配置错误，平均发生率为3.00%，该风险类别中通用弱点枚举（CWE）出现次数超过71.9万次。随着软件高度可配置化趋势的增强，此类别的上升并不令人意外。值得注意的CWE包括 *CWE-16 配置* 和 *CWE-611 XML外部实体引用（XXE）限制不当*。


## 评分表


<table>
  <tr>
   <td>映射的CWE数量
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
   <td>总CVE数量
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

安全配置错误是指系统、应用程序或云服务在安全层面配置不当，从而产生漏洞的情况。

应用程序可能存在漏洞的情况包括：



* 应用程序堆栈的任何部分缺乏适当的安全加固，或云服务的权限配置不当。
* 启用或安装了不必要的功能（例如不必要的端口、服务、页面、账户、测试框架或权限）。
* 默认账户及其密码仍处于启用状态且未更改。
* 缺乏拦截过多错误信息的集中配置。错误处理向用户暴露了堆栈跟踪或其他信息量过大的错误消息。
* 对于升级后的系统，最新的安全功能被禁用或未安全配置。
* 过度优先考虑向后兼容性导致不安全的配置。
* 应用服务器、应用框架（例如 Struts、Spring、ASP.NET）、库、数据库等中的安全设置未设置为安全值。
* 服务器未发送安全标头或指令，或者这些标头或指令未设置为安全值。

如果没有经过协调一致且可重复的应用程序安全配置加固流程，系统将面临更高的风险。


## 如何预防

应实施安全的安装流程，包括：



* 一个可重复的加固流程，能够快速轻松地部署另一个经过适当锁定的环境。开发、质量保证和生产环境应配置相同，但每个环境使用不同的凭据。此流程应实现自动化，以尽量减少建立新安全环境所需的工作量。
* 一个不包含任何不必要功能、组件、文档或示例的最小化平台。删除或不安装未使用的功能和框架。
* 作为补丁管理流程的一部分，定期审查和更新配置，使其符合所有安全公告、更新和补丁的要求（参见 [A03 软件供应链失效](A03_2025-Software_Supply_Chain_Failures.md)）。审查云存储权限（例如 S3 存储桶权限）。
* 分段式应用程序架构，通过分段、容器化或云安全组（ACL）在组件或租户之间提供有效且安全的隔离。
* 向客户端发送安全指令，例如安全标头。
* 一个自动化流程，用于验证所有环境中配置和设置的有效性。
* 主动添加集中配置，作为拦截过多错误信息的备份措施。
* 如果这些验证未实现自动化，则至少应每年进行一次手动验证。
* 使用底层平台提供的身份联合、短期凭据或基于角色的访问机制，而不是在代码、配置文件或流水线中嵌入静态密钥或机密。


## 示例攻击场景

**场景 #1：** 应用服务器附带了未从生产服务器中移除的示例应用程序。这些示例应用程序存在已知的安全漏洞，攻击者利用这些漏洞入侵服务器。如果其中某个应用程序是管理控制台，并且默认账户未更改，那么攻击者可以使用默认密码登录并接管控制台。

**场景 #2：** 服务器上未禁用目录列表功能。攻击者发现他们可以简单地列出目录。攻击者找到并下载了已编译的 Java 类，然后通过反编译和逆向工程查看代码。随后，攻击者在应用程序中发现了一个严重的访问控制漏洞。

**场景 #3：** 应用服务器的配置允许向用户返回详细的错误消息，例如堆栈跟踪。这可能会暴露敏感信息或底层漏洞，例如已知存在漏洞的组件版本。

**场景 #4：** 云服务提供商（CSP）默认将共享权限设置为对互联网开放。这使得存储在云存储中的敏感数据可以被访问。


## 参考资料

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: 安全配置错误

## 映射的CWE列表

* [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)

* [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

* [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

* [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

* [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

* [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

* [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

* [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

* [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

* [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

* [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

* [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

* [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)