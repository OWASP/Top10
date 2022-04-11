# A05:2021 – 安全设定缺陷

## 弱点因素(Factors)

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权引响 | 出现次数 | 所有相关 CVEs |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :-----------: |
|        20        |   19.84%   |   4.51%    |    89.58%    |    44.84%    |     8.12     |     6.56     | 208,387  |      789      |

## 弱点简介(Overview)

从先前版本的第六名排名，向上调升，90%的程式都被测试找出各类的设定缺陷。随着越来越多的可设定式软体数量增加，看到此类别的排名上升，并不是件意外的事。明显相对应的 CWEs 包含了 _CWE16 设定_ 以及 _CWE-611 不充足的 XML 外部实体引用限制_

## 弱点描述(Description)

如果程式包含了以下几个因素，则可能有易受攻击的脆弱性。

- 在程式各堆叠层面，缺少适切的安全强化，或是于云端服务上有着不当的权限设定。

- 不必要的功能启用或是安装 (例如，不必要的端口，服务，页面，帐号，或是特权)。

- 预设帐号与密码还可使用，并且未更改。

- 因错误处理而暴露出的堆叠追踪，或是向使用者，暴露出过多的错误警告资讯

- 因为系统升级，导致最新的安全功能被关闭，或是造成不安全的设定

- 在布署程式的伺服器，程式框架(例如 Struts, Spring, ASP net，各种函示库，资料库等。并未设定该有的安全参数。

- 服务器并未传送安全的 header 或是指令，或未被设定安全参数。

- 软件已经过时已淘汰，或者带有脆弱性 (请参照 A06:2021-易受攻击和已淘汰的组件 )

当没有一致性，可重复的程式安全设定流程时，系统将会面对高风险。

## 如何预防(How to Prevent)

安全的安装步骤流程，应该被实际布署，包含以下

- 一个可重复的安全强化流程，必需可达到快速且简单的布署，而且能在分隔且封锁的环境下执行。开发，品质管理，以及实际营运的环境，都须有一致相同的设定，并且使用不同的认证资讯。这种步骤需要尽可能的自动化，降低需要建立安全环境时，所需要的投入。

- 一个最精简的平台，上面不会搭配任何不需要的功能，套件，档案，以及范本。移除或不安装任何，不须使用的功能或框架。

- 在变更管理下，需有特定的任务，依据安全告知，相关更新，来执行安全审视及更动(可参照 A06:2021-易受攻击和已淘汰的组件)。审视云端储存的权限(例如 S3 bucket 的权限)

- 一个可分割的程式架构，对于各元件，用户，可透过分离，容器化，云端安全群组设定(ACLs)，来达到分割的效果。提供有效且安全的分离。

- 寄送安全指令给用户端，例如 安全标头。

- 一个自动化的流程，可以确认环境中各类的安全设定。

## 攻击情境范例(Example Attack Scenarios)

**情境 #1:** 营运用的程式服务器，带有预设的样本程式，并未移除。这个样本程式带有已知的安全缺陷，可被攻击者利用入侵服务器。例如，预设的程式带有管理者界面，并且有未变更的帐号，攻击者可以透过预设的密码登入，并取得控制权。

**情境 #2:** 资料目录指令并未在服务器上关闭。攻击者可以找出并且下载，已编译过 Java 档案，并且透过反编译与逆向工程等手法，查看原始码。再因此找出程式中，严重的存取控制缺陷。

**情境 #3:** 程式服务器的设定，允许输出带有详细内容的错误讯息，例如堆叠追踪，供用户查看。这有可能导致敏感讯息的外泄，或间接透露出，使用中，并带有脆弱性的元件版本。

**情境 #4:** 一个云端服务器，提供了预设权限分享，给其他在网际网路的 CSP 用户。这将导致云端储存的敏感资料可以被存取。

## References

- [OWASP Testing Guide: Configuration
  Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

- [OWASP 测试指南: 设定管理](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

- OWASP Testing Guide: Testing for Error Codes

- OWASP 测试指南: 错误代码测试

- Application Security Verification Standard V19 Configuration

- 应用程式安全确认标准 v19 设定篇

- [NIST Guide to General Server
  Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

- [NIST 泛用服务器強化指南](https://csrc.nist.gov/publications/detail/sp/800-123/final)

- [CIS Security Configuration
  Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

- [CIS 安全设定指南/基准](https://www.cisecurity.org/cis-benchmarks/)

- [Amazon S3 Bucket Discovery and
  Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

- [Amazon S3 储存贮体侦测与探索](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## 對应的 CWEs 清单(List of Mapped CWEs)

CWE-2 Configuration

CWE-2 设定

CWE-11 ASP.NET Misconfiguration: Creating Debug Binary

CWE-11 ASP.NET 错误设定:创建除错二进制档

CWE-13 ASP.NET Misconfiguration: Password in Configuration File

CWE-13 ASP.NET 错误设定: 设定档中所存的密码

CWE-15 External Control of System or Configuration Setting

CWE-15 系統的外部控制与设定

CWE-16 Configuration

CWE-16 设定

CWE-260 Password in Configuration File

CWE-260 设定档中所存的密码

CWE-315 Cleartext Storage of Sensitive Information in a Cookie

CWE-315 cookies 中的明文存放敏感资料

CWE-520 .NET Misconfiguration: Use of Impersonation

CWE-520 .NET 错误设定: 冒充使用

CWE-526 Exposure of Sensitive Information Through Environmental
Variables

CWE-526 环境物件所泄漏的敏感咨询

CWE-537 Java Runtime Error Message Containing Sensitive Information

CWE-537 Java 运行环境下，错误讯息包含敏感资讯

CWE-541 Inclusion of Sensitive Information in an Include File

CWE-541 包容档案中，包含敏感资讯

CWE-547 Use of Hard-coded, Security-relevant Constants

CWE-547 使用写死的安全相关参数

CWE-611 Improper Restriction of XML External Entity Reference

CWE-611 不充足的 XML 外部实体引用限制

CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

CWE-614 HTTPS 下，敏感 Cookies 沒有使用"安全"参数设定

CWE-756 Missing Custom Error Page

CWE-756 遗漏常规的错误页面

CWE-776 Improper Restriction of Recursive Entity References in DTDs
('XML Entity Expansion')

CWE-776 DTDs 中，不充足的遞迴物件引用限制
(XML 物件扩张)

CWE-942 Permissive Cross-domain Policy with Untrusted Domains

CWE-942 跨网域白名单的过度权限

CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

CWE-1004 敏感 Cookie 没有使用'HttpOnly'参数设定

CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration

CWE-1032 OWASP 2017 前十大 A6 群组 - 安全错误设定

CWE-1174 ASP.NET Misconfiguration: Improper Model Validation

CWE-1174 ASP.NET 错误设定: 不充足的模组验证
