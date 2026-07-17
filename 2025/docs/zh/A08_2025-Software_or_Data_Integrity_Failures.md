# A08:2025 软件或数据完整性失效 ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景

软件或数据完整性失效仍位列第8位，名称从"软件*与*数据完整性失效"略微调整为更清晰的表述。此类问题侧重于在低于软件供应链失效的层级上，未能维护信任边界并验证软件、代码及数据工件的完整性。其核心在于对软件更新和关键数据做出假设，却未验证其完整性。值得注意的常见弱点枚举（CWE）包括 *CWE-829：包含来自不受信任控制域的功能*、*CWE-915：对动态确定对象属性的不当控制修改*，以及 *CWE-502：不可信数据的反序列化*。

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
   <td>平均加权利用
   </td>
   <td>平均加权影响
   </td>
   <td>总发生次数
   </td>
   <td>总CVE数量
   </td>
  </tr>
  <tr>
   <td>14
   </td>
   <td>8.98%
   </td>
   <td>2.75%
   </td>
   <td>78.52%
   </td>
   <td>45.49%
   </td>
   <td>7.11
   </td>
   <td>4.79
   </td>
   <td>501,327
   </td>
   <td>3,331
   </td>
  </tr>
</table>

## 描述

软件与数据完整性失效涉及那些未能防范将无效或不可信的代码或数据视为可信且有效的代码和基础设施。例如，应用程序依赖来自不受信任来源、仓库和内容分发网络（CDN）的插件、库或模块。一个不安全的CI/CD流水线，若未进行软件完整性检查的消费与提供，可能引入未授权访问、不安全或恶意代码，或导致系统受损。另一个例子是CI/CD从不受信任的地方拉取代码或工件，且在使用前未通过签名或类似机制进行验证。最后，许多应用程序现在包含自动更新功能，更新在未充分验证完整性的情况下被下载并应用于先前可信的应用程序。攻击者可能上传自己的更新，使其分发并在所有安装实例上运行。另一个例子是，对象或数据被编码或序列化为攻击者可查看和修改的结构，从而容易受到不安全反序列化的攻击。

## 如何预防

* 使用数字签名或类似机制来验证软件或数据来自预期来源且未被篡改。
* 确保库和依赖项（如npm或Maven）仅从受信任的仓库获取。如果风险较高，考虑托管一个经过审查的内部已知良好仓库。
* 确保对代码和配置更改有审查流程，以最大程度减少恶意代码或配置被引入软件流水线的可能性。
* 确保CI/CD流水线具有适当的分隔、配置和访问控制，以保证构建和部署过程中代码的完整性。
* 确保未签名或未加密的序列化数据不会从不受信任的客户端接收，并在未经完整性检查或数字签名的情况下使用，以检测序列化数据的篡改或重放。

## 攻击场景示例

**场景 #1 包含来自不受信任来源的Web功能：** 一家公司使用外部服务提供商提供支持功能。为方便起见，它将 `myCompany.SupportProvider.com` 的DNS映射到 `support.myCompany.com`。这意味着所有在 `myCompany.com` 域上设置的cookie（包括身份验证cookie）都将发送给支持提供商。任何能访问支持提供商基础设施的人都可以窃取所有访问过 `support.myCompany.com` 的用户的cookie，并执行会话劫持攻击。

**场景 #2 未经签名的更新：** 许多家用路由器、机顶盒、设备固件等未通过签名固件验证更新。未签名固件正成为攻击者日益增长的目标，预计情况只会更糟。这是一个主要问题，因为很多时候除了在将来版本中修复并等待旧版本淘汰外，没有其他补救机制。

**场景 #3 使用来自不受信任来源的包：** 一名开发者在寻找所需包的更新版本时遇到困难，因此从在线网站而非常规的受信任包管理器下载了该包。该包未签名，因此无法确保完整性。该包包含恶意代码。

**场景 #4 不安全反序列化：** 一个React应用程序调用一组Spring Boot微服务。作为函数式程序员，他们试图确保代码是不可变的。他们提出的解决方案是序列化用户状态，并在每次请求中来回传递。攻击者注意到"rO0"Java对象签名（以base64编码），并使用 [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) 在应用服务器上获得远程代码执行。

## 参考资料

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)

## 映射的CWE列表

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

* [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

* [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

* [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

* [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)

* [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

* [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

* [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

* [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)