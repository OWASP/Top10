# A08:2025 软件或数据完整性失效 ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景

软件或数据完整性失效继续位列第 8，名称从“Software *and* Data Integrity Failures”略作澄清性调整。该类别关注在比软件供应链失效更低一层的位置，未能维护信任边界并验证软件、代码和数据工件完整性的问题。该类别关注在没有验证完整性的情况下，对软件更新和关键数据作出假设。值得关注的通用弱点枚举（CWE）包括 *CWE-829：从不可信控制范围引入功能*、*CWE-915：对动态确定对象属性的修改控制不当* 和 *CWE-502：反序列化不可信数据*。

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

软件和数据完整性失效与未能防止无效或不可信代码或数据被当作可信和有效内容处理的代码及基础设施有关。一个例子是应用依赖来自不可信来源、仓库和内容分发网络（CDN）的插件、库或模块。缺少消费和提供软件完整性检查的不安全 CI/CD 流水线，可能引入未经授权访问、不安全或恶意代码、系统被攻陷等风险。另一个例子是 CI/CD 从不可信位置拉取代码或工件，或者在使用前没有通过签名检查或类似机制验证它们。最后，许多应用现在包含自动更新功能，会在缺少充分完整性验证的情况下下载更新，并应用到此前受信任的应用上。攻击者可能上传自己的更新，使其被分发并在所有安装实例上运行。还有一种例子是，对象或数据被编码或序列化为攻击者可见且可修改的结构，从而容易受到不安全反序列化攻击。

## 如何预防

* 使用数字签名或类似机制验证软件或数据来自预期来源，且没有被修改。
* 确保 npm 或 Maven 等库和依赖只使用可信仓库。如果风险较高，考虑托管内部的、经过审核的已知良好仓库。
* 确保代码和配置变更有审查流程，以降低恶意代码或配置被引入软件流水线的可能性。
* 确保 CI/CD 流水线具备适当隔离、配置和访问控制，以保障流经构建和部署流程的代码完整性。
* 确保不会从不可信客户端接收未签名或未加密的序列化数据，并在没有某种完整性检查或数字签名来检测篡改或重放的情况下继续使用。

## 攻击场景示例

**场景 #1 来自不可信来源的 Web 功能引入：** 某公司使用外部服务提供商提供支持功能。为了方便，它将 `myCompany.SupportProvider.com` DNS 映射到 `support.myCompany.com`。这意味着所有设置在 `myCompany.com` 域上的 cookie，包括认证 cookie，现在都会被发送给该支持提供商。任何能访问支持提供商基础设施的人，都可以窃取访问过 `support.myCompany.com` 的所有用户的 cookie，并执行会话劫持攻击。

**场景 #2 未签名更新：** 许多家用路由器、机顶盒、设备固件等不会通过签名固件验证更新。未签名固件正成为攻击者越来越关注的目标，而且预计只会更糟。这是重大问题，因为许多时候除了在未来版本中修复并等待旧版本自然淘汰外，没有其他修复机制。

**场景 #3 使用来自不可信来源的软件包：** 开发人员难以找到所需软件包的更新版本，于是没有从常规、可信的软件包管理器下载，而是从网上某个网站下载。该软件包未签名，因此无法确保完整性。软件包中包含恶意代码。

**场景 #4 不安全反序列化：** 一个 React 应用调用一组 Spring Boot 微服务。作为函数式程序员，开发者试图确保代码不可变。他们想到的方案是序列化用户状态，并在每个请求中来回传递。攻击者注意到 `rO0` Java 对象签名（base64 编码），并使用 [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) 在应用服务器上获得远程代码执行。

## 参考资料

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)

## 映射的 CWE 列表

* [CWE-345 数据真实性验证不足](https://cwe.mitre.org/data/definitions/345.html)
* [CWE-353 缺少完整性检查支持](https://cwe.mitre.org/data/definitions/353.html)
* [CWE-426 不可信搜索路径](https://cwe.mitre.org/data/definitions/426.html)
* [CWE-427 搜索路径元素不受控制](https://cwe.mitre.org/data/definitions/427.html)
* [CWE-494 下载代码时未进行完整性检查](https://cwe.mitre.org/data/definitions/494.html)
* [CWE-502 反序列化不可信数据](https://cwe.mitre.org/data/definitions/502.html)
* [CWE-506 嵌入恶意代码](https://cwe.mitre.org/data/definitions/506.html)
* [CWE-509 复制恶意代码（病毒或蠕虫）](https://cwe.mitre.org/data/definitions/509.html)
* [CWE-565 依赖未经验证和完整性检查的 Cookie](https://cwe.mitre.org/data/definitions/565.html)
* [CWE-784 安全决策中依赖未经验证和完整性检查的 Cookie](https://cwe.mitre.org/data/definitions/784.html)
* [CWE-829 从不可信控制范围引入功能](https://cwe.mitre.org/data/definitions/829.html)
* [CWE-830 从不可信来源引入网页功能](https://cwe.mitre.org/data/definitions/830.html)
* [CWE-915 对动态确定对象属性的修改控制不当](https://cwe.mitre.org/data/definitions/915.html)
* [CWE-926 安卓应用组件导出不当](https://cwe.mitre.org/data/definitions/926.html)
