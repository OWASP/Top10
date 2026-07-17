# A06:2025 不安全设计 ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}


## 背景

不安全设计在排名中从第4位下滑两位至第6位，因为 **[A02:2025-Security Misconfiguration](A02_2025-Security_Misconfiguration.md)** 和 **[A03:2025-Software Supply Chain Failures](A03_2025-Software_Supply_Chain_Failures.md)** 超越了它。该类别于2021年引入，我们观察到行业在威胁建模方面有了显著改进，并且对安全设计的重视程度也有所提高。此类别重点关注与设计和架构缺陷相关的风险，呼吁更多地使用威胁建模、安全设计模式和参考架构。这包括应用程序业务逻辑中的缺陷，例如缺乏对应用程序内非预期或意外状态变更的定义。作为一个社区，我们需要超越编码领域的"左移"，转向编码前的活动，如需求编写和应用程序设计，这些对于"安全设计"原则至关重要（例如，参见 **[Establish a Modern AppSec Program: Planning and Design Phase](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**）。值得注意的常见弱点枚举（CWE）包括：*CWE-256：凭据未受保护存储、CWE-269：权限管理不当、CWE-434：危险类型文件无限制上传、CWE-501：信任边界违反，以及 CWE-522：凭据保护不足。*


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
   <td>平均加权利用度
   </td>
   <td>平均加权影响
   </td>
   <td>总发生次数
   </td>
   <td>总 CVE 数量
   </td>
  </tr>
  <tr>
   <td>39
   </td>
   <td>22.18%
   </td>
   <td>1.86%
   </td>
   <td>88.76%
   </td>
   <td>35.18%
   </td>
   <td>6.96
   </td>
   <td>4.05
   </td>
   <td>729,882
   </td>
   <td>7,647
   </td>
  </tr>
</table>



## 描述

不安全设计是一个广泛的类别，代表了不同的弱点，表现为"缺失或无效的控制设计"。不安全设计并非所有其他十大风险类别的根源。请注意，不安全设计与不安全实现之间存在区别。我们区分设计缺陷和实现缺陷是有原因的：它们有不同的根本原因，发生在开发过程的不同阶段，并且有不同的修复方法。一个安全的设计仍然可能存在实现缺陷，从而导致可能被利用的漏洞。而一个不安全的设计无法通过完美的实现来修复，因为必要的安全控制从未被创建以防御特定的攻击。导致不安全设计的因素之一是缺乏对所开发软件或系统固有的业务风险分析，从而未能确定所需的安全设计级别。

实现安全设计的三个关键部分是：

* 收集需求与资源管理
* 创建安全设计
* 拥有安全开发生命周期


### 需求与资源管理

与业务方一起收集并协商应用程序的业务需求，包括所有数据资产的机密性、完整性、可用性和真实性方面的保护需求，以及预期的业务逻辑。考虑应用程序的暴露程度，以及是否需要租户隔离（超出访问控制所需的隔离）。编制技术需求，包括功能性和非功能性的安全需求。规划并协商涵盖所有设计、构建、测试和运营（包括安全活动）的预算。


### 安全设计

安全设计是一种文化和方法论，它持续评估威胁，并确保代码经过稳健的设计和测试，以防止已知的攻击方法。威胁建模应融入细化会议（或类似活动）中；关注数据流、访问控制或其他安全控制的变化。在用户故事开发中，确定正确的流程和失败状态，确保负责方和受影响方充分理解并达成一致。分析预期流程和失败流程的假设与条件，确保它们保持准确和理想。确定如何验证假设并强制执行正确行为所需的条件。确保结果记录在用户故事中。从错误中学习，并提供积极激励以促进改进。安全设计既不是附加组件，也不是可以添加到软件中的工具。


### 安全开发生命周期

安全的软件需要一个安全开发生命周期、安全设计模式、铺平道路方法论、安全组件库、适当的工具、威胁建模以及用于改进流程的事故后复盘。在软件项目开始时、整个项目期间以及持续的软件维护中，都要联系你的安全专家。考虑利用 [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/) 来帮助构建你的安全软件开发工作。

开发者的自我责任往往被低估。培养一种意识、责任和主动风险缓解的文化。定期进行安全方面的交流（例如在威胁建模会议期间）可以培养一种将安全纳入所有重要设计决策的思维方式。


## 如何预防

* 建立并使用安全开发生命周期，与 AppSec 专业人员合作，帮助评估和设计安全及隐私相关的控制措施
* 建立并使用安全设计模式库或铺平道路组件
* 对应用程序的关键部分（如身份验证、访问控制、业务逻辑和关键流程）使用威胁建模
* 将威胁建模作为教育工具，培养安全思维
* 将安全语言和控制措施整合到用户故事中
* 在应用程序的每一层（从前端到后端）实施合理性检查
* 编写单元测试和集成测试，以验证所有关键流程能够抵御威胁模型。为应用程序的每一层编译用例和误用例
* 根据暴露和保护需求，在系统和网络层上隔离层级
* 通过设计在所有层级上稳健地隔离租户


## 示例攻击场景

**场景 #1：** 凭据恢复工作流程可能包含"问答"机制，但这被 NIST 800-63b、OWASP ASVS 和 OWASP Top 10 所禁止。问答不能作为身份证据，因为多个人可能知道答案。应移除此类功能，并用更安全的设计替代。

**场景 #2：** 一家连锁影院提供团体预订折扣，且最多允许十五人参加，之后需要支付押金。攻击者可以对此流程进行威胁建模，并测试是否能在应用程序的业务逻辑中找到攻击向量，例如在一次请求中预订六百个座位以及所有影院，从而造成巨大的收入损失。

**场景 #3：** 一家零售连锁店的电子商务网站没有针对黄牛机器人的防护，这些机器人购买高端显卡后在拍卖网站上转售。这给显卡制造商和零售连锁店所有者带来了糟糕的公众形象，并导致无法以任何价格购买到这些显卡的爱好者长期不满。精心设计的反机器人设计和领域逻辑规则，例如在商品上架后几秒内的购买行为，可能识别出非真实购买并拒绝此类交易。


## 参考文献

* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## 映射的 CWE 列表

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)

* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)

* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)

* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)

* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)

* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)

* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

* [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)

* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)

* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)