# A06:2025 不安全设计 ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## 背景

不安全设计排名从第 4 位下滑两位到第 6 位，被 **[A02:2025-安全配置错误](A02_2025-Security_Misconfiguration.md)** 和 **[A03:2025-软件供应链失效](A03_2025-Software_Supply_Chain_Failures.md)** 超过。该类别于 2021 年引入，我们已经看到行业在威胁建模方面有明显改进，也更加重视安全设计。该类别关注与设计和架构缺陷相关的风险，并呼吁更多使用威胁建模、安全设计模式和参考架构。这包括应用业务逻辑中的缺陷，例如没有定义应用内部不希望发生或意外发生的状态变化。作为社区，我们需要超越编码阶段的“左移”，推进到需求编写和应用设计等编码前活动，这些活动对 Secure by Design 原则至关重要（例如参见 **[建立现代 AppSec 计划：规划和设计阶段](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**）。值得关注的通用弱点枚举（CWE）包括 *CWE-256：凭据存储未受保护*、*CWE-269：权限管理不当*、*CWE-434：危险类型文件上传不受限制*、*CWE-501：信任边界违背* 和 *CWE-522：凭据保护不足*。

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

不安全设计是一个宽泛类别，代表多种弱点，可概括为“缺失或无效的控制设计”。不安全设计不是其他所有 Top Ten 风险类别的来源。需要注意，不安全设计和不安全实现是不同的。我们区分设计缺陷和实现缺陷是有原因的：它们根因不同，发生在开发流程的不同时间点，修复方式也不同。安全设计仍可能因实现缺陷产生可被利用的漏洞。不安全设计无法通过完美实现修复，因为防御特定攻击所需的安全控制从未被创建。导致不安全设计的因素之一，是开发中的软件或系统本身缺少业务风险画像，因此无法判断需要什么级别的安全设计。

安全设计包含三个关键部分：

* 收集需求和资源管理
* 创建安全设计
* 具备安全开发生命周期

### 需求和资源管理

与业务方收集并协商应用的业务需求，包括所有数据资产在机密性、完整性、可用性和真实性方面的保护需求，以及预期业务逻辑。考虑应用将暴露到什么程度，以及是否需要租户隔离（超出访问控制所需的隔离）。汇总技术需求，包括功能性和非功能性安全需求。规划并协商覆盖设计、构建、测试和运维的预算，其中包括安全活动。

### 安全设计

安全设计是一种文化和方法论，会持续评估威胁，并确保代码经过稳健设计和测试，以防止已知攻击方法。威胁建模应集成到需求细化会（或类似活动）中；关注数据流、访问控制或其他安全控制的变化。在故事开发过程中，确定正确流程和失败状态，并确保相关责任方和受影响方都理解并达成一致。分析预期流程和失败流程中的假设及条件，确保它们仍然准确且符合预期。确定如何验证这些假设，并强制执行正确行为所需的条件。确保结果记录在故事中。从错误中学习，并提供正向激励来促进改进。安全设计既不是附加项，也不是一个可以简单加到软件上的工具。

### 安全开发生命周期

安全软件需要安全开发生命周期、安全设计模式、铺好的道路方法、安全组件库、合适工具、威胁建模，以及用于改进流程的事件复盘。请在软件项目开始时、项目过程中以及持续软件维护期间联系安全专家。考虑使用 [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/) 来组织安全软件开发工作。

开发人员的自我责任常被低估。应培养安全意识、责任感和主动缓解风险的文化。围绕安全的定期交流（例如威胁建模会）可以形成一种思维方式，让安全进入所有重要设计决策。

## 如何预防

* 与 AppSec 专业人员共同建立并使用安全开发生命周期，以帮助评估和设计与安全及隐私相关的控制。
* 建立并使用安全设计模式库或铺好的道路组件库。
* 对应用的关键部分使用威胁建模，例如认证、访问控制、业务逻辑和关键流程。
* 将威胁建模作为教育工具，用来形成安全思维。
* 将安全语言和控制集成到用户故事中。
* 在应用的每一层（从前端到后端）集成合理性检查。
* 编写单元测试和集成测试，验证所有关键流程能够抵御威胁模型。为应用每一层编写用例 *和* 滥用用例。
* 根据暴露程度和保护需求，在系统层和网络层隔离各层。
* 在所有层中通过设计稳健地隔离租户。

## 攻击场景示例

**场景 #1：** 凭据恢复流程可能包含“问题和答案”，但 NIST 800-63b、OWASP ASVS 和 OWASP Top 10 都禁止这种方式。问题和答案不能作为身份依据，因为不止一个人可能知道答案。此类功能应被移除，并替换为更安全的设计。

**场景 #2：** 某连锁影院允许团体订票折扣，并规定超过 15 人才需要支付定金。攻击者可以对该流程进行威胁建模，测试是否能在应用业务逻辑中找到攻击向量，例如通过少量请求一次性预订 600 个座位和所有影院，造成巨大收入损失。

**场景 #3：** 某零售连锁的电子商务网站没有防护黄牛机器人抢购高端显卡并转卖到拍卖网站。这会给显卡厂商和零售连锁所有者带来严重负面舆论，也会让无法以任何价格买到显卡的爱好者长期不满。周密的反机器人设计和领域逻辑规则，例如识别在开售后几秒内完成的购买，可能识别非真实购买并拒绝此类交易。

## 参考资料

* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST - Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## 映射的 CWE 列表

* [CWE-73 文件名或路径受外部控制](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 允许输入列表过于宽松](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 凭据存储未受保护](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 权限分配错误](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 权限管理不当](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-286 用户管理错误](https://cwe.mitre.org/data/definitions/286.html)
* [CWE-311 缺少敏感数据加密](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 明文存储敏感信息](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-313 在文件或磁盘上明文存储](https://cwe.mitre.org/data/definitions/313.html)
* [CWE-316 在内存中明文存储敏感信息](https://cwe.mitre.org/data/definitions/316.html)
* [CWE-362 使用共享资源并发执行时同步不当（竞争条件）](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-382 J2EE 不良实践：使用 `System.exit()`](https://cwe.mitre.org/data/definitions/382.html)
* [CWE-419 主通道未受保护](https://cwe.mitre.org/data/definitions/419.html)
* [CWE-434 危险类型文件上传不受限制](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-436 解释冲突](https://cwe.mitre.org/data/definitions/436.html)
* [CWE-444 HTTP 请求解释不一致（HTTP 请求走私）](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-451 用户界面对关键信息表述失真](https://cwe.mitre.org/data/definitions/451.html)
* [CWE-454 可信变量或数据存储受外部初始化](https://cwe.mitre.org/data/definitions/454.html)
* [CWE-472 假定不可变的网站参数受外部控制](https://cwe.mitre.org/data/definitions/472.html)
* [CWE-501 信任边界违背](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 凭据保护不足](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-525 使用含敏感信息的浏览器缓存](https://cwe.mitre.org/data/definitions/525.html)
* [CWE-539 使用包含敏感信息的持久 Cookie](https://cwe.mitre.org/data/definitions/539.html)
* [CWE-598 使用带敏感查询字符串的 `GET` 请求方法](https://cwe.mitre.org/data/definitions/598.html)
* [CWE-602 在客户端强制执行服务端安全](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-628 函数调用参数指定错误](https://cwe.mitre.org/data/definitions/628.html)
* [CWE-642 关键状态数据受外部控制](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-646 依赖外部提供文件的文件名或扩展名](https://cwe.mitre.org/data/definitions/646.html)
* [CWE-653 隔离或分隔不足](https://cwe.mitre.org/data/definitions/653.html)
* [CWE-656 依赖隐藏实现安全](https://cwe.mitre.org/data/definitions/656.html)
* [CWE-657 违反安全设计原则](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-676 使用潜在危险函数](https://cwe.mitre.org/data/definitions/676.html)
* [CWE-693 保护机制失效](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 交互频率控制不当](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-807 安全决策依赖不可信输入](https://cwe.mitre.org/data/definitions/807.html)
* [CWE-841 行为工作流强制执行不当](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 渲染用户界面层或框架限制不当](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1022 使用带 `window.opener` 访问权限、指向不可信目标的网站链接](https://cwe.mitre.org/data/definitions/1022.html)
* [CWE-1125 攻击面过大](https://cwe.mitre.org/data/definitions/1125.html)
