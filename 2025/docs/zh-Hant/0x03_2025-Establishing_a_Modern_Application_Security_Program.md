# 建立现代应用安全计划

OWASP Top Ten 系列是安全意识文档，目的是让读者关注其覆盖主题中最关键的风险。它们不是完整清单，只是起点。在本清单的早期版本中，我们建议从建立应用安全计划开始，以避免这些风险以及更多问题。本节将说明如何启动并建设现代应用安全计划。

如果你已经有应用安全计划，可以考虑使用 [OWASP SAMM（Software Assurance Maturity Model）](https://owasp.org/www-project-samm/)或 DSOMM（DevSecOps Maturity Model）对其进行成熟度评估。这些成熟度模型全面而细致，可帮助你判断扩展和成熟计划时应把精力放在哪里。请注意：做好应用安全并不需要完成 OWASP SAMM 或 DSOMM 中的所有事项；它们的作用是提供指导和许多选项。它们不是用来提出不可达成的标准，也不是用来描述无法负担的计划。它们覆盖范围很广，是为了给你提供更多思路和选择。

如果你正从零开始建立计划，或者觉得 OWASP SAMM 或 DSOMM 对当前团队来说“过重”，请参考以下建议。

### 1. 建立基于风险的资产组合方法：

* 从业务角度识别应用资产组合的保护需求。这应部分由隐私法律以及与受保护数据资产相关的其他法规驱动。

* 建立一个[通用风险评级模型](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)，使用一致的可能性和影响因素，并反映组织的风险容忍度。

* 按此方式衡量并优先排序所有应用和 API。将结果加入[配置管理数据库（CMDB）](https://de.wikipedia.org/wiki/Configuration_Management_Database)。

* 建立保障指南，明确所需覆盖范围和严谨程度。

### 2. 用坚实基础赋能：

* 建立一组聚焦的策略和标准，为所有开发团队提供应遵循的应用安全基线。

* 定义一组可复用的通用安全控制，与这些策略和标准相互补充，并为其使用提供设计和开发指导。

* 建立应用安全培训课程体系，要求不同开发角色按主题完成有针对性的培训。

### 3. 将安全集成到现有流程中：

* 定义安全实现和验证活动，并将其集成到现有开发和运维流程中。

* 活动包括威胁建模、安全设计和设计审查、安全编码和代码审查、渗透测试以及修复。

* 为开发和项目团队提供主题专家和支持服务，帮助他们成功完成工作。

* 审查当前系统开发生命周期以及所有软件安全活动、工具、策略和流程，并记录下来。

* 对新软件，在系统开发生命周期（SDLC）的每个阶段加入一个或多个安全活动。下面我们提供许多可选建议。确保每个新项目或软件计划都执行这些新活动，这样你才能知道每个新软件都能以组织可接受的安全状态交付。

* 选择活动时，应确保最终产品达到组织可接受的风险水平。

* 对现有软件（有时称为遗留系统），你需要正式的维护计划。可以参考下方“运维和变更管理”部分中有关如何维护安全应用的建议。

### 4. 应用安全教育：

* 考虑为开发人员建立安全冠军计划，或更通用的安全教育计划（有时称为倡导计划或安全意识计划），教给他们你希望他们掌握的内容。这会帮助他们保持知识更新，知道如何安全地完成工作，并让工作中的安全文化更加积极。它通常也会增进团队之间的信任，让协作关系更顺畅。OWASP 通过 [OWASP Security Champions Guide](https://securitychampions.owasp.org/) 支持你，该指南正在逐步扩展。

* OWASP Education Project 提供培训材料，帮助开发人员学习 Web 应用安全。若想动手学习漏洞，可以尝试 [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/) 或 [OWASP WebGoat](https://owasp.org/www-project-webgoat/)。若想保持更新，可以参加 [OWASP AppSec Conference](https://owasp.org/events/)、[OWASP Conference Training](https://owasp.org/events/)，或本地 [OWASP Chapter](https://owasp.org/chapters/) 会议。

### 5. 提供管理层可见性：

* 用指标管理。基于收集到的指标和分析数据推动改进和资金决策。指标包括安全实践和活动的遵循情况、引入的漏洞、缓解的漏洞、应用覆盖率、按类型划分的缺陷密度和实例数量等。

* 分析实现和验证活动中的数据，寻找根因和漏洞模式，从而推动整个企业范围内的战略性、系统性改进。从错误中学习，并提供正向激励来促进改进。

## 建立并使用可重复的安全流程和标准安全控制

### 需求和资源管理阶段：

* 与业务方收集并协商应用的业务需求，包括所有数据资产在机密性、真实性、完整性和可用性方面的保护需求，以及预期业务逻辑。

* 汇总技术需求，包括功能性和非功能性安全需求。OWASP 建议使用 [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) 作为设定应用安全需求的指南。

* 规划并协商预算，覆盖设计、构建、测试和运维的各个方面，包括安全活动。

* 将安全活动加入项目计划。

* 在项目启动会上以安全代表身份介绍自己，让团队知道应找谁沟通。

### 提案请求（RFP）和合同：

* 与内部或外部开发人员协商需求，包括与你的安全计划相关的指南和安全要求，例如 SDLC、最佳实践。

* 评估所有技术需求的满足情况，包括规划和设计阶段。

* 协商所有技术需求，包括设计、安全和服务级别协议（SLA）。

* 采用模板和清单，例如 [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex)。<br>**注意：** *该附件面向美国合同法，因此在使用示例附件前请咨询合格的法律意见。*

### 规划和设计阶段：

* 与开发人员和内部利益相关方（例如安全专家）协商规划和设计。

* 根据保护需求和预期威胁级别定义安全架构、控制、对策和设计审查。这应由安全专家支持。

* 与其在应用和 API 中事后补安全，不如从一开始就把安全设计进去，成本也低得多。OWASP 建议将 [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) 和 [OWASP Proactive Controls](https://top10proactive.owasp.org/) 作为设计阶段纳入安全的起点。

* 执行威胁建模，参见 [OWASP Cheat Sheet: Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)。

* 教会软件架构师安全设计概念和模式，并要求他们尽可能加入设计。

* 与开发人员一起检查数据流。

* 在所有其他用户故事旁加入安全用户故事。

### 安全开发生命周期：

* 为改进组织构建应用和 API 时遵循的流程，OWASP 建议使用 [OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/)。该模型帮助组织制定并实施适合自身风险的软件安全策略。

* 为软件开发人员提供安全编码培训，也提供任何你认为有助于他们构建更稳健、更安全应用的培训。

* 进行代码审查，参见 [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)。

* 给开发人员提供安全工具，并教他们使用，尤其是静态分析、软件组成分析、机密扫描和[基础设施即代码（IaC）](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)扫描器。

* 在可行时为开发人员建立护栏（技术性保护措施，引导他们做出更安全的选择）。

* 构建强大且可用的安全控制并不容易。尽可能提供安全默认值，并在可行时建立“铺好的路”（让最简单的做法也是最安全、最显然应优先选择的做法）。[OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) 是开发人员的良好起点，许多现代框架也已经内置用于授权、验证、CSRF 防护等标准且有效的安全控制。

* 给开发人员提供与安全相关的 IDE 插件，并鼓励他们使用。

* 为他们提供密钥管理工具、许可证和使用文档。

* 为他们提供私有 AI，理想情况下配有 RAG 服务器，包含有用的安全文档、团队编写的高质量提示词，以及能够调用组织所选安全工具的 MCP 服务器。教他们安全使用 AI，因为无论你是否愿意，他们都会使用。

### 建立持续应用安全测试：

* 测试技术功能以及与 IT 架构的集成，并协调业务测试。

* 从技术和业务角度创建“使用”和“滥用”测试用例。

* 根据内部流程、保护需求和应用的假定威胁级别管理安全测试。

* 提供安全测试工具（模糊测试器、DAST 等）、安全测试环境和工具使用培训；或者替他们做测试；或者雇用测试人员。

* 如果需要高保障级别，考虑正式渗透测试，以及压力测试和性能测试。

* 与开发人员合作，帮助他们判断缺陷报告中哪些问题需要修复，并确保他们的经理给他们修复时间。

### 发布：

* 将应用投入运行，并在需要时从旧应用迁移。

* 完成所有文档，包括变更管理数据库（CMDB）和安全架构。

### 运维和变更管理：

* 运维必须包括应用安全管理指南，例如补丁管理。

* 提升用户安全意识，并管理可用性与安全性之间的冲突。

* 规划并管理变更，例如迁移到应用新版本，或迁移到 OS、中间件、库等其他组件的新版本。

* 确保所有应用都纳入清单，并记录所有重要细节。更新所有文档，包括 CMDB、安全架构、控制、对策，以及任何运行手册或项目文档。

* 对所有应用执行日志记录、监控和告警。如果缺失，就补上。

* 创建有效且高效的更新和补丁流程。

* 创建定期扫描计划（理想情况下包括动态、静态、密钥、IaC 和软件组成分析）。

* 为修复安全缺陷设定 SLA。

* 提供员工（理想情况下也包括客户）报告缺陷的渠道。

* 建立训练有素的事件响应团队，使其了解软件攻击的表现以及可观测性工具。

* 运行阻断或防护工具来拦截自动化攻击。

* 每年（或更频繁）加固配置。

* 至少每年进行一次渗透测试（取决于应用所需保障级别）。

* 建立流程和工具来加固并保护软件供应链。

* 建立并更新业务连续性和灾难恢复规划，其中包括最重要的应用以及维护这些应用所使用的工具。

### 退役系统：

* 应归档所有必须保留的数据。所有其他数据应安全擦除。

* 安全退役应用，包括删除未使用的账户、角色和权限。

* 在 CMDB 中将应用状态设置为已退役。

## 将 OWASP Top 10 作为标准使用

OWASP Top 10 主要是一份安全意识文档。不过，自 2003 年创立以来，许多组织仍将其用作事实上的行业 AppSec 标准。如果你想将 OWASP Top 10 用作编码或测试标准，请明确它只是最低要求和起点。

使用 OWASP Top 10 作为标准的一个难点在于，我们记录的是 AppSec 风险，而不一定是容易测试的问题。例如，[A06:2025-不安全设计](A06_2025-Insecure_Design.md) 超出了大多数测试形式的范围。另一个例子是测试是否实现了就地、在用且有效的日志记录和监控，这只能通过访谈以及抽样请求有效事件响应来完成。静态代码分析工具可以查找缺少日志记录的情况，但可能无法判断业务逻辑或访问控制是否记录了重大安全事件。渗透测试人员也许只能确认他们在测试环境中触发了事件响应，而测试环境很少像生产环境一样被监控。

以下是我们关于何时适合使用 OWASP Top 10 的建议：

<table>
  <tr>
   <td><strong>使用场景</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>OWASP Application Security Verification Standard</strong>
   </td>
  </tr>
  <tr>
   <td>安全意识
   </td>
   <td>是
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>培训
   </td>
   <td>入门级
   </td>
   <td>全面
   </td>
  </tr>
  <tr>
   <td>设计和架构
   </td>
   <td>偶尔适用
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>编码标准
   </td>
   <td>最低要求
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>安全代码审查
   </td>
   <td>最低要求
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>同行审查清单
   </td>
   <td>最低要求
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>单元测试
   </td>
   <td>偶尔适用
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>集成测试
   </td>
   <td>偶尔适用
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>渗透测试
   </td>
   <td>最低要求
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>工具支持
   </td>
   <td>最低要求
   </td>
   <td>是
   </td>
  </tr>
  <tr>
   <td>安全供应链
   </td>
   <td>偶尔适用
   </td>
   <td>是
   </td>
  </tr>
</table>

我们鼓励任何想采用应用安全标准的人使用 [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)（ASVS），因为它设计为可验证、可测试，并可用于安全开发生命周期的各个部分。

ASVS 是工具厂商唯一可接受的选择。由于 OWASP Top 10 中多个风险的性质，工具无法全面检测、测试或防护 OWASP Top 10，尤其参见 [A06:2025-不安全设计](A06_2025-Insecure_Design.md)。OWASP 不鼓励任何声称完整覆盖 OWASP Top 10 的说法，因为这根本不真实。

