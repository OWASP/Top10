![OWASP Logo](../assets/TOP_10_logo_Final_Logo_Colour.png)

# 十大最关键 Web 应用安全风险

# 引言

欢迎阅读第 8 版 OWASP Top Ten！

衷心感谢所有在问卷中贡献数据和观点的人。没有你们，本版不可能完成。**谢谢你们！**

## OWASP Top 10:2025 简介

* [A01:2025 - 失效的访问控制](A01_2025-Broken_Access_Control.md)
* [A02:2025 - 安全配置错误](A02_2025-Security_Misconfiguration.md)
* [A03:2025 - 软件供应链失效](A03_2025-Software_Supply_Chain_Failures.md)
* [A04:2025 - 加密机制失效](A04_2025-Cryptographic_Failures.md)
* [A05:2025 - 注入](A05_2025-Injection.md)
* [A06:2025 - 不安全设计](A06_2025-Insecure_Design.md)
* [A07:2025 - 认证失效](A07_2025-Authentication_Failures.md)
* [A08:2025 - 软件或数据完整性失效](A08_2025-Software_or_Data_Integrity_Failures.md)
* [A09:2025 - 安全日志记录和告警失效](A09_2025-Security_Logging_and_Alerting_Failures.md)
* [A10:2025 - 异常条件处理不当](A10_2025-Mishandling_of_Exceptional_Conditions.md)

## 2025 年 Top 10 有哪些变化

2025 年 Top Ten 包含两个新增类别和一次类别合并。我们尽可能继续把重点放在根因而不是症状上。考虑到软件工程和软件安全本身的复杂性，要创建十个完全没有重叠的类别基本不可能。

![Mapping](../assets/2025-mappings.png)

* **[A01:2025 - 失效的访问控制](A01_2025-Broken_Access_Control.md)** 保持第 1 位，是最严重的应用安全风险；贡献数据表明，平均 3.73% 的受测应用存在本类别 40 个 CWE 中的一个或多个弱点。上图中的虚线表示服务端请求伪造（SSRF）已并入此类别。
* **[A02:2025 - 安全配置错误](A02_2025-Security_Misconfiguration.md)** 从 2021 年的第 5 位上升到 2025 年的第 2 位。在本轮数据中，配置错误更为普遍。3.00% 的受测应用存在本类别 16 个 CWE 中的一个或多个弱点。随着软件工程继续把越来越多的应用行为交给配置驱动，这并不意外。
* **[A03:2025 - 软件供应链失效](A03_2025-Software_Supply_Chain_Failures.md)** 是对 [A06:2021 - 易受攻击和过时的组件](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) 的扩展，覆盖软件依赖、构建系统和分发基础设施整个生态内或跨生态发生的更广泛的妥协。该类别在社区问卷中以压倒性优势被选为最受关注的问题。它包含 5 个 CWE，在收集数据中的体现有限；我们认为这是由于测试难度较高，并希望测试能力在这一领域逐步跟上。该类别在数据中的发生次数最少，但来自 CVE 的平均可利用性和影响分数最高。
* **[A04:2025 - 加密机制失效](A04_2025-Cryptographic_Failures.md)** 排名从第 2 位下降两位到第 4 位。贡献数据表明，平均 3.80% 的应用存在本类别 32 个 CWE 中的一个或多个弱点。该类别通常会导致敏感数据暴露或系统被攻陷。
* **[A05:2025 - 注入](A05_2025-Injection.md)** 排名从第 3 位下降两位到第 5 位，相对于加密机制失效和不安全设计的位置保持不变。注入是测试最充分的类别之一，本类别 38 个 CWE 关联的 CVE 数量最多。注入覆盖从跨站脚本（高频率、低影响）到 SQL 注入（低频率、高影响）等一系列问题。
* **[A06:2025 - 不安全设计](A06_2025-Insecure_Design.md)** 排名从第 4 位下滑两位到第 6 位，被安全配置错误和软件供应链失效超过。该类别于 2021 年引入，我们已经看到行业在威胁建模方面有明显改进，并且更加重视安全设计。
* **[A07:2025 - 认证失效](A07_2025-Authentication_Failures.md)** 保持第 7 位，名称略有变化（此前为 [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)），以更准确地反映该类别中的 36 个 CWE。该类别仍然重要，但标准化认证框架的使用增加似乎正在降低认证失效的发生。
* **[A08:2025 - 软件或数据完整性失效](A08_2025-Software_or_Data_Integrity_Failures.md)** 继续位列第 8。该类别关注在比软件供应链失效更低一层的位置，未能维护信任边界并验证软件、代码和数据工件完整性的问题。
* **[A09:2025 - 安全日志记录和告警失效](A09_2025-Security_Logging_and_Alerting_Failures.md)** 保持第 9 位。名称略有变化（此前为 [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)），用于强调告警功能的重要性：相关日志事件需要触发适当行动。没有告警的高质量日志，在识别安全事件时价值很有限。该类别在数据中一直会被低估，本次也再次由社区问卷参与者投票进入列表。
* **[A10:2025 - 异常条件处理不当](A10_2025-Mishandling_of_Exceptional_Conditions.md)** 是 2025 年新增类别。它包含 24 个 CWE，关注错误处理不当、逻辑错误、失效开放以及系统可能遇到的异常条件所引发的其他相关场景。

## 方法论

本版 Top Ten 仍然受数据启发，但不会盲目由数据驱动。我们基于贡献数据对 12 个类别排序，并允许社区问卷的反馈推动或突出其中两个类别。这样做有一个基本原因：审视贡献数据，本质上是在回看过去。应用安全研究人员需要投入时间识别新的漏洞并开发新的测试方法。将这些测试集成到工具和流程中可能需要数周到数年。等我们能够大规模可靠测试某个弱点时，可能已经过去多年。还有一些重要风险，我们也许永远无法可靠测试，并在数据中呈现。为了平衡这种视角，我们使用社区问卷，询问一线应用安全和开发从业者，他们看到哪些关键风险可能在测试数据中体现不足。

## 类别如何构建

与上一版 OWASP Top Ten 相比，部分类别有所变化。下面从较高层面概述这些类别变化。

在本次迭代中，我们收集数据时不再像 2021 版那样限制 CWE 范围。我们要求提供从 2021 年开始某一年度测试的应用数量，以及测试中发现至少一个 CWE 实例的应用数量。这种格式让我们能够跟踪每个 CWE 在应用总体中的普遍程度。我们会忽略频次；虽然频次在其他场景可能有必要，但它会掩盖风险在应用总体中的实际普遍性。一个应用中有 4 个 CWE 实例还是 4000 个实例，并不会影响 Top Ten 的计算。尤其是人工测试人员通常只会列出一次漏洞，无论它在应用中重复出现多少次；自动化测试框架则会把同一类漏洞的每个实例都列为独立问题。我们从 2017 年约 30 个 CWE，到 2021 年近 400 个 CWE，再到本版数据集中用于分析的 589 个 CWE。我们计划未来补充更多数据分析。CWE 数量的大幅增加也要求我们调整类别结构。

我们花了数月对 CWE 进行分组和分类，而且本可以继续投入更多时间。但总要在某个时间点停止。CWE 中既有根因类型，也有症状类型；根因类型如“加密机制失效”和“配置错误”，症状类型如“敏感数据暴露”和“拒绝服务”。我们决定尽可能关注根因，因为这更有利于提供识别和修复指导。关注根因而不是症状并不是新概念；Top Ten 一直是症状和根因的混合。CWE 本身也是症状和根因的混合；我们只是更有意识地指出这一点。本版每个类别平均包含 25 个 CWE，下限是 A03:2025-软件供应链失效和 A09:2025 安全日志记录和告警失效的 5 个 CWE，上限是 A01:2025-失效的访问控制的 40 个 CWE。我们决定将每个类别中的 CWE 数量上限设为 40。更新后的类别结构也带来额外培训价值，因为企业可以聚焦于对其语言或框架有意义的 CWE。

有人问我们，为什么不改成类似 MITRE Top 25 Most Dangerous Software Weaknesses 的“10 个 CWE 列表”。我们在类别中使用多个 CWE 主要有两个原因。第一，并不是所有 CWE 都存在于所有编程语言或框架中。这会给工具和培训/意识计划带来问题，因为 Top Ten 的部分内容可能并不适用。第二，常见漏洞往往对应多个 CWE。例如，通用注入、命令注入、跨站脚本、硬编码密码、缺少验证、缓冲区溢出、敏感信息明文存储等都有多个 CWE。不同组织或测试人员可能会使用不同 CWE。通过使用包含多个 CWE 的类别，我们可以提升基线认知，让大家了解同一通用类别名称下可能出现的不同类型弱点。在 2025 版 Top Ten 中，10 个类别共包含 248 个 CWE。在本版发布时，[MITRE 可下载字典](https://cwe.mitre.org)中共有 968 个 CWE。

## 数据如何用于选择类别

与 2021 版类似，我们使用 CVE 数据来衡量 *Exploitability* 和 *（Technical）Impact*。我们下载 OWASP Dependency Check，提取 CVSS Exploit 和 Impact 分数，并按 CVE 关联的 CWE 分组。这需要相当多的研究和处理，因为所有 CVE 都有 CVSSv2 分数，但 CVSSv2 存在一些 CVSSv3 试图修正的问题。某个时间点之后，所有 CVE 也都会分配 CVSSv3 分数。此外，CVSSv2 和 CVSSv3 的评分范围与公式也发生了变化。

在 CVSSv2 中，Exploit 和（技术）Impact 最高都可以达到 10.0，但公式会把它们分别压低到 60% 和 40%。在 CVSSv3 中，理论最高值被限制为 Exploit 6.0、Impact 4.0。按权重计算后，CVSSv3 中 Impact 分数平均提高了将近 1.5 分，而可利用性平均降低了将近 0.5 分。

从 OWASP Dependency Check 提取的国家漏洞数据库（NVD）中，大约有 17.5 万条 CVE 记录映射到 CWE（高于 2021 年的 12.5 万条）。此外，有 643 个唯一 CWE 映射到 CVE（高于 2021 年的 241 个）。在提取的近 22 万条 CVE 中，16 万条有 CVSS v2 分数，15.6 万条有 CVSS v3 分数，6000 条有 CVSS v4 分数。许多 CVE 同时有多个分数，因此这些数量相加会超过 22 万。

对 Top Ten 2025，我们按以下方式计算平均可利用性和影响分数。我们将所有带 CVSS 分数的 CVE 按 CWE 分组，然后按拥有 CVSSv3 的数据比例以及剩余 CVSSv2 数据的比例，对可利用性和影响分数进行加权，得到总体平均值。我们把这些平均值映射回数据集中的 CWE，用作风险公式另一半的 Exploit 和（技术）Impact 评分。

为什么不使用 CVSS v4.0？因为它的评分算法发生了根本变化，不再像 CVSSv2 和 CVSSv3 那样容易提供 *Exploit* 或 *Impact* 分数。我们会尝试为未来版本的 Top Ten 找到使用 CVSS v4.0 评分的方法，但在 2025 版中未能及时确定可行方式。

## 为什么使用社区问卷

数据中的结果很大程度上受限于行业能够通过自动化方式测试到的内容。和有经验的 AppSec 专业人员交流时，他们会告诉你，他们发现的问题和看到的趋势还没有进入数据。人们需要时间为某些漏洞类型开发测试方法，随后还需要更多时间将这些测试自动化，并在大量应用上运行。我们发现的一切都在回看过去，可能遗漏上一年出现、但尚未进入数据的趋势。

因此，由于数据并不完整，我们只从数据中选择十个类别中的八个。另外两个类别来自 Top 10 社区问卷。这让一线从业者可以投票选出他们认为最高风险、但可能不在数据中（甚至可能永远无法用数据表达）的类别。

## 感谢数据贡献者

以下组织（以及几位匿名捐赠者）慷慨捐赠了超过 280 万个应用的数据，帮助我们建立了规模最大、覆盖最全面的应用安全数据集。没有你们，这不可能实现。

* Accenture (Prague)
* Anonymous (multiple)
* Bugcrowd
* Contrast Security
* CryptoNet Labs
* Intuitor SoftTech Services
* Orca Security
* Probely
* Semgrep
* Sonar
* usd AG
* Veracode
* Wallarm

## 主要作者

* Andrew van der Stock - X: [@vanderaj](https://x.com/vanderaj)
* Brian Glas - X: [@infosecdad](https://x.com/infosecdad)
* Neil Smithline - X: [@appsecneil](https://x.com/appsecneil)
* Tanya Janca - X: [@shehackspurple](https://x.com/shehackspurple)
* Torsten Gigler - Mastodon: [@torsten_gigler@infosec.exchange](https://infosec.exchange/@torsten_gigler)

## 记录问题和拉取请求

请在以下位置提交修正或问题：

### 项目链接：

* [主页](https://owasp.org/www-project-top-ten/)
* [GitHub 仓库](https://github.com/OWASP/Top10)

