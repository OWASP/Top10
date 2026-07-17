# A03:2025 软件供应链故障 ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## 背景

该类别在 Top 10 社区调查中排名第一，恰好有 50% 的受访者将其列为头号风险。自 2013 年首次以“A9 – 使用含有已知漏洞的组件”身份出现在 Top 10 中以来，该风险的范围已扩大至涵盖所有供应链故障，而不仅仅是涉及已知漏洞的故障。尽管范围有所扩大，但供应链故障仍然是一个难以识别的问题，仅有 11 个通用漏洞披露（CVE）关联了相关的 CWE。然而，在贡献数据中进行测试和报告时，该类别的平均发生率最高，达到 5.19%。相关的 CWE 包括 *CWE-477：使用过时函数、CWE-1104：使用未维护的第三方组件*、CWE-1329：*依赖不可更新的组件*，以及 *CWE-1395：依赖易受攻击的第三方组件*。


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
   <td>平均加权利用
   </td>
   <td>平均加权影响
   </td>
   <td>总出现次数
   </td>
   <td>总 CVE 数量
   </td>
  </tr>
  <tr>
   <td>6
   </td>
   <td>9.56%
   </td>
   <td>5.72%
   </td>
   <td>65.42%
   </td>
   <td>27.47%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>



## 描述

软件供应链故障是指在构建、分发或更新软件过程中出现的故障或其他破坏。它们通常由系统所依赖的第三方代码、工具或其他依赖项中的漏洞或恶意更改引起。

如果出现以下情况，您很可能存在风险：

*   您没有仔细跟踪所使用的所有组件（包括客户端和服务器端）的版本。这包括您直接使用的组件以及嵌套的（传递性）依赖项。
*   软件存在漏洞、不受支持或已过时。这包括操作系统、Web/应用服务器、数据库管理系统（DBMS）、应用程序、API 以及所有组件、运行时环境和库。
*   您没有定期扫描漏洞，也没有订阅与您所用组件相关的安全公告。
*   您没有变更管理流程或对供应链内变更的跟踪，包括跟踪 IDE、IDE 扩展和更新、组织代码仓库的变更、沙箱、镜像和库仓库、工件创建和存储方式等。供应链的每个部分都应记录在案，尤其是变更。
*   您没有强化供应链的每个部分，特别是要关注访问控制和最小权限的应用。
*   您的供应链系统没有任何职责分离。任何个人都不应能够在没有他人监督的情况下编写代码并将其一路推送到生产环境。
*   来自不可信来源的组件（涉及技术栈的任何部分）被用于或可能影响生产环境。
*   您没有以基于风险的、及时的方式修复或升级底层平台、框架和依赖项。这种情况通常发生在修补是按变更控制下的月度或季度任务进行的环境中，导致组织在修复漏洞前暴露数天或数月的不必要风险。
*   软件开发人员没有测试更新、升级或修补后的库的兼容性。
*   您没有保护系统每个部分的安全配置（参见 [A02:2025-Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)）。
*   您的 CI/CD 管道的安全性低于其构建和部署的系统，尤其是在管道复杂的情况下。


## 如何预防

应建立补丁管理流程，以：

*   集中生成和管理整个软件的软件物料清单（SBOM）。
*   不仅要跟踪您的直接依赖项，还要跟踪它们的（传递性）依赖项，以此类推。
*   通过移除未使用的依赖项、不必要的功能、组件、文件和文档来减少攻击面。
*   使用 OWASP Dependency Track、OWASP Dependency Check、retire.js 等工具，持续盘点客户端和服务器端组件（例如框架、库）及其依赖项的版本。
*   持续监控诸如通用漏洞披露（CVE）、国家漏洞数据库（NVD）以及 [Open Source Vulnerabilities (OSV)](https://osv.dev/) 等来源，以发现您所用组件中的漏洞。使用软件组合分析、软件供应链或专注于安全的 SBOM 工具来自动化此过程。订阅与您所用组件相关的安全漏洞警报。
*   仅通过安全链接从官方（可信）来源获取组件。优先选择签名包，以减少包含被篡改的恶意组件的可能性（参见 [A08:2025-软件和数据集成失效](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)）。
*   审慎选择您使用的依赖项版本，并仅在必要时进行升级。
*   监控那些未维护或不为旧版本创建安全补丁的库和组件。如果无法修补，请考虑迁移到替代方案。如果无法迁移，请考虑部署虚拟补丁来监控、检测或防御已发现的问题。
*   定期更新您的 CI/CD、IDE 以及任何其他开发者工具。
*   避免同时向所有系统部署更新。使用分阶段推出或金丝雀部署，以限制在可信供应商被攻破时的影响范围。

应建立变更管理流程或跟踪系统，以跟踪以下内容的变更：

*   CI/CD 设置（所有构建工具和管道）
*   代码仓库
*   沙箱区域
*   开发者 IDE
*   SBOM 工具及创建的工件
*   日志系统和日志
*   第三方集成，例如 SaaS
*   工件仓库
*   容器注册表

强化以下系统，包括启用 MFA 和锁定 IAM：

*   您的代码仓库（包括不检入机密、保护分支、备份）
*   开发者工作站（定期修补、MFA、监控等）
*   您的构建服务器和 CI/CD（职责分离、访问控制、签名构建、环境范围机密、防篡改日志等）
*   您的工件（通过来源、签名和时间戳确保完整性，为每个环境提升工件而非重建，确保构建不可变）
*   基础设施即代码（像所有代码一样管理，包括使用 PR 和版本控制）

每个组织都必须确保有一个持续的计划，用于在应用程序或产品组合的整个生命周期内监控、分类和应用更新或配置变更。


## 示例攻击场景

**场景 #1：** 一个可信供应商被植入恶意软件攻破，导致您在升级时计算机系统被攻破。这方面最著名的例子可能是：

*   2019 年的 SolarWinds 入侵事件，导致约 18,000 个组织被攻破。[https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**场景 #2：** 一个可信供应商被攻破，其恶意行为仅在特定条件下触发。

*   2025 年 Bybit 被盗 15 亿美元的事件是由 [a supply chain attack in wallet software](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/) 引起的，该恶意代码仅在目标钱包被使用时执行。

**场景 #3：** 2025 年的 [`Shai-Hulud` supply chain attack](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) 是第一个成功的自传播 npm 蠕虫。攻击者植入了流行软件包的恶意版本，这些版本使用后安装脚本收集并窃取敏感数据到公共 GitHub 仓库。该恶意软件还会检测受害者环境中的 npm 令牌，并自动使用它们推送任何可访问软件包的恶意版本。该蠕虫在被 npm 阻止前已传播到超过 500 个软件包版本。这次供应链攻击先进、传播迅速且破坏力强，通过针对开发者机器，表明开发者本身已成为供应链攻击的主要目标。

**场景 #4：** 组件通常以与应用程序本身相同的权限运行，因此任何组件中的缺陷都可能导致严重影响。此类缺陷可能是偶然的（例如编码错误）或故意的（例如组件中的后门）。一些被发现的可利用组件漏洞示例如下：

*   CVE-2017-5638，一个 Struts 2 远程代码执行漏洞，允许在服务器上执行任意代码，已被认为是重大数据泄露事件的元凶。
*   CVE-2021-44228（“Log4Shell”），一个 Apache Log4j 远程代码执行零日漏洞，已被认为是勒索软件、加密货币挖矿和其他攻击活动的元凶。


## 参考文献

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP 测试指南 - 映射应用程序架构 (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby 库安全公告数据库和工具
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## 映射的 CWE 列表

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)