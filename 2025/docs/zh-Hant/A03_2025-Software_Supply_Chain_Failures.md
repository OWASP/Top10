# A03:2025 软件供应链失效 ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## 背景

该类别在 Top 10 社区问卷中排名第一，正好有 50% 的受访者将其列为第 1 位。自 2013 年 Top 10 中首次以“A9 - 使用含有已知漏洞的组件”出现以来，该风险范围已经扩大到包括所有供应链失效，而不只是涉及已知漏洞的情况。尽管范围扩大，供应链失效仍然难以识别，只有 11 个通用漏洞与暴露（CVE）拥有相关 CWE。不过，一旦在贡献数据中被测试并报告，本类别的平均发生率最高，达到 5.19%。相关 CWE 包括 *CWE-477：使用过时函数*、*CWE-1104：使用无人维护的第三方组件*、*CWE-1329：依赖不可更新的组件* 和 *CWE-1395：依赖存在漏洞的第三方组件*。

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

软件供应链失效是指在构建、分发或更新软件的过程中发生故障或其他妥协。它们通常由第三方代码、工具或系统依赖的其他组件中的漏洞或恶意变更引起。

如果出现以下情况，你很可能存在风险：

* 没有仔细跟踪所用所有组件的版本（客户端和服务端都包括）。这包括直接使用的组件以及嵌套的传递依赖。
* 软件存在漏洞、不受支持或已经过时。这包括操作系统、Web/应用服务器、数据库管理系统（DBMS）、应用、API 和所有组件、运行时环境及库。
* 没有定期扫描漏洞，也没有订阅与所用组件相关的安全公告。
* 没有变更管理流程，或没有跟踪供应链内部的变更，包括 IDE、IDE 扩展和更新、组织代码仓库变更、沙箱、镜像和库仓库、工件创建和存储方式等。供应链的每个部分都应记录，尤其是变更。
* 没有加固供应链的每个部分，尤其是访问控制和最小权限应用。
* 供应链系统没有职责分离。任何一个人都不应能在无人监督的情况下编写代码并一路推进到生产环境。
* 在技术栈任何部分使用来自不受信任来源的组件，或这些组件能够影响生产环境。
* 没有基于风险并及时修复或升级底层平台、框架和依赖。在补丁修复作为月度或季度变更控制任务执行的环境中，这种情况很常见，会让组织在漏洞修复前暴露数天或数月。
* 软件开发人员没有测试已更新、升级或打补丁的库的兼容性。
* 没有保护系统每个部分的配置（参见 [A02:2025-安全配置错误](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)）。
* CI/CD 流水线的安全性弱于它构建和部署的系统，尤其是流水线复杂时。

## 如何预防

应建立补丁管理流程，用于：

* 集中生成并管理整个软件的 Software Bill of Materials（SBOM）。
* 不只跟踪直接依赖，也跟踪它们的传递依赖，并逐层继续跟踪。
* 通过移除未使用依赖、不必要功能、组件、文件和文档来减少攻击面。
* 使用 OWASP Dependency Track、OWASP Dependency Check、retire.js 等工具，持续盘点客户端和服务端组件（例如框架、库）及其依赖的版本。
* 持续监控通用漏洞与暴露（CVE）、国家漏洞数据库（NVD）和[开源漏洞（OSV）](https://osv.dev/)等来源，发现所用组件中的漏洞。使用软件组成分析、软件供应链或面向安全的 SBOM 工具来自动化该流程。订阅与所用组件相关的安全漏洞告警。
* 只通过安全链路从官方（可信）来源获取组件。优先使用签名包，以降低纳入被修改的恶意组件的可能性（参见 [A08:2025-软件和数据完整性失效](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)）。
* 有意识地选择所使用的依赖版本，只在确有需要时升级。
* 监控无人维护或不再为旧版本提供安全补丁的库和组件。如果无法打补丁，考虑迁移到替代方案。如果仍不可行，考虑部署虚拟补丁来监控、检测或防护已发现的问题。
* 定期更新 CI/CD、IDE 和其他开发者工具。
* 避免同时向所有系统部署更新。使用分阶段发布或金丝雀发布，在可信供应商被攻陷时限制暴露范围。

应建立变更管理流程或跟踪系统，用于跟踪以下内容的变更：

* CI/CD 设置（所有构建工具和流水线）
* 代码仓库
* 沙箱区域
* 开发者 IDE
* SBOM 工具及创建的工件
* 日志系统和日志
* 第三方集成，例如 SaaS
* 工件仓库
* 容器镜像仓库

加固以下系统，包括启用 MFA 并锁定 IAM：

* 代码仓库（包括不提交 secret、保护分支、备份）
* 开发者工作站（定期打补丁、MFA、监控等）
* 构建服务器和 CI/CD（职责分离、访问控制、签名构建、按环境限定的 secret、防篡改日志等）
* 工件（通过来源证明、签名和时间戳确保完整性；在各环境中提升工件而不是重新构建；确保构建不可变）
* 基础设施即代码（像所有代码一样管理，包括使用 PR 和版本控制）

每个组织都必须确保在应用或资产组合的整个生命周期中，持续监控、分级处理并应用更新或配置变更。

## 攻击场景示例

**场景 #1：** 可信供应商被恶意软件攻陷，导致你升级时计算机系统也被攻陷。最著名的例子可能是：

* 2019 年 SolarWinds 攻陷事件，约 18,000 个组织受到影响。[https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**场景 #2：** 可信供应商被攻陷，使其只在特定条件下表现出恶意行为。

* 2025 年 Bybit 15 亿美元盗窃事件由[钱包软件中的供应链攻击](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/)引起，该攻击只在目标钱包被使用时执行。

**场景 #3：** 2025 年的 [`Shai-Hulud` 供应链攻击](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)是首个成功自传播的 npm 蠕虫。攻击者植入热门软件包的恶意版本，并利用 post-install 脚本收集敏感数据并外传到公开 GitHub 仓库。该恶意软件还会检测受害环境中的 npm 令牌，并自动使用这些令牌向任何可访问的软件包推送恶意版本。在 npm 阻断前，该蠕虫影响了超过 500 个软件包版本。这次供应链攻击高级、传播迅速、破坏性强，并且通过瞄准开发者机器表明，开发者本身已经成为供应链攻击的首要目标。

**场景 #4：** 组件通常以与应用本身相同的权限运行，因此任何组件中的缺陷都可能造成严重影响。此类缺陷可能是意外的（例如编码错误），也可能是有意的（例如组件中的后门）。一些已发现的可利用组件漏洞示例包括：

* CVE-2017-5638，Struts 2 远程代码执行漏洞，允许在服务器上执行任意代码，并被认为导致了重大安全事件。
* CVE-2021-44228（“Log4Shell”），Apache Log4j 远程代码执行零日漏洞，被认为与勒索软件、加密货币挖矿和其他攻击活动有关。

## 参考资料

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)

## 映射的 CWE 列表

* [CWE-447 使用过时函数](https://cwe.mitre.org/data/definitions/447.html)
* [CWE-1035 2017 年 OWASP 十大 A9：使用含有已知漏洞的组件](https://cwe.mitre.org/data/definitions/1035.html)
* [CWE-1104 使用无人维护的第三方组件](https://cwe.mitre.org/data/definitions/1104.html)
* [CWE-1329 依赖不可更新的组件](https://cwe.mitre.org/data/definitions/1329.html)
* [CWE-1357 依赖可信度不足的组件](https://cwe.mitre.org/data/definitions/1357.html)
* [CWE-1395 依赖存在漏洞的第三方组件](https://cwe.mitre.org/data/definitions/1395.html)
