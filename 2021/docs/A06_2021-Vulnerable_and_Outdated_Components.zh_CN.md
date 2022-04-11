# A06:2021 – 易受攻击和已淘汰的组件(Vulnerable and Outdated Components)

## 弱点因素(Factors)

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 所有相关 CVEs 数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :----------------: |
|        3         |   27.96%   |   8.77%    |    51.78%    |    22.47%    |     5.00     |     5.00     |  30,457  |         0          |

## 弱点简介

此弱点在产业调查中排名第二，但有足够的资料让它进入前十。
易受攻击的组件是我们努力测试和评估风险的已知问题，该弱点是在 CWEs 中唯一没有任何 CVE 对应的类别，因此使用预设的 5.0 漏洞利用/影响权重。
知名的 CWEs 包括：
\*CWE-1104：使用未维护的第三方组件 以及两个 2013 年度、2017 年度 前 10 名的 CWEs。

## 弱点描述

您可能容易受到攻击：

- 如果您不知道您使用的所有组件的版本（用户端和伺服器端）。这包括您直接使用的组件以及嵌入的相依套件(nested dependencies)。

- 如果软体容易受到攻击、已不支援或已淘汰。
  包括作业系统、网页/应用程式伺服器、资料库管理系统 (DBMS)、应用程式、 API 以及所有组件、执行环境和程式库(libraries)。

- 如果您没有定期执行弱点扫瞄并订阅与您使用组件相关的资安通报。

- 如果您未凭借基于风险的方式及时修补或升级底层平台、框架和相依套件。
  这通常发生在修补工作是变更控制下的每月或每季度任务的环境中，会使组织数天甚至数月不必要地暴露于可修补的漏洞风险。
- 如果软体开发人员未测试更新、升级或修补后程式库的相容性。

- 如果你未保护组件的设定档案。 （请参阅 A05:2021 - 安全设定缺陷 Security Misconfiguration）。

## 如何预防(How to Prevent)

应该设置修补程式管理流程来：

- 删除未使用的相依套件、不必要的功能、组件、档案及文件。

- 持续使用版控工具来盘点客户端和伺服器端组件（例如框架、程式库）及相依组件的版本，如版控工具、OWASP Dependency Check、retire.js 等。
  持续监控 CVE 和 NVD 等等来源来确认是组件是否存在的漏洞。使用软体组合分析工具来自动化该流程。
  订阅您使用的组件相关的安全漏洞的资安通报。
- 持续盘点客户端和伺服器端组件（例如框架、程式库）及相依组件的版本，如版控工具、OWASP Dependency Check、retire.js 等。
  持续监控 CVE 和 NVD 等等来源来确认是组件是否存在的漏洞。
  使用软体组合分析工具来自动化该流程。
  订阅您使用的组件相关的安全漏洞的资安通报。
  使用诸如版控工具、OWASP Dependency Check、retire.js 等工具持续盘点客户端和服务器端组件（例如框架、程式库）及其相依组件的版本。
- 仅透过官方提供的安全连结来取得组件。
  优先选择已签署的更新包，以降低更新包被加入恶意组件的可能。 （请参阅 A08:2021-软体及资料完整性失效）。

- 监控未维护或未为旧版本创建安全修补程式的程式库和组件。
  如果无法修补程式，请考虑部署虚拟修补程式来监控、检测或防御已发现的特定弱点。

每个组织都必须确保在应用程式或开发专案(portfolio)的生命周期内制订持续监控、鉴别分类(triaging) 及 申请更新 或是 更改配置的计划。

## 攻击情境范例(Example Attack Scenarios)

**情境 #1：** 组件通常以与应用程式本身相同的权限运行，因此任何组件中的缺陷都可能导致严重的影响。
此类缺陷可能是偶然的（例如，编码错误）或有意的（例如，组件中的后门）。
一些已知易受攻击组件的范例为：

- CVE-2017-5638：一个 Struts 2 远端程式码执行漏洞，可以在伺服器上执行任意代码，已被归咎于重大漏洞。

- 虽然物联网 (IoT) 设备通常很难或无法修补，但修补它们可能有很高的重要性。 （例如，生物医学设备）。

有一些自动化工具可以帮助攻击者找到未修补或配置错误的系统。例如，Shodan IoT 搜索引擎可以帮助您找到存在 2014 年 4 月未修补 Heartbleed 漏洞的设备。

## 参考文献(References)

- OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling

- OWASP Dependency Check (for Java and .NET libraries)

- OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

- OWASP Virtual Patching Best Practices

- The Unfortunate Reality of Insecure Libraries

- MITRE Common Vulnerabilities and Exposures (CVE) search
-
- National Vulnerability Database (NVD)

- Retire.js for detecting known vulnerable JavaScript libraries

- Node Libraries Security Advisories

- [Ruby Libraries Security Advisory Database and Tools]()

- https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## 對應的 CWEs 清單(List of Mapped CWEs)

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
