# A08:2021 – Software and Data Integrity Failures

# 弱点因素

| 对应的 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 相关 CVEs 总量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :------------: |
|        10        |   16.67%   |   2.05%    |    75.04%    |    45.35%    |     6.94     |     7.94     |  47,972  |     1,152      |

## 弱点简介

这是 2021 年的新类型，着重在软体更新，关键资料及持续性整合/部署(CI/CD)流程未经完整性验证之假设。同时在 CVE/CVSS 资料加权后之最高影响之一。值得注意的 CWE 包含 CWE-502：不受信任资料之反序列化，CWE-829：包含来自不受信任控制领域之功能及 CWE-494：下载未经完整性验证之程式码。

## 弱点描述

程式码或基础架构未能保护软体及资料之完整性受到破坏。举例来说，物件或资料经编码或序列化到一个对攻击者可读写之结构中将导致不安全的反序列化。另一种形式则是应用程式依赖来自于不受信任来源，典藏库及内容递送网路之外挂，函式库或模组。不安全的持续性整合/部署(CI/CD)流程则会造成潜在的未经授权存取，恶意程式码或系统破坏。最后，现在许多应用程式拥有自动更新功能，但自动更新功能在缺乏充足完整性验证功能时就下载并安装更新到处于安全状态下的应用程式。攻击者能上传自制更新档案，更新档案将传播到所有已安装之应用程式并在这些应用程式上执行。

## 弱点描述

- 确保不受信任之客户端不会收到未签署或加密之序列化资料并利用完整性检查或数位签章来侦测窜改或重放攻击。

- 利用数位签章或类似机制确保软体或资料来自预期之提供者
- 确保函式库及从属套件，例如 npm 或 Maven，是从受信任的典藏库取得。

- 使用软体供应链安全工具(例如 OWASP Dependency Check 或 OWASP CycloneDX)确保元件没有已知弱点。
- 适当地设定持续性整合/部署(CI/CD)流程的组态及存取控制以确保程式码在组建及部署流程中的完整性。

## 攻击情境范例

**情境 1 不安全的反序列化**：一个反应式应用程式呼叫 Spring Boot 微服务。程式设计师们试图确保他们的代码是不可变的。他们的解决方案是在双向所有请求讯息中包含序列化的用户状态。攻击者注意到“R00”Java 物件签章并使用 Java Serial Killer 工具(用来执行 Java 反序列化攻击)在应用程式服务器远端执行程式码。

**情境 2 未签署之更新**：许多家用路由器、机上盒、装置韧体等未以通过签署之韧体验证更新档案。未签署韧体是越来越多攻击者的目标且情况只会变得更糟。这是一个主要问题，因为只能以新版本修复此机制并期待旧版本自然淘汰，没有其他方法。

**情境 3 SolarWinds 恶意更新**：众所周知，某些国家会攻击更新机制，最近一次值得注意的是对 SolarWinds Orion 的攻击。该软体开发商拥有安全组建和更新完整性流程。尽管如此，这些流程仍被破坏并在几个月时间中向 18,000 多个组织送出高度针对性的恶意更新，其中大约 100 个组织受到了影响。这是历史上此类性质最深远、最重大的资安事件之一。

## 参考文献

- \[OWASP Cheat Sheet: Deserialization\](
  <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

- \[OWASP Cheat Sheet: Software Supply Chain Security\]()

- \[OWASP Cheat Sheet: Secure build and deployment\]()

- \[SAFECode Software Integrity Controls\](
  https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

- \[A 'Worst Nightmare' Cyberattack: The Untold Story Of The
  SolarWinds
  Hack\](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

- <https://www.manning.com/books/securing-devops>

## List of Mapped CWEs

## 对应的 CWEs 清单

CWE-345 Insufficient Verification of Data Authenticity

CWE-345 不足的资料真实性验证

CWE-353 Missing Support for Integrity Check

CWE-353 缺乏对完整性确认之支援

CWE-426 Untrusted Search Path

CWE-426 不受信任的搜寻路径

CWE-494 Download of Code Without Integrity Check

CWE-494 下载未经完整性验证之程式码

CWE-502 Deserialization of Untrusted Data

CWE-502 不受信任资料之反序列化

CWE-565 Reliance on Cookies without Validation and Integrity Checking

CWE-565 信任未经验证及完整性确认的 Cookies

CWE-784 Reliance on Cookies without Validation and Integrity Checking in
a Security Decision

CWE-784 在安全性决策中信任未经验证及完整性确认的 Cookies

CWE-829 Inclusion of Functionality from Untrusted Control Sphere

CWE-829  包含来自不受信任控制领域之功能

CWE-830 Inclusion of Web Functionality from an Untrusted Source

CWE-830  包含来自不受信任控制来源之网页功能

CWE-915 Improperly Controlled Modification of Dynamically-Determined
Object Attributes

CWE-915 动态决定物件属性于不当控制下之修改
