# A04:2021 – 不安全设计

## 弱点因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 所有相关 CVEs 数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :----------------: |
|        40        |   24.19%   |   3.00%    |    77.25%    |    42.51%    |     6.46     |     6.78     | 262,407  |       2,691        |

## 弱点简介

2021 年中的一个全新类别，着重于在设计与架构中的风险。来呼吁更多使用到威胁建模、安全设计模式与参考架构。
著名的 CWE 包括下列 _CWE-209: 产生的错误信息的中包含敏感讯息_、_CWE-256: 未受保护的凭证储存方式_、_CWE-501: 违反信任边界_ 与 _CWE-522: 不足够的凭证保护_。

## 弱点描述

不安全设计是一个广泛的类别呈现许多不同的弱点，代表为"缺乏或无效的控制设计"。缺乏不安全设计是指没有控制措施。举例来说，想像一段程式码应该加密敏感资料但是没有对应的实作方法。无效的不安全设计是可以实现威胁的地方，但不足的领域（商业）逻辑验证会阻止该动作。以下个例子说，想像领域逻辑是用来处理基于收入等级的疫情减税但是并未确认所有的输入都是有正确的签名，因此提供超过原本可以获得而且更显著的减税利益。

安全设计一个文化与方法持续不断的来评估威胁并保证程式码有被稳健的设计与测试来预防已知的攻击方法。安全设计需要安全的开发生命周期、某种形式上的安全设计模式或是已完成的元件库或工具以及威胁建模。

## 如何预防

- 建立与使用安全开发生命周期并且协同应用程式安全的专业人士来评估与设计安全与隐私相关的控制措施。

- 建立与使用安全设计模式的函式库或是已完成可使用的元件。

- 使用威胁建模在关键的认证、存取控制、商业逻辑与关键缺陷上。

- 撰写单元测试与整合测试来验证所有的关键流程对威胁建模都有抵抗。

## 攻击情境范例

**情境 #1** 凭证恢复的流程或许会包含“问题与答案”，该方式是被 NIST 800-63b、OWASP ASVS 与 WASP Top 10 中禁止。 “问题与答案”无法被作为信任身份的证据因为不止一个人可能会知道答案，因此这个方法会被禁止的原因。因此此类的程式码应该被移除或是用更安全的设计来替代。

**情境 #2:** 电影院在要求押金前允许团体预订折扣并且最多有 15 名观众。攻击者可以威胁模型此流程并测试他们在一次请求中是否可以预订 600 个座位和的所有电影院，导致电影院巨大的收入损失。

**情境 #3:** 连锁零售的电子商务网站没有保护机制来对抗黄牛的机器人购买高端的显示卡再转售到拍卖网站。对于零售商与显示卡制造商产生了可怕的宣传效应并且导致与那些无法购买到显卡的爱好者间产生了不愉快。巧妙的防机器人设计与领域逻辑规则，例如短暂几秒的购买时间或许可以辨识出不可信赖的购买并且拒绝该交易。

## 參考文献

- [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

- NIST – Guidelines on Minimum Standards for Developer Verification of
  > Software  
  > https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software

## 對应的 CWEs 清单

CWE-73 External Control of File Name or Path

CWE-183 Permissive List of Allowed Inputs

CWE-209 Generation of Error Message Containing Sensitive Information

CWE-213 Exposure of Sensitive Information Due to Incompatible Policies

CWE-235 Improper Handling of Extra Parameters

CWE-256 Unprotected Storage of Credentials

CWE-257 Storing Passwords in a Recoverable Format

CWE-266 Incorrect Privilege Assignment

CWE-269 Improper Privilege Management

CWE-280 Improper Handling of Insufficient Permissions or Privileges

CWE-311 Missing Encryption of Sensitive Data

CWE-312 Cleartext Storage of Sensitive Information

CWE-313 Cleartext Storage in a File or on Disk

CWE-316 Cleartext Storage of Sensitive Information in Memory

CWE-419 Unprotected Primary Channel

CWE-430 Deployment of Wrong Handler

CWE-434 Unrestricted Upload of File with Dangerous Type

CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request
Smuggling')

CWE-451 User Interface (UI) Misrepresentation of Critical Information

CWE-472 External Control of Assumed-Immutable Web Parameter

CWE-501 Trust Boundary Violation

CWE-522 Insufficiently Protected Credentials

CWE-525 Use of Web Browser Cache Containing Sensitive Information

CWE-539 Use of Persistent Cookies Containing Sensitive Information

CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session

CWE-598 Use of GET Request Method With Sensitive Query Strings

CWE-602 Client-Side Enforcement of Server-Side Security

CWE-642 External Control of Critical State Data

CWE-646 Reliance on File Name or Extension of Externally-Supplied File

CWE-650 Trusting HTTP Permission Methods on the Server Side

CWE-653 Insufficient Compartmentalization

CWE-656 Reliance on Security Through Obscurity

CWE-657 Violation of Secure Design Principles

CWE-799 Improper Control of Interaction Frequency

CWE-807 Reliance on Untrusted Inputs in a Security Decision

CWE-840 Business Logic Errors

CWE-841 Improper Enforcement of Behavioral Workflow

CWE-927 Use of Implicit Intent for Sensitive Communication

CWE-1021 Improper Restriction of Rendered UI Layers or Frames

CWE-1173 Improper Use of Validation Framework
