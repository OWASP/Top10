# A07:2021 – 认证及验证机制失效

## 弱点因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 所有相关 CVEs 数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :----------------: |
|        22        |   14.84%   |   2.55%    |    79.51%    |    45.72%    |     7.40     |     6.50     | 132,195  |       3,897        |

## 弱点描述

确认用户的身分、认证、会话(session)管理对于防止与认证相关的攻击至关重要，如果应用程式存在以下情况，则可能有认证的漏洞:

- 允许像是攻击者已经拥有有效用户名称和密码列表的撞库自动化攻击。

- 允许暴力或其他自动化攻击。

- 允许预设、脆弱、常见的密码，像是"Password1"或"admin/admin"。

- 使用脆弱或无效的认证资讯回复或忘记密码的流程，如不安全的"知识相关问答"。

- 将密码使用明码、加密或较脆弱杂凑法的方式储存(参考 A3: 2017-敏感性资料泄漏)。

- 不具有或是无效的多因素认证。

- 于 URL 中泄漏会话(session) ID(如 URL 重写)。

- 成功登入后没有轮换会话(session) ID。

- 没有正确的注销会话(session) ID。用户的会话(session)或认证 tokens(主要是单一登入(SSO)token) 没有在登出时或一段时间没活动时被适当的注销。

## 如何预防

- 在可能的情况下，实作多因素认证来防止自动化撞库攻击、暴力破解、以及遭窃认证资讯被重复利用的攻击。

- 不要交付或部署任何预设的认证资讯，特别是管理者。

- 实作脆弱密码的检查，如测试新设定或变更的密码是否存在于前 10,000 个最差密码清单。

- 将密码长度、复杂度、和轮换政策与"NIST 800-63b 第 5.1.1 节-被记忆的秘密或其他现代基于证据的密码政策"保持一致。

- 对所有结果使用相同的讯息回应，确保注册、认证资讯回复、以及 API 路径能够抵御帐号列举攻击。

- 限制或增加失败登入尝试的延迟。记录所有失败并于侦测到撞库、暴力破解或其他攻击时发出告警。

- 使用伺服器端、安全的内建会话(session)管理器，在登入后产生新的高乱数随机程度(entropy)的随机会话(session)ID。会话(session)ID 不应出现在 URL 中，必须被安全的储存，并且在登出后、闲置、超时后被注销。

## 攻击情境范例

**情境 #1:** 使用已知列表密码的撞库攻击是一种常见的攻击方式，假设应用程式没有实施自动化威胁或撞库攻击的保护，在这种情况下，应用程式会被利用为密码预报的工具来判断认证资讯是否有效。

**情境 #2:** 大多数的认证攻击是因为持续的使用密码作为唯一因素，最佳实践、密码轮换、以及复杂度的要求会鼓励用户使用和重复使用脆弱的密码。建议组织按照 NIST 800-63 停止这些做法并使用多因素认证。

**情境 #3:** 应用程式的会话超时没有被设定正确。一个用户使用公用电脑来存取应用程式时，用户没有选择"登出"而是简单的关闭浏览器分页就离开，此时一个攻击者在一小时后使用同一个浏览器，前一个用户仍然处于通过认证的状态。

## 参考文献

- [OWASP Proactive Controls: Implement Digital
  Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

- [OWASP Application Security Verification Standard: V2
  authentication](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Application Security Verification Standard: V3 Session
  Management](https://owasp.org/www-project-application-security-verification-standard)

- OWASP Testing Guide: Identity, Authentication

- [OWASP Cheat Sheet:
  Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

- OWASP Cheat Sheet: Credential Stuffing

- [OWASP Cheat Sheet: Forgot
  Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

- OWASP Cheat Sheet: Session Management

- [OWASP Automated Threats
  Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

- NIST 800-63b: 5.1.1 Memorized Secrets

## 對應的 CWEs 清單

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)
