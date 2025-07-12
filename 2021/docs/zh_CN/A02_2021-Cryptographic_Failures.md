# A02:2021 – 加密機制失效

## 弱点因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 所有相关 CVEs 数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :----------------: |
|        29        |   46.44%   |   4.49%    |    79.33%    |    34.85%    |     7.29     |     6.81     | 233,788  |       3,075        |

## 弱点簡介

上升一个名次來到第二名，之前版本称为"敏感性资料泄漏"，更像是一种广泛的症状而非根因，本版本聚焦于密码学相关的失效(或缺乏加密)，并因此常常导致敏感资料的泄漏。著名的 CWE 包含"CWE259: Use of Hard-coded Password", "CWE-327: Broken or Risky Crypto Algorithm", 以及"CWE-331: Insufficient Entropy"。

## 弱点描述

首先确定靜态资料及资料传输的防护需求，举例來说，密码、信用卡卡号、健康记录、个资、以及需要额外保护的营业祕密...等等主要被隐私法所保护的资料，如欧盟 GDPR 或 PCIDSS 等等金融业相关的资料保护法或标准。对于这些资料需考量:

- 是否以明文形式传输任何数据? 像是 HTTP, SMTP, FTP 等等协定，使用于对外网际网络的流量是危险的。必须验证所有的內部流量，如在负载平衡器、网站服务器、或后端系统之间 。

- 是否有任何老旧或脆弱的加密演算法被预设使用或存在于较旧的程式码?

- 是否正在使用默认的加密密钥、是否生成了弱加密密钥并重复使用，是否有适当的密钥管理或轮换?加密密钥是否被写入源代码中？

- 是否未强制执行加密? 举例: HTTP headers(浏览器)是否有遗失安全相关的指令或头信息?

- 收到的服务器证书和信任链是否正确验证？

请參考 ASVS 加密(V7), 资料保护(V9), 及 SSL/TLS(V10)。

## 如何预防

至少执行以下措施，并参考相关资料:

- 对应用程式处理、存储、传输的资料进行分类，根据隐私法、法令法规、或商业需求辨认哪些为敏感性资料。

- 依照分类执行对应的控制措施。

- 非必要不储存敏感性资料，尽快舍弃或使用符合 PCIDSS 的资料记号化(tokenization)甚至截断(truncation)。 沒有被保存的数据是不会被窃取的。

- 确保将所有靜态的敏感性资料加密。

- 确认使用最新版且标准的強演算法、协定及密钥; 使用适当的密钥管理。

- 使用安全的协定加密传输中的资料，像是有完全前向保密(PFS)、服务器加密优先顺序(cipher prioritization by the server)及安全參数的 TLS。 使用如 HTTP 強制安全传输技术(HSTS)的指令強化加密。

- 针对包含敏感资料的回应停用缓存。

- 使用具有散列/延迟因素(work factor/delay factor)，如 Argon2, scrypt, bcrypt 或 PBKDF2 的強自适应性加盐散列函数來储存密码。

- 独立验证设定的有效性。

## 攻击情境范例

**情境 #1**: 有一个应用程式使用自动化资料库加密來加密资料库中的信用卡卡号，但是资料被检索时是被自动解密的，进而允许透过 SQL 注入缺陷來检索信用卡卡号明文。

**情境 #2**: 有一个站台沒有对所有页面強制使用 TLS 或支援脆弱的加密，攻击者监控网络流量(如在不安全的无线网络), 将连线从 HTTPS 降级成 HTTP，并拦截请求窃取使用者的会话(session) cookies，之后攻击者重送窃取到的会话(session) cookies 并劫持用户(认证过的)的会话，进而检索或修改使用者的隐私资料。 除了上述以外，攻击者也能修改传输的资料，如汇款收款人。

**情境 #3**: 密码资料库使用未被加盐或简单的散列函数來储存每个人的密码，一个档案上传的缺陷可以让攻击者存取密码资料库，所有未被加盐的哈希可以被预先计算好的彩虹表解密。即使加盐，由简单或快速的哈希仍能被 GPU 破解。

## 參考文獻

- [OWASP Proactive Controls: Protect Data
  Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

- [OWASP Application Security Verification Standard (V7,
  9, 10)](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Cheat Sheet: Transport Layer
  Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

- [OWASP Cheat Sheet: User Privacy
  Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

- OWASP Cheat Sheet: Password and Cryptographic Storage

- [OWASP Cheat Sheet:
  HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

- OWASP Testing Guide: Testing for weak cryptography

## 对应的 CWEs 清單

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
