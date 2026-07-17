# A07:2025 认证失效 ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## 背景

认证失效仍位列第7名，名称略有调整以更准确反映该类别中的36个CWE。尽管标准化框架带来了一些改进，但该类别自2021年以来一直保持第7位。值得注意的CWE包括 *CWE-259 使用硬编码密码*、*CWE-297: 证书与主机不匹配的不当验证*、*CWE-287: 不当认证*、*CWE-384: 会话固定* 以及 *CWE-798 使用硬编码凭证*。


## 评分表


<table>
  <tr>
   <td>映射的CWE数量
   </td>
   <td>最大发生率
   </td>
   <td>平均发生率
   </td>
   <td>最大覆盖率
   </td>
   <td>平均覆盖率
   </td>
   <td>平均加权利用难度
   </td>
   <td>平均加权影响
   </td>
   <td>总发生次数
   </td>
   <td>总CVE数量
   </td>
  </tr>
  <tr>
   <td>36
   </td>
   <td>15.80%
   </td>
   <td>2.92%
   </td>
   <td>100.00%
   </td>
   <td>37.14%
   </td>
   <td>7.69
   </td>
   <td>4.44
   </td>
   <td>1,120,673
   </td>
   <td>7,147
   </td>
  </tr>
</table>



## 描述

当攻击者能够欺骗系统，将无效或错误的用户识别为合法用户时，便存在此漏洞。如果应用程序存在以下情况，则可能存在认证弱点：

* 允许自动化攻击，例如凭证填充，攻击者利用已泄露的有效用户名和密码列表进行攻击。最近，此类攻击已扩展到包括混合密码攻击凭证填充（也称为密码喷洒攻击），攻击者使用泄露凭证的变体或增量来获取访问权限，例如尝试 Password1!、Password2!、Password3! 等。

* 允许暴力破解或其他自动化、脚本化攻击，且未快速阻止。

* 允许使用默认、弱密码或常见密码，例如 "Password1" 或用户名 "admin" 搭配密码 "admin"。

* 允许用户使用已知已泄露的凭证创建新账户。

* 允许使用薄弱或无效的凭证恢复和忘记密码流程，例如“基于知识的答案”，这类方法无法确保安全。

* 使用明文、加密或弱哈希密码的数据存储（参见[ A04:2025-Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)）。

* 缺少或使用无效的多因素认证。

* 在多因素认证不可用时，允许使用薄弱或无效的备用方案。

* 在URL、隐藏字段或其他客户端可访问的不安全位置暴露会话标识符。

* 成功登录后重复使用相同的会话标识符。

* 在注销或一段时间不活动后，未正确失效用户会话或认证令牌（主要是单点登录（SSO）令牌）。

* 未正确断言所提供凭证的作用域和预期受众。

## 如何预防

* 在可能的情况下，实施并强制使用多因素认证，以防止自动化的凭证填充、暴力破解和被盗凭证重用攻击。

* 在可能的情况下，鼓励并启用密码管理器，帮助用户做出更好的选择。

* 不要随产品发布或部署任何默认凭证，特别是针对管理员用户。

* 实施弱密码检查，例如针对新密码或更改后的密码，与最差的10,000个密码列表进行比对测试。

* 在创建新账户和更改密码时，针对已知泄露凭证列表进行验证（例如使用 [haveibeenpwned.com](https://haveibeenpwned.com)）。

* 根据 [National Institute of Standards and Technology (NIST) 800-63b's guidelines in section 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) 关于记忆秘密或其他现代、基于证据的密码策略，调整密码长度、复杂性和轮换策略。

* 除非怀疑存在泄露，否则不要强制用户轮换密码。如果怀疑存在泄露，立即强制重置密码。

* 确保注册、凭证恢复和API路径通过为所有结果返回相同消息（“无效的用户名或密码。”）来强化，防止账户枚举攻击。

* 限制或逐步增加失败登录尝试的延迟，但注意不要造成拒绝服务场景。记录所有失败情况，并在检测到或怀疑存在凭证填充、暴力破解或其他攻击时提醒管理员。

* 使用服务器端、安全、内置的会话管理器，在登录后生成具有高熵的新随机会话ID。会话标识符不应出现在URL中，应安全存储在安全cookie中，并在注销、空闲和绝对超时后失效。

* 理想情况下，使用预先构建且值得信赖的系统来处理认证、身份和会话管理。尽可能通过购买和使用经过强化且充分测试的系统来转移此风险。

* 验证所提供凭证的预期用途，例如对于JWT，验证 `aud`、`iss` 声明和作用域。


## 示例攻击场景

**场景 #1：** 凭证填充，即使用已知用户名和密码组合列表，现在是一种非常常见的攻击。最近，攻击者被发现会根据常见的人类行为对密码进行“增量”或其他调整。例如，将 'Winter2025' 改为 'Winter2026'，或将 'ILoveMyDog6' 改为 'ILoveMyDog7' 或 'ILoveMyDog5'。这种调整密码尝试的方式称为混合凭证填充攻击或密码喷洒攻击，其效果甚至可能比传统版本更有效。如果应用程序未实施针对自动化威胁（暴力破解、脚本或机器人）或凭证填充的防御措施，则该应用程序可能被用作密码验证器，以判断凭证是否有效并获取未授权访问。

**场景 #2：** 大多数成功的认证攻击是由于持续使用密码作为唯一认证因素而发生的。曾经被视为最佳实践的密码轮换和复杂性要求，反而鼓励用户重用密码和使用弱密码。建议组织根据NIST 800-63停止这些做法，并在所有重要系统上强制使用多因素认证。

**场景 #3：** 应用程序会话超时未正确实现。用户使用公共计算机访问应用程序，没有选择“注销”，而是直接关闭浏览器标签页离开。另一个例子是，如果单点登录（SSO）会话无法通过单点注销（SLO）关闭。也就是说，一次登录会登录到多个系统，例如邮件阅读器、文档系统和聊天系统。但注销只发生在当前系统。如果攻击者在受害者认为已成功注销后使用同一浏览器，但用户仍在某些应用程序中保持认证状态，那么攻击者就可以访问受害者的账户。同样的问题也可能发生在办公室和企业中，当敏感应用程序未正确退出，而同事（临时）访问了未锁定的计算机时。

## 参考资料

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## 映射的CWE列表

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)