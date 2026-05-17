# A07:2025 认证失效 ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景

认证失效保持第 7 位，名称略有变化，以更准确地反映本类别中的 36 个 CWE。尽管标准化框架带来了一些好处，本类别仍保持了 2021 年的第 7 位。值得关注的 CWE 包括 *CWE-259：使用硬编码密码*、*CWE-297：证书主机不匹配验证不当*、*CWE-287：认证不当*、*CWE-384：会话固定* 和 *CWE-798：使用硬编码凭据*。

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

当攻击者能够欺骗系统，使系统把无效或错误用户识别为合法用户时，就存在该漏洞。如果应用存在以下情况，可能存在认证弱点：

* 允许凭据填充等自动化攻击，即攻击者拥有一批泄露的有效用户名和密码。近期此类攻击已扩展到包括混合密码攻击凭据填充（也称为密码喷洒攻击），攻击者会使用泄露凭据的变体或递增形式来尝试访问，例如尝试 Password1!、Password2!、Password3! 等。

* 允许暴力破解或其他自动化脚本攻击，且不能快速阻断。

* 允许默认、弱或众所周知的密码，例如用户名为 "admin" 且密码也为 "admin"，或使用 "Password1"。

* 允许用户使用已知泄露凭据创建新账户。

* 允许使用弱或无效的凭据恢复和忘记密码流程，例如“基于知识的答案”，这类方式无法做到安全。

* 使用明文、加密或弱哈希的密码数据存储（参见 [A04:2025-加密机制失效](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)）。

* 缺少多因素认证，或多因素认证无效。

* 在多因素认证不可用时，允许使用弱或无效的回退机制。

* 在 URL、隐藏字段或客户端可访问的其他不安全位置暴露会话标识符。

* 成功登录后重复使用同一个会话标识符。

* 在登出或一段时间不活动后，没有正确使用户会话或认证令牌（主要是单点登录（SSO）令牌）失效。

* 没有正确声明所提供凭据的作用域和预期受众。

## 如何预防

* 在可行时，实现并强制使用多因素认证，以防止自动化凭据填充、暴力破解和被盗凭据复用攻击。

* 在可行时，鼓励并支持使用密码管理器，帮助用户做出更好的选择。

* 不要随产品交付或部署任何默认凭据，尤其是管理员用户的默认凭据。

* 实施弱密码检查，例如将新密码或修改后的密码与最差的前 10,000 个密码列表比对。

* 在创建新账户和修改密码时，对照已知泄露凭据列表进行验证（例如使用 [haveibeenpwned.com](https://haveibeenpwned.com)）。

* 让密码长度、复杂度和轮换策略符合 [National Institute of Standards and Technology (NIST) 800-63b 第 5.1.1 节](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets)中关于记忆密钥的指南，或其他现代、基于证据的密码策略。

* 除非怀疑已发生泄露，不要强迫用户定期轮换密码。如果怀疑发生泄露，应立即强制重置密码。

* 确保注册、凭据恢复和 API 路径通过对所有结果使用相同消息来防止账户枚举攻击（例如“用户名或密码无效。”）。

* 限制失败登录尝试或逐步增加延迟，但注意不要造成拒绝服务。记录所有失败，并在检测到或怀疑凭据填充、暴力破解或其他攻击时告警管理员。

* 使用服务端、安全、内置的会话管理器，在登录后生成新的高熵随机会话 ID。会话标识符不应出现在 URL 中，应安全地存储在安全 cookie 中，并在登出、空闲超时和绝对超时后失效。

* 理想情况下，使用预制、可信的系统处理认证、身份和会话管理。尽可能通过采购和使用经过加固且充分测试的系统来转移此风险。

* 验证所提供凭据的预期用途，例如对 JWT 验证 `aud`、`iss` 声明和作用域。

## 攻击场景示例

**场景 #1：** 凭据填充，即使用已知用户名和密码组合列表，已经是非常常见的攻击。近期发现攻击者会基于人类常见行为“递增”或调整密码。例如，把 `Winter2025` 改成 `Winter2026`，或把 `ILoveMyDog6` 改成 `ILoveMyDog7` 或 `ILoveMyDog5`。这种调整密码尝试的方式被称为混合凭据填充攻击或密码喷洒攻击，效果甚至可能超过传统版本。如果应用没有针对自动化威胁（暴力破解、脚本或机器人）或凭据填充实施防护，该应用就可能被用作密码预言机，用于判断凭据是否有效并获取未经授权的访问。

**场景 #2：** 大多数成功的认证攻击都源于继续把密码作为唯一认证因素。曾经被视为最佳实践的密码轮换和复杂度要求，会鼓励用户复用密码并使用弱密码。根据 NIST 800-63，建议组织停止这些做法，并在所有重要系统上强制使用多因素认证。

**场景 #3：** 应用会话超时实现不正确。用户使用公共计算机访问应用，但没有选择“登出”，只是关闭浏览器标签页就离开。另一个例子是，如果单点登录（SSO）会话无法通过单点登出（SLO）关闭，也会产生问题。也就是说，一次登录会让你进入邮件阅读器、文档系统和聊天系统等多个系统。但登出只发生在当前系统。如果攻击者在受害者以为自己已成功登出后使用同一个浏览器，而用户仍在某些应用中保持认证状态，攻击者就能访问受害者账户。同样问题也可能发生在办公室和企业环境中：敏感应用没有正确退出，而同事临时接触到了未锁定的电脑。

## 参考资料

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)

## 映射的 CWE 列表

* [CWE-258 配置文件中存在空密码](https://cwe.mitre.org/data/definitions/258.html)
* [CWE-259 使用硬编码密码](https://cwe.mitre.org/data/definitions/259.html)
* [CWE-287 认证不当](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-288 使用替代路径或通道绕过认证](https://cwe.mitre.org/data/definitions/288.html)
* [CWE-289 通过替代名称绕过认证](https://cwe.mitre.org/data/definitions/289.html)
* [CWE-290 通过欺骗绕过认证](https://cwe.mitre.org/data/definitions/290.html)
* [CWE-291 依赖 IP 地址进行认证](https://cwe.mitre.org/data/definitions/291.html)
* [CWE-293 使用 `Referer` 字段进行认证](https://cwe.mitre.org/data/definitions/293.html)
* [CWE-294 通过捕获重放绕过认证](https://cwe.mitre.org/data/definitions/294.html)
* [CWE-295 证书验证不当](https://cwe.mitre.org/data/definitions/295.html)
* [CWE-297 证书主机不匹配验证不当](https://cwe.mitre.org/data/definitions/297.html)
* [CWE-298 证书主机不匹配验证不当](https://cwe.mitre.org/data/definitions/298.html)
* [CWE-299 证书主机不匹配验证不当](https://cwe.mitre.org/data/definitions/299.html)
* [CWE-300 通道可被非端点访问](https://cwe.mitre.org/data/definitions/300.html)
* [CWE-302 通过假定不可变数据绕过认证](https://cwe.mitre.org/data/definitions/302.html)
* [CWE-303 认证算法实现错误](https://cwe.mitre.org/data/definitions/303.html)
* [CWE-304 认证中缺少关键步骤](https://cwe.mitre.org/data/definitions/304.html)
* [CWE-305 通过主要弱点绕过认证](https://cwe.mitre.org/data/definitions/305.html)
* [CWE-306 关键功能缺少认证](https://cwe.mitre.org/data/definitions/306.html)
* [CWE-307 对过多认证尝试限制不当](https://cwe.mitre.org/data/definitions/307.html)
* [CWE-308 使用单因素认证](https://cwe.mitre.org/data/definitions/308.html)
* [CWE-309 使用密码系统作为主认证方式](https://cwe.mitre.org/data/definitions/309.html)
* [CWE-346 来源验证错误](https://cwe.mitre.org/data/definitions/346.html)
* [CWE-350 安全关键操作依赖反向 DNS 解析](https://cwe.mitre.org/data/definitions/350.html)
* [CWE-384 会话固定](https://cwe.mitre.org/data/definitions/384.html)
* [CWE-521 弱密码要求](https://cwe.mitre.org/data/definitions/521.html)
* [CWE-613 会话过期不足](https://cwe.mitre.org/data/definitions/613.html)
* [CWE-620 密码变更未验证](https://cwe.mitre.org/data/definitions/620.html)
* [CWE-640 忘记密码恢复机制薄弱](https://cwe.mitre.org/data/definitions/640.html)
* [CWE-798 使用硬编码凭据](https://cwe.mitre.org/data/definitions/798.html)
* [CWE-940 通信通道来源验证不当](https://cwe.mitre.org/data/definitions/940.html)
* [CWE-941 通信通道目标指定错误](https://cwe.mitre.org/data/definitions/941.html)
* [CWE-1390 弱认证](https://cwe.mitre.org/data/definitions/1390.html)
* [CWE-1391 使用弱凭据](https://cwe.mitre.org/data/definitions/1391.html)
* [CWE-1392 使用默认凭据](https://cwe.mitre.org/data/definitions/1392.html)
* [CWE-1393 使用默认密码](https://cwe.mitre.org/data/definitions/1393.html)
