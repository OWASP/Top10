# A04:2025 加密机制失效 ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景

该弱点排名下降两位至第 4 位，重点关注缺少加密、加密强度不足、加密密钥泄露以及相关错误。在本风险中，几个最常见的通用弱点枚举（CWE）涉及使用弱伪随机数生成器：*CWE-327：使用已破解或有风险的加密算法*、*CWE-331：熵不足*、*CWE-1241：随机数生成器中使用可预测算法* 和 *CWE-338：使用加密强度不足的伪随机数生成器（PRNG）*。

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
   <td>32
   </td>
   <td>13.77%
   </td>
   <td>3.80%
   </td>
   <td>100.00%
   </td>
   <td>47.74%
   </td>
   <td>7.23
   </td>
   <td>3.90
   </td>
   <td>1,665,348
   </td>
   <td>2,185
   </td>
  </tr>
</table>

## 描述

一般而言，所有传输中的数据都应在[传输层](https://en.wikipedia.org/wiki/Transport_layer)（[OSI 层](https://en.wikipedia.org/wiki/OSI_model)第 4 层）加密。过去的障碍，例如 CPU 性能和私钥/证书管理，现在已经因 CPU 具备加速加密的指令（例如 [AES 支持](https://en.wikipedia.org/wiki/AES_instruction_set)）而缓解；私钥和证书管理也因 [LetsEncrypt.org](https://LetsEncrypt.org) 等服务而简化，主要云厂商还为各自平台提供了集成程度更高的证书管理服务。

除了保护传输层，还需要判断哪些数据需要静态加密，以及哪些数据需要在传输中额外加密（位于[应用层](https://en.wikipedia.org/wiki/Application_layer)，OSI 第 7 层）。例如，密码、信用卡号、健康记录、个人信息和商业秘密都需要额外保护，尤其是这些数据受隐私法律（例如欧盟《通用数据保护条例》（GDPR））或 PCI 数据安全标准（PCI DSS）等法规约束时。对所有此类数据，应考虑：

* 是否在默认配置或旧代码中使用了过时或弱加密算法或协议？
* 是否使用默认加密密钥、生成弱加密密钥、重复使用密钥，或缺少适当的密钥管理和轮换？
* 加密密钥是否被提交到源代码仓库？
* 是否未强制加密，例如是否缺少任何 HTTP 头（浏览器）安全指令或头？
* 是否正确验证接收到的服务器证书及其信任链？
* 初始化向量是否被忽略、重复使用，或未按加密模式要求足够安全地生成？是否使用了 ECB 等不安全运行模式？在更适合使用认证加密时，是否只使用普通加密？
* 是否在没有基于密码的密钥派生函数的情况下，把密码用作加密密钥？
* 是否使用了并非为满足加密要求而设计的随机性？即使选择了正确函数，是否需要开发人员提供种子？如果不需要，开发人员是否用熵/不可预测性不足的种子覆盖了内置的强种子功能？
* 是否使用了 MD5 或 SHA1 等已弃用哈希函数，或在需要加密哈希函数时使用了非加密哈希函数？
* 加密错误消息或侧信道信息是否可被利用，例如填充预言机攻击？
* 加密算法是否可以被降级或绕过？

参见 ASVS 中关于 Cryptography（V11）、Secure Communication（V12）和 Data Protection（V14）的参考资料。

## 如何预防

至少执行以下事项，并参考资料进一步确认：

* 对应用处理、存储或传输的数据进行分类和标记。识别哪些数据根据隐私法律、监管要求或业务需求属于敏感数据。
* 将最敏感的密钥存储在硬件或云端 HSM 中。
* 尽可能使用可信的加密算法实现。
* 不要不必要地存储敏感数据。尽快丢弃它，或使用符合 PCI DSS 的令牌化甚至截断。不保留的数据不会被窃取。
* 确保所有敏感数据在静态状态下加密。
* 确保使用最新且强健的标准算法、协议和密钥；使用适当的密钥管理。
* 只使用 TLS 1.2 及以上协议加密所有传输中数据，使用具备前向保密（FS）的密码套件，停止支持 CBC 分组密码，支持量子密钥交换算法。对 HTTPS 使用 HTTP Strict Transport Security（HSTS）强制加密。用工具检查所有配置。
* 对包含敏感数据的响应禁用缓存。这包括 CDN、Web 服务器以及任何应用缓存（例如 Redis）。
* 按数据分类应用所需安全控制。
* 不要使用 FTP 和 STARTTLS 等未加密协议。避免使用 SMTP 传输机密数据。
* 使用带工作因子（延迟因子）的强自适应加盐哈希函数存储密码，例如 Argon2、yescrypt、scrypt 或 PBKDF2-HMAC-SHA-512。对使用 bcrypt 的遗留系统，可参考 [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) 获取更多建议。
* 初始化向量必须按运行模式适当选择。这可能意味着使用 CSPRNG（加密安全伪随机数生成器）。对需要 nonce 的模式，初始化向量（IV）不一定需要 CSPRNG。任何情况下，同一个固定密钥下 IV 都不应重复使用。
* 始终使用认证加密，而不是只使用加密。
* 密钥应以加密随机方式生成，并以字节数组形式存储在内存中。如果使用密码，则必须通过适当的基于密码的密钥派生函数转换成密钥。
* 确保在适当位置使用加密随机性，并且没有用可预测或低熵方式设种子。大多数现代 API 不需要开发人员为 CSPRNG 提供种子即可安全使用。
* 避免已弃用的加密函数、分组构建方法和填充方案，例如 MD5、SHA1、Cipher Block Chaining Mode（CBC）、PKCS number 1 v1.5。
* 通过安全专家、专门工具或两者共同审查，确保设置和配置满足安全要求。
* 你需要现在就为后量子密码（PQC）做准备，参见 ENISA 参考资料，使高风险系统最迟在 2030 年底前处于安全状态。

## 攻击场景示例

**场景 #1**：某站点没有为所有页面使用或强制使用 TLS，或支持弱加密。攻击者监控网络流量（例如在不安全无线网络中），将连接从 HTTPS 降级为 HTTP，拦截请求并窃取用户会话 cookie。随后攻击者重放该 cookie，劫持用户的（已认证）会话，访问或修改用户私有数据。攻击者也可能篡改所有传输数据，例如修改转账收款方。

**场景 #2**：密码数据库使用未加盐或简单哈希存储所有人的密码。文件上传缺陷允许攻击者获取密码数据库。所有未加盐哈希都可以通过预计算哈希彩虹表暴露。由简单或快速哈希函数生成的哈希即使加盐，也可能被 GPU 破解。

## 参考资料

* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data ](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS): ](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12, ](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

## 映射的 CWE 列表

* [CWE-261 密码编码强度弱](https://cwe.mitre.org/data/definitions/261.html)
* [CWE-296 证书信任链跟随不当](https://cwe.mitre.org/data/definitions/296.html)
* [CWE-319 明文传输敏感信息](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-320 密钥管理错误（已禁用）](https://cwe.mitre.org/data/definitions/320.html)
* [CWE-321 使用硬编码加密密钥](https://cwe.mitre.org/data/definitions/321.html)
* [CWE-322 未进行实体认证的密钥交换](https://cwe.mitre.org/data/definitions/322.html)
* [CWE-323 加密中重复使用一次性随机数或密钥对](https://cwe.mitre.org/data/definitions/323.html)
* [CWE-324 使用已过期密钥](https://cwe.mitre.org/data/definitions/324.html)
* [CWE-325 缺少必需的加密步骤](https://cwe.mitre.org/data/definitions/325.html)
* [CWE-326 加密强度不足](https://cwe.mitre.org/data/definitions/326.html)
* [CWE-327 使用已破解或有风险的加密算法](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-328 可逆的单向哈希](https://cwe.mitre.org/data/definitions/328.html)
* [CWE-329 CBC 模式未使用随机 IV](https://cwe.mitre.org/data/definitions/329.html)
* [CWE-330 使用随机性不足的值](https://cwe.mitre.org/data/definitions/330.html)
* [CWE-331 熵不足](https://cwe.mitre.org/data/definitions/331.html)
* [CWE-332 PRNG 中熵不足](https://cwe.mitre.org/data/definitions/332.html)
* [CWE-334 随机值空间过小](https://cwe.mitre.org/data/definitions/334.html)
* [CWE-335 伪随机数生成器（PRNG）中种子使用错误](https://cwe.mitre.org/data/definitions/335.html)
* [CWE-336 伪随机数生成器（PRNG）中使用相同种子](https://cwe.mitre.org/data/definitions/336.html)
* [CWE-337 伪随机数生成器（PRNG）中使用可预测种子](https://cwe.mitre.org/data/definitions/337.html)
* [CWE-338 使用加密强度不足的伪随机数生成器（PRNG）](https://cwe.mitre.org/data/definitions/338.html)
* [CWE-340 生成可预测数字或标识符](https://cwe.mitre.org/data/definitions/340.html)
* [CWE-342 可从先前值预测精确值](https://cwe.mitre.org/data/definitions/342.html)
* [CWE-347 加密签名验证不当](https://cwe.mitre.org/data/definitions/347.html)
* [CWE-523 凭据传输未受保护](https://cwe.mitre.org/data/definitions/523.html)
* [CWE-757 协商过程中选择较不安全算法（算法降级）](https://cwe.mitre.org/data/definitions/757.html)
* [CWE-759 使用未加盐的单向哈希](https://cwe.mitre.org/data/definitions/759.html)
* [CWE-760 使用带可预测盐值的单向哈希](https://cwe.mitre.org/data/definitions/760.html)
* [CWE-780 使用未带 OAEP 的 RSA 算法](https://cwe.mitre.org/data/definitions/780.html)
* [CWE-916 使用计算成本不足的密码哈希](https://cwe.mitre.org/data/definitions/916.html)
* [CWE-1240 使用存在风险实现的加密原语](https://cwe.mitre.org/data/definitions/1240.html)
* [CWE-1241 随机数生成器中使用可预测算法](https://cwe.mitre.org/data/definitions/1241.html)
