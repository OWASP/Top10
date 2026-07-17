# A04:2025 加密机制失效 ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## 背景

该弱点下降两位至第4名，主要关注与缺乏加密、加密强度不足、加密密钥泄露及相关错误有关的问题。此风险中最常见的三种通用弱点枚举（CWE）涉及使用弱伪随机数生成器：*CWE-327 使用有缺陷或危险的加密算法、CWE-331：熵不足*、*CWE-1241：在随机数生成器中使用可预测算法*，以及 *CWE-338 使用加密强度弱的伪随机数生成器（PRNG）*。



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
   <td>平均加权利用度
   </td>
   <td>平均加权影响
   </td>
   <td>总发生次数
   </td>
   <td>总CVE数量
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

一般来说，所有传输中的数据都应在[transport layer](https://en.wikipedia.org/wiki/Transport_layer)（[OSI layer](https://en.wikipedia.org/wiki/OSI_model) 4）层进行加密。以往的性能瓶颈（如CPU性能）和私钥/证书管理问题，如今已通过支持加密加速指令（例如：[AES support](https://en.wikipedia.org/wiki/AES_instruction_set)）的CPU得到解决，而私钥和证书管理也通过[LetsEncrypt.org](https://LetsEncrypt.org)等服务得以简化，主流云厂商甚至为其特定平台提供了更紧密集成的证书管理服务。

除了保护传输层安全外，还需确定哪些数据需要静态加密，以及哪些数据在传输过程中需要额外加密（在[application layer](https://en.wikipedia.org/wiki/Application_layer)，即OSI第7层）。例如，密码、信用卡号、健康记录、个人信息和商业机密需要额外保护，特别是当这些数据受隐私法律（如欧盟通用数据保护条例GDPR）或法规（如PCI数据安全标准PCI DSS）约束时。对于所有此类数据：

* 是否在默认配置或旧代码中使用了过时或弱加密算法/协议？
* 是否使用了默认加密密钥、生成了弱加密密钥、重复使用密钥，或缺少正确的密钥管理和轮换？
* 加密密钥是否被检入源代码仓库？
* 是否未强制实施加密，例如缺少任何HTTP标头（浏览器）安全指令或标头？
* 接收到的服务器证书和信任链是否得到正确验证？
* 初始化向量是否被忽略、重复使用，或未针对加密操作模式生成足够安全的向量？是否使用了不安全的操作模式（如ECB）？在更适合使用认证加密的情况下是否仍使用普通加密？
* 在缺少基于密码的密钥派生函数时，是否将密码直接用作加密密钥？
* 是否使用了未设计为满足加密要求的随机性？即使选择了正确的函数，是否需要开发者提供种子？如果不需要，开发者是否用缺乏足够熵/不可预测性的种子覆盖了内置的强种子生成功能？
* 是否使用了已弃用的哈希函数（如MD5或SHA1），或在需要加密哈希函数时使用了非加密哈希函数？
* 加密错误消息或侧信道信息是否可被利用，例如以填充预言攻击的形式？
* 加密算法是否可被降级或绕过？

请参考ASVS：加密（V11）、安全通信（V12）和数据保护（V14）。


## 如何预防

至少执行以下操作，并参考相关参考资料：

* 对应用程序处理、存储或传输的数据进行分类和标记。根据隐私法律、法规要求或业务需求识别哪些数据是敏感的。
* 将最敏感的密钥存储在硬件或基于云的HSM中。
* 尽可能使用经过充分验证的加密算法实现。
* 不要不必要地存储敏感数据。尽快丢弃这些数据，或使用符合PCI DSS标准的令牌化甚至截断处理。未保留的数据无法被盗取。
* 确保对所有敏感数据进行静态加密。
* 确保使用最新且强大的标准算法、协议和密钥；实施正确的密钥管理。
* 仅使用不低于TLS 1.2的协议加密所有传输中的数据，使用前向保密（FS）密码套件，放弃对密码块链接（CBC）密码套件的支持，支持量子密钥交换算法。对于HTTPS，使用HTTP严格传输安全（HSTS）强制实施加密。使用工具检查所有内容。
* 对包含敏感数据的响应禁用缓存。这包括CDN、Web服务器以及任何应用程序缓存（例如Redis）中的缓存。
* 根据数据分类应用所需的安全控制措施。
* 不要使用未加密的协议（如FTP和STARTTLS）。避免使用SMTP传输机密数据。
* 使用具有工作因子（延迟因子）的强自适应加盐哈希函数存储密码，例如Argon2、yescrypt、scrypt或PBKDF2-HMAC-SHA-512。对于使用bcrypt的遗留系统，请访问[OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)获取更多建议。
* 初始化向量必须根据操作模式适当选择。这可能意味着使用CSPRNG（加密安全伪随机数生成器）。对于需要nonce的模式，初始化向量（IV）不需要CSPRNG。在所有情况下，对于固定密钥，IV绝不能重复使用。
* 始终使用认证加密，而不是仅使用普通加密。
* 密钥应通过加密随机方式生成，并以字节数组形式存储在内存中。如果使用密码，则必须通过适当的基于密码的密钥派生函数将其转换为密钥。
* 确保在适当的地方使用加密随机性，并且该随机性未以可预测的方式或低熵方式播种。大多数现代API不需要开发者播种CSPRNG即可保证安全。
* 避免使用已弃用的加密函数、块构建方法和填充方案，例如MD5、SHA1、密码块链接模式（CBC）、PKCS #1 v1.5。
* 通过安全专家或专为此目的设计的工具（或两者结合）审查设置和配置，确保其满足安全要求。
* 现在就需要为后量子密码学（PQC）做好准备，请参考（ENISA）资料，以确保高风险系统在2030年底前保持安全。


## 示例攻击场景

**场景 #1**：某个网站未对所有页面使用或强制实施TLS，或支持弱加密。攻击者监控网络流量（例如在不安全的无线网络上），将连接从HTTPS降级为HTTP，拦截请求并窃取用户的会话cookie。然后攻击者重放该cookie并劫持用户的（已认证）会话，访问或修改用户的私人数据。或者，他们可能篡改所有传输的数据，例如更改转账收款人。

**场景 #2**：密码数据库使用未加盐或简单的哈希值来存储所有人的密码。一个文件上传漏洞使攻击者能够获取密码数据库。所有未加盐的哈希值可以通过预计算哈希值的彩虹表被破解。由简单或快速哈希函数生成的哈希值（即使已加盐）也可能被GPU破解。



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


## 映射的CWE列表

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)

* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)

* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)

* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)

* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)

* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)