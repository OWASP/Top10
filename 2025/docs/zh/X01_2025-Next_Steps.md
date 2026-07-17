# 后续步骤

根据设计，OWASP Top 10 本身仅限于十个最重要的风险。每个 OWASP Top 10 都有一些“临界”风险，这些风险曾被仔细考虑是否纳入，但最终未能入选。其他风险则更为普遍且影响更大。

以下三个问题非常值得努力识别和修复，对于致力于成熟应用安全计划的组织、安全咨询公司或希望扩展其产品覆盖范围的工具供应商而言，尤其如此。


## X01:2025 缺乏应用韧性

### 背景。

这是对 2021 年“拒绝服务”的重新命名。之所以重新命名，是因为它描述的是症状而非根本原因。此类别侧重于描述与韧性问题相关的弱点的 CWE。该类别的评分与 A10:2025-异常情况处理不当非常接近。相关的 CWE 包括：*CWE-400 未受控制的资源消耗、CWE-409 对高度压缩数据的处理不当（数据放大）、CWE-674 未受控制的递归* 以及 *CWE-835 具有不可达退出条件的循环（“无限循环”）。*


### 评分表。


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
   <td>平均加权利用难度
   </td>
   <td>平均加权影响
   </td>
   <td>总出现次数
   </td>
   <td>总 CVE 数量
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>20.05%
   </td>
   <td>4.55%
   </td>
   <td>86.01%
   </td>
   <td>41.47%
   </td>
   <td>7.92
   </td>
   <td>3.49
   </td>
   <td>865,066
   </td>
   <td>4,423
   </td>
  </tr>
</table>



### 描述。

此类别代表了应用程序在应对压力、故障和边缘情况时的一种系统性弱点，即无法从故障中恢复。当应用程序无法优雅地处理、承受或从意外情况、资源限制和其他不良事件中恢复时，很容易导致可用性问题（最常见），但也可能导致数据损坏、敏感数据泄露、级联故障和/或安全控制被绕过。

此外，[X02:2025 Memory Management Failures](#x022025-memory-management-failures) 也可能导致应用程序甚至整个系统发生故障。

### 如何预防

为了防止此类漏洞，您必须为系统的故障和恢复进行设计。

*   添加限制、配额和故障转移功能，特别关注最消耗资源的操作
*   识别资源密集型页面并提前规划：减少攻击面，尤其不要向未知或不受信任的用户暴露不需要的“小工具”和需要大量资源（例如 CPU、内存）的功能
*   使用白名单和大小限制执行严格的输入验证，然后进行彻底测试
*   限制响应大小，切勿将原始响应发送回客户端（在服务器端进行处理）
*   默认采用安全/封闭状态（绝不开放），默认拒绝，如果出现错误则回滚
*   避免在请求线程中阻塞同步调用（使用异步/非阻塞方式，设置超时，设置并发限制等）
*   仔细测试您的错误处理功能
*   实施韧性模式，例如断路器、隔板、重试逻辑和优雅降级
*   进行性能和负载测试；如果您有风险承受能力，可以引入混沌工程
*   在合理且负担得起的范围内，实施并设计冗余架构
*   实施监控、可观测性和告警
*   根据 RFC 2267 过滤无效的发送方地址
*   通过指纹、IP 或动态行为阻止已知的僵尸网络
*   工作量证明：在*攻击者*端发起资源消耗操作，这对普通用户影响不大，但会影响试图发送大量请求的机器人。如果系统整体负载升高，则增加工作量证明的难度，特别是对于不太可信或看起来像机器人的系统
*   根据不活动时间和最终超时限制服务器端会话时间
*   限制会话绑定的信息存储


### 示例攻击场景。

**场景 #1：** 攻击者故意消耗应用程序资源以触发系统内的故障，导致拒绝服务。这可能是内存耗尽、磁盘空间填满、CPU 饱和或打开无限连接。

**场景 #2：** 输入模糊测试导致生成精心构造的响应，从而破坏应用程序的业务逻辑。

**场景 #3：** 攻击者专注于应用程序的依赖项，使 API 或其他外部服务瘫痪，导致应用程序无法继续运行。


### 参考资料。

*   [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
*   [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
*   [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
*   [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
*   [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
*   [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
*   [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### 映射的 CWE 列表
*   [CWE-73  External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
*   [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
*   [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
*   [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
*   [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
*   [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)
*   [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
*   [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
*   [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)
*   [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
*   [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
*   [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)
*   [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
*   [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
*   [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
*   [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
*   [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)
*   [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)
*   [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
*   [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
*   [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
*   [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
*   [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
*   [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
*   [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
*   [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)
*   [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
*   [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)
*   [CWE-653 Improper Isolation or Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
*   [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)
*   [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
*   [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
*   [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
*   [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
*   [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
*   [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
*   [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
*   [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)
*   [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)


## X02:2025 内存管理失败

### 背景。

像 Java、C#、JavaScript/TypeScript (node.js)、Go 和“安全”Rust 这样的语言是内存安全的。内存管理问题往往发生在非内存安全的语言中，例如 C 和 C++。该类别的社区调查得分最低，数据得分也较低，尽管其相关的 CVE 数量排名第三。我们认为这是由于 Web 应用程序相对于传统桌面应用程序占据主导地位。内存管理漏洞通常具有最高的 CVSS 分数。


### 评分表。


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
   <td>平均加权利用难度
   </td>
   <td>平均加权影响
   </td>
   <td>总出现次数
   </td>
   <td>总 CVE 数量
   </td>
  </tr>
  <tr>
   <td>24
   </td>
   <td>2.96%
   </td>
   <td>1.13%
   </td>
   <td>55.62%
   </td>
   <td>28.45%
   </td>
   <td>6.75
   </td>
   <td>4.82
   </td>
   <td>220,414
   </td>
   <td>30,978
   </td>
  </tr>
</table>



### 描述。

当应用程序被迫自行管理内存时，很容易出错。内存安全语言的使用越来越频繁，但全球范围内仍有许多遗留系统在生产环境中运行，新的底层系统需要使用非内存安全的语言，以及与大型机、物联网设备、固件和其他可能被迫自行管理内存的系统交互的 Web 应用程序。代表性的 CWE 包括 *CWE-120 未检查输入大小的缓冲区复制（“经典缓冲区溢出”）* 和 *CWE-121 基于栈的缓冲区溢出*。

内存管理失败可能发生在以下情况：

*   没有为变量分配足够的内存
*   没有验证输入，导致堆、栈或缓冲区溢出
*   存储的数据值大于变量类型所能容纳的大小
*   尝试使用未分配的内存或地址空间
*   产生差一错误（从 1 开始计数而不是从 0 开始）
*   在对象被释放后尝试访问它
*   使用未初始化的变量
*   内存泄漏或以其他方式在出错时耗尽所有可用内存，直到应用程序失败

内存管理失败可能导致应用程序甚至整个系统发生故障，另请参见 [X01:2025 Lack of Application Resilience](#x012025-lack-of-application-resilience)


### 如何预防。

防止内存管理失败的最佳方法是使用内存安全的语言。例如 Rust、Java、Go、C#、Python、Swift、Kotlin、JavaScript 等。在创建新应用程序时，尽力说服您的组织，为了切换到内存安全语言而学习曲线是值得的。如果正在进行全面重构，在可能且可行的情况下，推动用内存安全语言重写。

如果您无法使用内存安全语言，请执行以下操作：

*   启用以下服务器功能，使内存管理错误更难以利用：地址空间布局随机化 (ASLR)、数据执行保护 (DEP) 和结构化异常处理覆盖保护 (SEHOP)。
*   监控您的应用程序是否存在内存泄漏。
*   非常仔细地验证对系统的所有输入，并拒绝所有不符合预期的输入。
*   研究您正在使用的语言，列出不安全函数和更安全函数的列表，然后与您的整个团队分享该列表。如果可能，将其添加到您的安全编码指南或标准中。例如，在 C 语言中，优先使用 strncpy() 而不是 strcpy()，优先使用 strncat() 而不是 strcat()。
*   如果您的语言或框架提供内存安全库，请使用它们。例如：Safestringlib 或 SafeStr。
*   尽可能使用托管缓冲区和字符串，而不是原始数组和指针。
*   参加专注于内存问题和/或您所选语言的安全编码培训。告知您的培训师您担心内存管理失败。
*   执行代码审查和/或静态分析。
*   使用有助于内存管理的编译器工具，例如 StackShield、StackGuard 和 Libsafe。
*   对系统的每个输入执行模糊测试。
*   如果进行了渗透测试，请告知您的测试人员您担心内存管理失败，并希望他们在测试时特别关注这一点。
*   修复所有编译器错误*和*警告。不要因为程序能编译就忽略警告。
*   确保您的基础设施定期打补丁、扫描和加固。
*   专门监控您的基础设施是否存在潜在的内存漏洞和其他故障。
*   考虑使用 [canaries](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) 来保护您的地址栈免受溢出攻击。

### 示例攻击场景。

**场景 #1：** 缓冲区溢出是最著名的内存漏洞，攻击者向一个字段提交的信息超过其所能接受的数量，从而导致为底层变量创建的缓冲区溢出。在成功的攻击中，溢出的字符会覆盖栈指针，允许攻击者将恶意指令插入您的程序。

**场景 #2：** 释放后使用 (UAF) 经常发生，以至于它已成为一种半常见的浏览器漏洞赏金提交。想象一个处理操作 DOM 元素的 JavaScript 的 Web 浏览器。攻击者精心构造一个 JavaScript 载荷，创建一个对象（例如 DOM 元素）并获取对其的引用。通过精心操作，他们触发浏览器释放该对象的内存，同时保留一个指向它的悬空指针。在浏览器意识到内存已被释放之前，攻击者分配一个新对象，该对象占据*相同*的内存空间。当浏览器尝试使用原始指针时，它现在指向攻击者控制的数据。如果此指针指向虚函数表，攻击者可以将代码执行重定向到他们的载荷。

**场景 #3：** 一个接受用户输入的网络服务，没有正确验证或清理输入，然后将其直接传递给日志记录函数。用户的输入作为 syslog(user_input) 而不是 syslog("%s", user_input) 传递给日志记录函数，后者没有指定格式。攻击者发送包含格式说明符（如 %x）的恶意载荷来读取栈内存（敏感数据泄露），或使用 %n 写入内存地址。通过将多个格式说明符链接在一起，他们可以映射出栈，定位重要地址，然后覆盖它们。这将是一个格式字符串漏洞（未受控制的字符串格式）。

注意：现代浏览器使用多层防御来抵御此类攻击，包括 [browser sandboxing](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing) ASLR、DEP/NX、RELRO 和 PIE。对浏览器进行内存管理失败攻击并非易事。

### 参考资料。

*   [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
*   [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing)
*   [Project Zero Blog](https://googleprojectzero.blogspot.com)
*   [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### 映射的 CWE 列表
*   [CWE-14 Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
*   [CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
*   [CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
*   [CWE-121 Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
*   [CWE-122 Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
*   [CWE-124 Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html)
*   [CWE-125 Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
*   [CWE-126 Buffer Over-read](https://cwe.mitre.org/data/definitions/126.html)
*   [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
*   [CWE-191 Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
*   [CWE-196 Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html)
*   [CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
*   [CWE-415 Double Free](https://cwe.mitre.org/data/definitions/415.html)
*   [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)
*   [CWE-457 Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
*   [CWE-459 Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
*   [CWE-467 Use of sizeof() on a Pointer Type](https://cwe.mitre.org/data/definitions/467.html)
*   [CWE-787 Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
*   [CWE-788 Access of Memory Location After End of Buffer](https://cwe.mitre.org/data/definitions/788.html)
*   [CWE-824 Access of Uninitialized Pointer](https://cwe.mitre.org/data/definitions/824.html)



## X03:2025 对 AI 生成代码的不当信任（“氛围编码”