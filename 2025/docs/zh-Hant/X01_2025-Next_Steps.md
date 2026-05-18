# 下一步

按照设计，OWASP Top 10 天然只覆盖十个最重要的风险。每一版 OWASP Top 10 都会认真考虑一些“临门一脚”的风险是否纳入，但最终它们没有入选。其他风险更普遍、影响也更大。

以下三个问题非常值得识别和修复，尤其适合正在建设成熟 AppSec 计划的组织、安全咨询公司，或希望扩展产品覆盖范围的工具厂商。

## X01:2025 应用韧性不足 { #x012025-lack-of-application-resilience }

### 背景

这是对 2021 年“拒绝服务”的重命名。之所以改名，是因为原名称描述的是症状，而不是根因。该类别关注描述韧性相关弱点的 CWE。该类别得分与 A10:2025-异常条件处理不当非常接近。相关 CWE 包括：*CWE-400：资源消耗不受控制*、*CWE-409：高压缩数据处理不当（数据放大）*、*CWE-674：递归不受控制* 和 *CWE-835：循环退出条件不可达（无限循环）*。

### 评分表

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

### 描述

该类别指应用在面对压力、故障和边界情况时存在的系统性弱点，导致应用无法从故障中恢复。当应用不能优雅地处理、承受或从意外条件、资源限制和其他不利事件中恢复时，最常见结果是可用性问题，也可能导致数据损坏、敏感数据披露、级联故障和/或安全控制绕过。

此外，[X02:2025 内存管理失效](#x022025-memory-management-failures)也可能导致应用甚至整个系统失败。

### 如何预防

要预防这类漏洞，必须为系统的失败和恢复进行设计。

* 增加限制、配额和故障转移功能，特别关注最消耗资源的操作。
* 识别资源密集型页面并提前规划：减少攻击面，尤其不要把不需要的小工具和需要大量资源（例如 CPU、内存）的功能暴露给未知或不可信用户。
* 使用允许列表和大小限制执行严格输入验证，并进行充分测试。
* 限制响应大小，永远不要把原始响应直接发回客户端（应在服务端处理）。
* 默认安全/关闭（绝不开放），默认拒绝，并在出现错误时回滚。
* 避免在请求线程中使用阻塞同步调用（使用异步/非阻塞、设置超时、设置并发限制等）。
* 仔细测试错误处理功能。
* 实施韧性模式，例如断路器、舱壁、重试逻辑和优雅降级。
* 执行性能和负载测试；如果风险承受能力允许，可加入混沌工程。
* 在合理且可负担的范围内，为冗余进行实现和架构设计。
* 实施监控、可观测性和告警。
* 按 RFC 2267 过滤无效发送方地址。
* 通过指纹、IP 或基于行为的动态方式阻断已知僵尸网络。
* 工作量证明：在*攻击者*一侧发起资源消耗型操作，使其对普通用户影响不大，但会影响试图发送大量请求的机器人。如果系统总体负载上升，尤其是对不太可信或看起来像机器人的系统，应提高工作量证明难度。
* 基于不活动时间和最终超时限制服务端会话时间。
* 限制绑定到会话的信息存储。

### 攻击场景示例

**场景 #1：** 攻击者故意消耗应用资源以触发系统失败，造成拒绝服务。这可能是内存耗尽、填满磁盘空间、CPU 饱和，或打开无尽连接。

**场景 #2：** 输入模糊测试导致构造出的响应破坏应用业务逻辑。

**场景 #3：** 攻击者针对应用依赖下手，使 API 或其他外部服务不可用，而应用无法继续运行。

### 参考资料

* [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS-RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### 映射的 CWE 列表

* [CWE-73 文件名或路径受外部控制](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 允许输入列表过于宽松](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 明文存储密码](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 权限分配错误](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 权限管理不当](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-286 用户管理错误](https://cwe.mitre.org/data/definitions/286.html)
* [CWE-311 缺少敏感数据加密](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 明文存储敏感信息](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-313 在文件或磁盘上明文存储](https://cwe.mitre.org/data/definitions/313.html)
* [CWE-316 在内存中明文存储敏感信息](https://cwe.mitre.org/data/definitions/316.html)
* [CWE-362 使用共享资源并发执行时同步不当（竞争条件）](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-382 J2EE 不良实践：使用 `System.exit()`](https://cwe.mitre.org/data/definitions/382.html)
* [CWE-419 主通道未受保护](https://cwe.mitre.org/data/definitions/419.html)
* [CWE-434 危险类型文件上传不受限制](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-436 解释冲突](https://cwe.mitre.org/data/definitions/436.html)
* [CWE-444 HTTP 请求解释不一致（HTTP 请求/响应走私）](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-451 用户界面对关键信息表述失真](https://cwe.mitre.org/data/definitions/451.html)
* [CWE-454 可信变量或数据存储受外部初始化](https://cwe.mitre.org/data/definitions/454.html)
* [CWE-472 假定不可变的网站参数受外部控制](https://cwe.mitre.org/data/definitions/472.html)
* [CWE-501 信任边界违背](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 凭据保护不足](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-525 使用含敏感信息的浏览器缓存](https://cwe.mitre.org/data/definitions/525.html)
* [CWE-539 使用包含敏感信息的持久 Cookie](https://cwe.mitre.org/data/definitions/539.html)
* [CWE-598 使用带敏感查询字符串的 `GET` 请求方法](https://cwe.mitre.org/data/definitions/598.html)
* [CWE-602 在客户端强制执行服务端安全](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-628 函数调用参数指定错误](https://cwe.mitre.org/data/definitions/628.html)
* [CWE-642 关键状态数据受外部控制](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-646 依赖外部提供文件的文件名或扩展名](https://cwe.mitre.org/data/definitions/646.html)
* [CWE-653 隔离或分隔不当](https://cwe.mitre.org/data/definitions/653.html)
* [CWE-656 依赖隐藏实现安全](https://cwe.mitre.org/data/definitions/656.html)
* [CWE-657 违反安全设计原则](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-676 使用潜在危险函数](https://cwe.mitre.org/data/definitions/676.html)
* [CWE-693 保护机制失效](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 交互频率控制不当](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-807 安全决策依赖不可信输入](https://cwe.mitre.org/data/definitions/807.html)
* [CWE-841 行为工作流强制执行不当](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 渲染用户界面层或框架限制不当](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1022 使用带 `window.opener` 访问权限、指向不可信目标的网站链接](https://cwe.mitre.org/data/definitions/1022.html)
* [CWE-1125 攻击面过大](https://cwe.mitre.org/data/definitions/1125.html)

## X02:2025 内存管理失效 { #x022025-memory-management-failures }

### 背景

Java、C#、JavaScript/TypeScript（node.js）、Go 和“安全”Rust 等语言是内存安全的。内存管理问题往往发生在 C 和 C++ 等非内存安全语言中。尽管该类别相关 CVE 数量排名第三，但在社区问卷和数据中的得分都较低。我们认为这是因为 Web 应用相对于传统桌面应用占主导地位。内存管理漏洞经常拥有最高的 CVSS 分数。

### 评分表

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

### 描述

当应用必须自行管理内存时，很容易出错。内存安全语言的使用越来越多，但全球生产环境中仍有许多遗留系统，新的底层系统也可能需要使用非内存安全语言，还有一些 Web 应用会与大型机、IoT 设备、固件和其他可能必须自行管理内存的系统交互。代表性 CWE 包括 *CWE-120：复制缓冲区时未检查输入大小（经典缓冲区溢出）* 和 *CWE-121：基于栈的缓冲区溢出*。

内存管理失效可能发生在以下情况：

* 没有为变量分配足够内存。
* 没有验证输入，导致堆、栈或缓冲区溢出。
* 存储的数据值大于变量类型可容纳范围。
* 试图使用未分配的内存或地址空间。
* 产生差一错误（从 1 开始计数而不是从 0 开始）。
* 试图访问已经释放的对象。
* 使用未初始化变量。
* 内存泄漏，或在错误中耗尽所有可用内存，直到应用失败。

内存管理失效可能导致应用失败甚至整个系统失败，另见 [X01:2025 应用韧性不足](#x012025-lack-of-application-resilience)。

### 如何预防

预防内存管理失效的最佳方式是使用内存安全语言，例如 Rust、Java、Go、C#、Python、Swift、Kotlin、JavaScript 等。创建新应用时，应认真说服组织切换到内存安全语言，这值得学习曲线。如果进行完整重构，在可能且可行时，应推动用内存安全语言重写。

如果无法使用内存安全语言，请执行以下措施：

* 启用以下服务器功能，使内存管理错误更难被利用：地址空间布局随机化（ASLR）、数据执行保护（DEP）和结构化异常处理覆盖保护（SEHOP）。
* 监控应用是否存在内存泄漏。
* 非常谨慎地验证进入系统的所有输入，并拒绝所有不符合预期的输入。
* 研究所用语言，列出不安全和较安全函数，并与整个团队共享。如果可能，将该列表加入安全编码指南或标准。例如在 C 中，优先使用 strncpy() 而不是 strcpy()，使用 strncat() 而不是 strcat()。
* 如果语言或框架提供内存安全库，请使用它们。例如 Safestringlib 或 SafeStr。
* 尽可能使用托管缓冲区和字符串，而不是原始数组和指针。
* 接受专注于内存问题和/或所选语言的安全编码培训。告知培训师你关注内存管理失效。
* 执行代码审查和/或静态分析。
* 使用有助于内存管理的编译器工具，例如 StackShield、StackGuard 和 Libsafe。
* 对系统每个输入执行模糊测试。
* 如果进行渗透测试，告知测试人员你关注内存管理失效，并希望他们在测试时特别关注这一点。
* 修复所有编译器错误*和*警告。不要因为程序能编译就忽略警告。
* 确保底层基础设施定期打补丁、扫描和加固。
* 专门监控底层基础设施中潜在的内存漏洞和其他失效。
* 考虑使用 [canaries](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) 保护地址栈免受溢出攻击。

### 攻击场景示例

**场景 #1：** 缓冲区溢出是最著名的内存漏洞。攻击者向某个字段提交超过其可接受长度的信息，使其溢出为底层变量创建的缓冲区。攻击成功时，溢出的字符会覆盖栈指针，使攻击者能够把恶意指令插入程序。

**场景 #2：** 释放后使用（UAF）足够常见，已经是浏览器漏洞赏金中的半常见提交。设想一个 Web 浏览器处理操纵 DOM 元素的 JavaScript。攻击者构造 JavaScript 载荷，创建一个对象（例如 DOM 元素）并获取其引用。通过精心操纵，他们触发浏览器释放该对象内存，同时保留指向它的悬空指针。在浏览器意识到内存已释放之前，攻击者分配一个占用*同一*内存空间的新对象。当浏览器尝试使用原始指针时，它现在指向攻击者控制的数据。如果该指针指向虚函数表，攻击者就可以把代码执行重定向到自己的载荷。

**场景 #3：** 某网络服务接受用户输入，但没有正确验证或清理，然后直接传给日志函数。用户输入以 syslog(user_input) 而不是 syslog("%s", user_input) 的方式传给日志函数，后者没有指定格式。攻击者发送包含格式说明符的恶意载荷，例如使用 %x 读取栈内存（敏感数据泄露），或使用 %n 写入内存地址。通过串联多个格式说明符，他们可以绘制栈布局、定位重要地址，然后覆盖它们。这就是格式字符串漏洞（不受控字符串格式）。

注意：现代浏览器使用多层防御来抵御此类攻击，包括[浏览器沙箱](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing)、ASLR、DEP/NX、RELRO 和 PIE。针对浏览器的内存管理失效攻击并不容易实施。

### 参考资料

* [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing)
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### 映射的 CWE 列表

* [CWE-14 编译器移除清除缓冲区的代码](https://cwe.mitre.org/data/definitions/14.html)
* [CWE-119 内存缓冲区边界内操作限制不当](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 复制缓冲区时未检查输入大小（经典缓冲区溢出）](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 基于栈的缓冲区溢出](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 基于堆的缓冲区溢出](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-124 缓冲区下写（缓冲区下溢）](https://cwe.mitre.org/data/definitions/124.html)
* [CWE-125 越界读取](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-126 缓冲区过读](https://cwe.mitre.org/data/definitions/126.html)
* [CWE-190 整数溢出或回绕](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-191 整数下溢（回绕）](https://cwe.mitre.org/data/definitions/191.html)
* [CWE-196 无符号到有符号转换错误](https://cwe.mitre.org/data/definitions/196.html)
* [CWE-367 检查时与使用时（TOCTOU）竞争条件](https://cwe.mitre.org/data/definitions/367.html)
* [CWE-415 重复释放](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 释放后使用](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-457 使用未初始化变量](https://cwe.mitre.org/data/definitions/457.html)
* [CWE-459 清理不完整](https://cwe.mitre.org/data/definitions/459.html)
* [CWE-467 对指针类型使用 `sizeof()`](https://cwe.mitre.org/data/definitions/467.html)
* [CWE-787 越界写入](https://cwe.mitre.org/data/definitions/787.html)
* [CWE-788 访问缓冲区末尾之后的内存位置](https://cwe.mitre.org/data/definitions/788.html)
* [CWE-824 访问未初始化指针](https://cwe.mitre.org/data/definitions/824.html)

## X03:2025 不当信任 AI 生成代码（“氛围编程”）

### 背景

当前全世界都在讨论并使用 AI，软件开发人员也不例外。虽然目前还没有与 AI 生成代码相关的 CVE 或 CWE，但已有充分记录表明，AI 生成代码往往比人类编写的代码包含更多漏洞。

### 描述

我们看到软件开发实践正在变化，不仅包括在 AI 协助下编写代码，还包括几乎完全没有人工监督就编写并提交的代码（通常称为氛围编程）。就像过去不加思考地从博客或网站复制代码片段从来不是好主意一样，在这种情况下问题会被放大。好的、安全的代码片段过去和现在都很少见，并且由于系统约束，AI 在统计上可能忽略它们。

### 如何预防

我们敦促所有编写代码的人在使用 AI 时考虑以下事项：

* 你应能够阅读并完全理解自己提交的所有代码，即使这些代码由 AI 编写或从在线论坛复制。你要对自己提交的所有代码负责。
* 应彻底审查所有 AI 辅助代码中的漏洞，理想情况下既要自己查看，也要使用为此目的设计的安全工具（例如静态分析）。考虑使用 [OWASP Cheat Sheet Series: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html) 中描述的经典代码审查技术。
* 理想情况下，自己编写代码，让 AI 提出改进建议，检查 AI 的代码，并让 AI 修正，直到你对结果满意。
* 考虑使用 Retrieval Augmented Generation（RAG）服务器，放入你自己收集并审查过的安全代码示例和文档，例如组织的安全编码指南、标准或策略，并让 RAG 服务器执行任何策略或标准。
* 考虑购买为所选 AI 实施隐私和安全护栏的工具。
* 考虑购买私有 AI，理想情况下签订合同协议（包括隐私协议），明确 AI 不会使用组织的数据、查询、代码或任何其他敏感信息进行训练。
* 考虑在 IDE 和 AI 之间实现 Model Context Protocol（MCP）服务器，并配置它来强制使用组织所选的安全工具。
* 将策略和流程纳入 SDLC，告知开发人员（以及所有员工）在组织内应如何使用和不应如何使用 AI。
* 创建一份优秀且有效的提示词列表，考虑 IT 安全最佳实践。理想情况下，它们也应考虑内部安全编码指南。开发人员可以把这些提示词作为其程序的起点。
* AI 很可能成为系统开发生命周期每个阶段的一部分，既包括如何有效使用，也包括如何安全使用。请明智使用。
* 实际上，**<u>不</u>**建议在复杂功能、业务关键程序或长期使用的程序中使用氛围编程。
* 实施技术检查和保护措施，防止使用影子 AI。
* 对开发人员进行组织策略、安全 AI 使用方式以及软件开发中 AI 最佳实践的培训。

### 参考资料

* [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)

### 映射的 CWE 列表

-无-
