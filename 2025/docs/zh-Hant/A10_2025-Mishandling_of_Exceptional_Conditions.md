# A10:2025 异常条件处理不当 ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}

## 背景

异常条件处理不当是 2025 年新增类别。该类别包含 24 个 CWE，关注错误处理不当、逻辑错误、失效开放，以及系统可能遇到的异常条件所引发的其他相关场景。本类别中有一些 CWE 过去与代码质量差相关联。对我们来说，这种说法过于宽泛；我们认为，这个更具体的类别能提供更好的指导。

本类别中值得关注的 CWE 包括：*CWE-209：生成包含敏感信息的错误消息*、*CWE-234：未处理缺失参数*、*CWE-274：权限不足处理不当*、*CWE-476：空指针解引用* 和 *CWE-636：未能安全失效（失效开放）*。

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
   <td>24
   </td>
   <td>20.67%
   </td>
   <td>2.95%
   </td>
   <td>100.00%
   </td>
   <td>37.95%
   </td>
   <td>7.11
   </td>
   <td>3.81
   </td>
   <td>769,581
   </td>
   <td>3,416
   </td>
  </tr>
</table>

## 描述

软件中异常条件处理不当，是指程序未能预防、检测和响应异常且不可预测的情况，从而导致崩溃、意外行为，有时还会造成漏洞。这可能涉及以下三类失败中的一种或多种：应用没有阻止异常情况发生，没有在异常情况发生时识别它，和/或在事后响应不佳或完全不响应。

异常条件可能由缺失、薄弱或不完整的输入验证造成，也可能由没有在错误发生的函数处处理，而是在较晚、更高层级处理错误造成；还可能来自内存、权限或网络问题等意外环境状态、不一致的异常处理，或完全未处理的异常，使系统进入未知且不可预测的状态。任何时候，只要应用不确定下一条指令是什么，就已经对异常条件处理不当。难以发现的错误和异常可能长期威胁整个应用的安全。

当我们对异常条件处理不当时，可能出现许多不同安全漏洞，例如逻辑缺陷、溢出、竞争条件、欺诈交易，或与内存、状态、资源、时序、认证和授权有关的问题。这些类型的漏洞可能负面影响系统或其数据的机密性、可用性和/或完整性。攻击者会操纵应用有缺陷的错误处理来利用此类漏洞。

## 如何预防

为了正确处理异常条件，我们必须提前为这类情况做计划（预期最坏情况）。我们必须在每个可能发生系统错误的位置直接“捕获”错误，然后处理它，也就是采取有意义的行动来解决问题，并确保系统从问题中恢复。作为处理的一部分，应包括抛出错误（以用户能理解的方式告知用户）、记录事件日志，并在我们认为有必要时发出告警。还应设置全局异常处理器，以应对可能遗漏的情况。理想情况下，我们还应具备监控和/或可观测性工具或功能，用于发现重复错误或表明正在发生攻击的模式，并能触发某种响应、防御或阻断。这可以帮助我们阻止并响应专门针对错误处理弱点的脚本和机器人。

捕获并处理异常条件可以确保程序的底层基础设施不会被迫处理不可预测的情况。如果你正处于任何类型交易的中途，非常重要的一点是回滚交易的每个部分并重新开始（也称为故障关闭，failing closed）。试图从交易中途恢复，往往会造成无法恢复的错误。

在可能的情况下，尽量加入速率限制、资源配额、节流和其他限制，从源头预防异常条件。信息技术中不应存在无限制的东西，因为这会导致应用韧性不足、拒绝服务、成功的暴力破解攻击以及异常高昂的云账单。

请考虑是否应将超过一定频率的相同重复错误只输出为统计信息，显示发生次数和时间范围。该信息应追加到原始消息中，以免干扰自动化日志记录和监控，参见 [A09:2025 安全日志记录和告警失效](A09_2025-Security_Logging_and_Alerting_Failures.md)。

除此之外，我们还希望加入严格输入验证（对必须接受的潜在危险字符进行清理或转义），以及*集中式*错误处理、日志记录、监控、告警和全局异常处理器。一个应用不应有多个处理异常条件的函数，应在一个地方以相同方式执行。我们还应为本节所有建议创建项目安全需求，在项目设计阶段执行威胁建模和/或安全设计审查活动，执行代码审查或静态分析，并对最终系统执行压力、性能和渗透测试。

如果可能，整个组织应以同一种方式处理异常条件，因为这会让这项重要安全控制的代码审查和审计更容易。

## 攻击场景示例

**场景 #1：** 异常条件处理不当导致资源耗尽（拒绝服务）。如果应用在上传文件时捕获异常，但事后没有正确释放资源，每次新异常都会让资源保持锁定或不可用，直到所有资源耗尽。

**场景 #2：** 错误处理不当或数据库错误把完整系统错误暴露给用户，导致敏感数据泄露。攻击者持续制造错误，以利用敏感系统信息构造更好的 SQL 注入攻击。用户错误消息中的敏感数据成为侦察信息。

**场景 #3：** 攻击者通过网络中断打断多步骤交易，可能导致金融交易状态损坏。假设交易顺序为：扣减用户账户、增加目标账户余额、记录交易。如果系统在中途出错时没有正确回滚整个交易（故障关闭），攻击者可能耗尽用户账户，或可能利用竞争条件多次向目标账户转账。

## 参考资料

OWASP MASVS-RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/)

## 映射的 CWE 列表

* [CWE-209 生成包含敏感信息的错误消息](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215 将敏感信息插入调试代码](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234 未处理缺失参数](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235 额外参数处理不当](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248 未捕获异常](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252 未检查返回值](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274 权限不足处理不当](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280 权限或特权不足处理不当](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369 除零](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390 检测到错误条件但未采取行动](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391 未检查错误条件](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394 意外状态码或返回值](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396 捕获通用异常的声明](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397 抛出通用异常的声明](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460 抛出异常后的清理不当](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476 空指针解引用](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478 多条件表达式缺少默认分支](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484 `switch` 中遗漏 `break` 语句](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550 服务端生成包含敏感信息的错误消息](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636 未能安全失效（失效开放）](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703 异常条件检查或处理不当](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754 异常或异常条件检查不当](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755 异常条件处理不当](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756 缺少自定义错误页面](https://cwe.mitre.org/data/definitions/756.html)
