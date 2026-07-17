# A10:2025 异常条件处理不当 ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## 背景

异常条件处理不当是2025年的一个新类别。该类别包含24个CWE，重点关注不当的错误处理、逻辑错误、开放失败，以及由异常条件和系统可能遇到的其他相关场景。此类别包含一些以前与代码质量差相关的CWE。对我们来说，这过于笼统；我们认为，这个更具体的类别能提供更好的指导。

此类别中值得注意的CWE包括：*CWE-209 包含敏感信息的错误消息生成、CWE-234 未能处理缺失参数、CWE-274 权限不足处理不当、CWE-476 空指针解引用* 和 *CWE-636 未能安全失败（'开放失败'）*。


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
   <td>总出现次数
   </td>
   <td>总CVE数量
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

当程序未能预防、检测和响应异常及不可预测的情况时，就会发生软件中的异常条件处理不当，这会导致崩溃、意外行为，有时还会引发漏洞。这可能涉及以下三个失败点中的一个或多个：应用程序未能阻止异常情况的发生、未能识别正在发生的情况，和/或在事后应对不力或根本没有应对。

 

异常条件可能由以下原因引起：缺失、糟糕或不完整的输入验证；在函数发生处延迟或高层级处理错误；意外的环境状态，如内存、权限或网络问题；不一致的异常处理；或者异常根本未被处理，导致系统陷入未知和不可预测的状态。每当应用程序不确定其下一步指令时，就发生了异常条件处理不当。难以发现的错误和异常可能会长期威胁整个应用程序的安全。

 

当我们处理异常条件不当时，可能会产生许多不同的安全漏洞，例如逻辑错误、溢出、竞态条件、欺诈交易，或与内存、状态、资源、时序、身份验证和授权相关的问题。这些类型的漏洞可能会对系统或其数据的机密性、可用性和/或完整性产生负面影响。攻击者利用应用程序有缺陷的错误处理来攻击此漏洞。


## 如何预防

为了正确处理异常条件，我们必须为这些情况做好计划（做最坏的打算）。我们必须直接在可能发生系统错误的每个地方“捕获”所有可能的系统错误，然后处理它们（这意味着采取有意义的措施来解决问题，并确保我们从问题中恢复）。作为处理的一部分，我们应该包括抛出错误（以可理解的方式通知用户）、记录事件，以及在我们认为合理时发出警报。我们还应该有一个全局异常处理程序，以防我们遗漏了某些情况。理想情况下，我们还应该拥有监控和/或可观察性工具或功能，用于监视重复出现的错误或表明正在发生攻击的模式，这些工具或功能可以发出某种响应、防御或阻止。这可以帮助我们阻止和响应针对我们错误处理弱点的脚本和机器人。

 

捕获和处理异常条件可确保我们程序的基础设施不会被迫处理不可预测的情况。如果你正在进行任何类型的交易，那么回滚交易的每个部分并重新开始（也称为安全失败）是极其重要的。试图在交易中途恢复往往是造成不可挽回错误的原因。

 

只要有可能，就添加速率限制、资源配额、节流和其他限制，以首先防止异常条件的发生。信息技术中没有任何东西应该是无限的，因为这会导致应用程序缺乏弹性、拒绝服务、暴力破解攻击成功以及产生巨额的云账单。

考虑是否应该将超过一定频率的相同重复错误仅作为统计信息输出，显示它们发生的频率和时间范围。此信息应附加到原始消息中，以免干扰自动日志记录和监控，请参见 [A09:2025 Security Logging & Alerting Failures](A09_2025-Security_Logging_and_Alerting_Failures.md)。

除此之外，我们还需要包含严格的输入验证（对我们必须接受的可能危险字符进行清理或转义），以及*集中式*的错误处理、日志记录、监控和警报，以及一个全局异常处理程序。一个应用程序不应有多个处理异常条件的函数，而应在同一个地方以相同的方式执行。我们还应该为本节中的所有建议创建项目安全要求，在项目设计阶段执行威胁建模和/或安全设计审查活动，执行代码审查或静态分析，并对最终系统进行压力测试、性能测试和渗透测试。

 

如果可能，你的整个组织应以相同的方式处理异常条件，因为这样可以更轻松地审查和审计代码，以发现这一重要安全控制措施中的错误。


## 示例攻击场景

**场景 #1：** 通过异常条件处理不当导致的资源耗尽（拒绝服务）。如果应用程序在上传文件时捕获异常，但之后没有正确释放资源，就可能发生这种情况。每个新异常都会导致资源被锁定或无法使用，直到所有资源被耗尽。

**场景 #2：** 通过不当处理或数据库错误导致的敏感数据泄露，将完整的系统错误信息暴露给用户。攻击者持续制造错误，以便利用敏感的系统信息发起更有效的SQL注入攻击。用户错误消息中的敏感数据是侦察信息。

**场景 #3：** 攻击者通过网络中断中断多步骤交易，可能导致金融交易中的状态损坏。假设交易顺序是：借记用户账户、贷记目标账户、记录交易。如果系统在交易中途出现错误时没有正确回滚整个交易（安全失败），攻击者可能会耗尽用户账户的资金，或者可能产生竞态条件，允许攻击者多次向目标账户发送资金。


## 参考文献

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/) 

## 映射的CWE列表
* [CWE-209	Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215	Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234	Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235	Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248	Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252	Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274	Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280	Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369	Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390	Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391	Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394	Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396	Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397	Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460	Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476	NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478	Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484	Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550	Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636	Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703	Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754	Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755	Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756	Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)