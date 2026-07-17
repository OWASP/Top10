# A09:2025 安全日志记录与告警失效 ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## 背景

安全日志记录与告警失效仍位列第9名。该类别名称略有调整，以强调触发相关日志事件所需的告警功能。此类问题在数据中始终被低估，且第三次由社区调查参与者投票进入榜单。该类别极难测试，在CVE/CVSS数据中占比极低（仅723个CVE），但对可见性、事件告警及取证分析影响重大。该类别涉及的问题包括：*日志输出编码处理不当（CWE-117）、将敏感数据写入日志文件（CWE-532）以及日志记录不足（CWE-778）。*


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
   <td>加权利用平均值
   </td>
   <td>加权影响平均值
   </td>
   <td>总发生次数
   </td>
   <td>总CVE数量
   </td>
  </tr>
  <tr>
   <td>5
   </td>
   <td>11.33%
   </td>
   <td>3.91%
   </td>
   <td>85.96%
   </td>
   <td>46.48%
   </td>
   <td>7.19
   </td>
   <td>2.65
   </td>
   <td>260,288
   </td>
   <td>723
   </td>
  </tr>
</table>



## 描述

没有日志记录和监控，攻击和入侵就无法被检测；没有告警，安全事件发生时很难快速有效地响应。以下情况均属于日志记录、持续监控、检测和告警不足，无法触发主动响应：

*   可审计事件（如登录、登录失败、高价值交易）未被记录或记录不一致（例如，仅记录成功登录，但未记录失败尝试）。
*   警告和错误未生成日志消息，或生成的日志消息不充分、不清晰。
*   日志的完整性未得到妥善保护，存在被篡改的风险。
*   应用程序和API的日志未针对可疑活动进行监控。
*   日志仅存储在本地，且未进行适当备份。
*   未建立或未有效实施适当的告警阈值和响应升级流程。告警未能在合理时间内被接收或审查。
*   动态应用安全测试（DAST）工具（如Burp或ZAP）的渗透测试和扫描未触发告警。
*   应用程序无法实时或近实时地检测、升级或告警活跃攻击。
*   通过向用户或攻击者暴露日志和告警事件（参见[A01:2025-Broken Access Control](A01_2025-Broken_Access_Control.md)），或记录了不应记录的敏感信息（如PII或PHI），导致敏感信息泄露风险。
*   如果日志数据未正确编码，则面临日志或监控系统被注入或攻击的风险。
*   应用程序缺失或错误处理了错误及其他异常情况，导致系统不知道发生了错误，因此无法记录问题。
*   用于发出告警的适当“用例”缺失或过时，无法识别特殊情况。
*   过多的误报警报导致无法区分重要告警与不重要告警，导致告警被过晚识别或完全未被识别（导致SOC团队物理过载）。
*   检测到的告警无法被正确处理，因为该用例的剧本不完整、过时或缺失。


## 如何预防

开发人员应根据应用程序的风险，实施以下部分或全部控制措施：

*   确保所有登录、访问控制和服务器端输入验证失败都能被记录，并包含足够的用户上下文信息以识别可疑或恶意账户，且保留足够长的时间以支持延迟取证分析。
*   确保应用程序中包含安全控制的每个部分，无论其成功或失败，都被记录下来。
*   确保日志以日志管理解决方案易于消费的格式生成。
*   确保日志数据被正确编码，以防止对日志或监控系统的注入或攻击。
*   确保所有交易都有审计追踪，并具备完整性控制以防止篡改或删除，例如使用仅追加的数据库表或类似机制。
*   确保所有抛出错误的交易都被回滚并重新开始。始终以封闭失败（fail closed）的方式处理。
*   如果您的应用程序或其用户行为可疑，请发出告警。为此主题为您的开发人员创建指南，以便他们可以据此编写代码或购买相关系统。
*   DevSecOps和安全团队应建立有效的监控和告警用例，包括剧本，以便安全运营中心（SOC）团队能够快速检测并响应可疑活动。
*   在您的应用程序中添加“蜜标”作为攻击者的陷阱，例如添加到数据库、数据中，作为真实和/或技术用户身份。由于它们在正常业务中不会被使用，任何访问都会生成日志数据，并且可以几乎无误报地发出告警。
*   行为分析和AI支持可作为可选附加技术，以支持降低告警的误报率。
*   建立或采用事件响应和恢复计划，例如美国国家标准与技术研究院（NIST）800-61r2或更高版本。教导您的软件开发人员了解应用程序攻击和事件的表现形式，以便他们能够报告这些情况。

存在商业和开源的应用保护产品，例如OWASP ModSecurity核心规则集，以及开源日志关联软件，例如Elasticsearch、Logstash、Kibana（ELK）技术栈，它们提供自定义仪表板和告警功能，可能有助于应对这些问题。此外，还有商业可观测性工具，可以帮助您近乎实时地响应或阻止攻击。


## 示例攻击场景

**场景 #1：** 一家儿童健康计划提供商的网站运营商因缺乏监控和日志记录而未能检测到入侵。外部方告知该健康计划提供商，一名攻击者访问并修改了超过350万名儿童的数千份敏感健康记录。事后审查发现，网站开发人员未解决重大漏洞。由于系统没有日志记录或监控，数据泄露可能自2013年起就已持续发生，时间跨度超过七年。

**场景 #2：** 一家印度大型航空公司发生数据泄露，涉及数百万乘客超过十年的个人数据，包括护照和信用卡数据。数据泄露发生在第三方云托管提供商处，该提供商在一段时间后通知了航空公司。

**场景 #3：** 一家欧洲大型航空公司遭遇了GDPR规定的可报告数据泄露。据报道，此次泄露是由攻击者利用支付应用程序的安全漏洞造成的，攻击者窃取了超过40万条客户支付记录。该航空公司因此被隐私监管机构罚款2000万英镑。


## 参考文献

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## 映射的CWE列表

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)