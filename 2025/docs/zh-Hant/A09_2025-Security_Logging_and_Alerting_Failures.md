# A09:2025 安全日志记录和告警失效 ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景

安全日志记录和告警失效保持第 9 位。该类别名称略有变化，用于强调相关日志事件需要告警功能来触发行动。该类别在数据中始终会被低估，并且第三次由社区问卷参与者投票进入列表。该类别极难测试，在 CVE/CVSS 数据中的体现很少（只有 723 个 CVE）；但它对可见性、事件告警和取证可能有很大影响。本类别包括与*正确处理写入日志文件时的输出编码（CWE-117）、向日志文件插入敏感数据（CWE-532）和日志记录不足（CWE-778）*相关的问题。

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

没有日志记录和监控，就无法检测攻击和安全事件；没有告警，也很难在安全事件中快速有效响应。当出现以下情况时，就会发生日志记录不足、持续监控不足、检测不足，以及无法通过告警发起主动响应的问题：

* 可审计事件没有记录或记录不一致，例如登录、登录失败和高价值交易（例如只记录成功登录，不记录失败尝试）。
* 警告和错误不生成日志消息，或生成的消息不足、不清晰。
* 日志完整性没有得到妥善保护，容易被篡改。
* 应用和 API 的日志没有被监控以发现可疑活动。
* 日志只存储在本地，没有正确备份。
* 没有建立适当的告警阈值和响应升级流程，或这些流程无效。告警没有在合理时间内被接收或审查。
* 渗透测试和动态应用安全测试（DAST）工具（例如 Burp 或 ZAP）的扫描没有触发告警。
* 应用无法实时或近实时检测、升级或告警正在发生的攻击。
* 通过让日志记录和告警事件对用户或攻击者可见，容易导致敏感信息泄露（参见 [A01:2025-失效的访问控制](A01_2025-Broken_Access_Control.md)），或记录了不应记录的敏感信息（例如 PII 或 PHI）。
* 如果日志数据没有正确编码，就容易受到针对日志或监控系统的注入或攻击。
* 应用缺失或错误处理错误及其他异常条件，导致系统不知道发生了错误，因此无法记录问题。
* 缺少足够的、用于触发告警的“用例”，或用例已经过时，无法识别特殊情况。
* 过多误报让人无法区分重要告警和不重要告警，导致重要告警被过晚识别或完全没有被识别（SOC 团队实际过载）。
* 因为该用例的剧本不完整、过时或缺失，检测到的告警无法被正确处理。

## 如何预防

开发人员应根据应用风险实现以下部分或全部控制：

* 确保所有登录、访问控制和服务端输入验证失败都能被记录，并包含足够的用户上下文，以识别可疑或恶意账户；保留足够长时间，以便延迟取证分析。
* 确保应用中包含安全控制的每一部分都记录日志，无论成功还是失败。
* 确保日志以日志管理解决方案能够轻松消费的格式生成。
* 确保正确编码日志数据，以防止对日志或监控系统的注入或攻击。
* 确保所有交易都有带完整性控制的审计轨迹，以防止篡改或删除，例如只追加数据库表或类似机制。
* 确保所有抛出错误的交易都回滚并重新开始。始终故障关闭（fail closed）。
* 如果应用或其用户行为可疑，应发出告警。为开发人员创建这方面的指南，让他们能据此编码，或采购相关系统。
* DevSecOps 和安全团队应建立有效的监控和告警用例，包括剧本，使安全运营中心（SOC）团队能够快速检测并响应可疑活动。
* 在应用中加入“蜜标”作为攻击者陷阱，例如加入数据库、数据，或作为真实和/或技术用户身份。由于它们不会在正常业务中使用，任何访问都会生成可告警的日志数据，且几乎没有误报。
* 行为分析和 AI 支持可以作为可选附加技术，用于降低告警误报率。
* 建立或采用事件响应和恢复计划，例如 National Institute of Standards and Technology（NIST）800-61r2 或更新版本。教会软件开发人员应用攻击和事件的表现，使他们能够报告。

商业和开源应用防护产品（例如 OWASP ModSecurity Core Rule Set）以及开源日志关联软件（例如 Elasticsearch、Logstash、Kibana（ELK）栈）提供自定义仪表板和告警功能，可能有助于处理这些问题。也有商业可观测性工具可以帮助你近实时响应或阻断攻击。

## 攻击场景示例

**场景 #1：** 某儿童健康计划提供商的网站运营方由于缺少监控和日志，无法检测到安全事件。外部方通知该健康计划提供商，攻击者已经访问并修改了超过 350 万名儿童的数千条敏感健康记录。事件后审查发现，网站开发人员没有处理重大漏洞。由于系统没有日志记录或监控，数据泄露可能自 2013 年以来一直在进行，时间超过七年。

**场景 #2：** 某大型印度航空公司发生数据泄露，涉及数百万乘客超过十年的个人数据，包括护照和信用卡数据。数据泄露发生在第三方云托管提供商处，该提供商在一段时间后才通知航空公司。

**场景 #3：** 某大型欧洲航空公司发生必须按 GDPR 报告的安全事件。据报道，该事件由攻击者利用支付应用安全漏洞造成，攻击者收集了超过 40 万条客户支付记录。该航空公司因此被隐私监管机构罚款 2000 万英镑。

## 参考资料

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)

## 映射的 CWE 列表

* [CWE-117 日志输出转义不当](https://cwe.mitre.org/data/definitions/117.html)
* [CWE-221 因遗漏造成信息丢失](https://cwe.mitre.org/data/definitions/221.html)
* [CWE-223 遗漏安全相关信息](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-532 向日志文件插入敏感信息](https://cwe.mitre.org/data/definitions/532.html)
* [CWE-778 日志记录不足](https://cwe.mitre.org/data/definitions/778.html)
