# A09:2021 – Security Logging and Monitoring Failures

## 因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 | 最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 总发生数 | 相关 CVEs 总数量 |
| :--------------: | :--------: | :--------: | :----------: | :----------: | :----------: | :----------: | :------: | :--------------: |
|        4         |   19.23%   |   6.51%    |    53.67%    |    39.97%    |     6.87     |     4.99     |  53,615  |       242        |

## 简介

安全记录及监控是业界调查结果 (#3)，由 2017 年的第十名稍微上升。记录及监控功能验证非常有挑战性，通常需要以访谈或询问之方式检验有无侦测渗透测试的攻击活动。侦测及应变对资安事件至关重要，但此类型之 CVE/CVSS 资料不多。尽管如此，此类型对于事件告警、可见性和鉴识仍然非常有影响力。此类型涵盖 CWE-778 不足地记录，CWE-117 未经适当处理之日志输出，CWE-223 遗漏安全相关资讯及 CWE-532 于日志档案置入敏感资讯。

## 描述

在 2021 年 OWASP Top 10，此类型有助于对进行中资安事件之侦测，升级及应变。缺乏记录及监控时无法侦测资安事件发生。不足地记录，侦测，监控及主动应变随时会发生：

- 可稽核事件未记录，如登入成功，登入失败及高价值交易。

- 警告或错误发生时未产生，产生不充足或产生不明确日志。
- 未监控应用程式或应用程式介面(API)日志中的可疑活动。

- 日志仅储存于本地端。
- 未设有或设有无效之适当告警阀值及应变升级程序。
- 渗透测试及 DAST 工具(如 OWASP ZAP)扫描没有触发告警。

- 应用程式无法接近即时或即时侦测，升级或警告进行中之攻击。

允许使用者或攻击者读取日志或告警事件可能早成资讯泄漏(参考 A01:2021 权限控制失效)

## 如何预防

开发者应依据应用程式所面临风险实作下列部分或全部的控制项：

- 确保记录所有登入，存取控制及服务器端输入验证之失败，日志应包含充足使用者情境以识别可疑或恶意帐号，日志应存留充足时间以利未来可能之鉴识分析要求。

- 确保日志格式符合一般日志管理系统常用格式。
- 确保日志经正确编码以防止遭受注入攻击或日志/监控系统遭受攻击。
- 确保高价值交易进行时产生稽核轨迹(日志)并实作完整性控制以避免窜改或删除，如仅限附加的资料表或类似工具。
- DevSecOps 团队应建立有效地监控及告警机制以利侦测可疑活动并快速应变。
- 建立或导入事件应变及复原计画，如 NIST 800-61r2 或更新版本。

现有多种商业化及开放原始码应用程式保护架构，如 OWASP ModSecurity Core Rule Set 及开放原始码日志关联软体可客制化仪表板及告警，如 ELK stack。

## 攻击情景范例

**情境 1**：一家儿童健康计划供应商的网站运营商因缺乏监控和记录无法侦测资安事件。外部通知该健康计划供应商，攻击者已存取及修改超过 350 万名儿童的敏感健康记录。事后审查发现网站开发者没有处理重大弱点。由于系统没有记录或监控，资料泄漏可能从 2013 年开始至今，时间超过七年。

**情境 2**：印度一家大型航空公司发生涉及数百万乘客超过十年包括护照及信用卡资料等个人资料的资料泄漏。资料泄漏发生在第三方供应商提供的云端服务，该供应商在资料泄漏发生一段时间后通知航空公司。

情境 3：一家大型欧洲航空公司发生依 GDPR 应报告之个资事故。据报导，攻击者利用支付应用系统之安全漏洞，取得超过 40 万笔客户支付纪录。该航空公司遭隐私主管机关裁罚两千万英镑。

## 参考文档

- [OWASP Proactive Controls: Implement Logging and
  Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

- [OWASP Application Security Verification Standard: V8 Logging and
  Monitoring](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: Testing for Detailed Error
  Code](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

- [OWASP Cheat Sheet:
  Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [Data Integrity: Recovering from Ransomware and Other Destructive
  Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

- [Data Integrity: Identifying and Protecting Assets Against
  Ransomware and Other Destructive
  Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

- [Data Integrity: Detecting and Responding to Ransomware and Other
  Destructive
  Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## List of Mapped CWEs

CWE-117 Improper Output Neutralization for Logs

CWE-117 未经适当处理之日志输出

CWE-223 Omission of Security-relevant Information

CWE-223 遗漏安全相关资讯

CWE-532 Insertion of Sensitive Information into Log File

CWE-532 于日志档案置入敏感资讯

CWE-778 Insufficient Logging

CWE-778 不足地记录
