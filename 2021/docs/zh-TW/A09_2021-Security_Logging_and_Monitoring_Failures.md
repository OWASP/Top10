# A09:2021 – Security Logging and Monitoring Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 53.67%       | 39.97%       | 6.87                 | 4.99                | 53,615            | 242        |

| 可對照 CWEs 數量  | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 總發生數 | 相關 CVEs 總數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 53.67%       | 39.97%       | 6.87                 | 4.99                | 53,615            | 242        |

## Overview

Security logging and monitoring came from the industry survey (#3), up
slightly from the tenth position in the OWASP Top 10 2017. Logging and
monitoring can be challenging to test, often involving interviews or
asking if attacks were detected during a penetration test. There isn't
much CVE/CVSS data for this category, but detecting and responding to
breaches is critical. Still, it can be very impactful for visibility,
incident alerting, and forensics. This category expands beyond *CWE-778
Insufficient Logging* to include *CWE-117 Improper Output Neutralization
for Logs*, *CWE-223 Omission of Security-relevant Information*, and
*CWE-532* *Insertion of Sensitive Information into Log File*.

安全記錄及監控是業界調查結果 (#3)，由2017年的第十名稍微上升。記錄及監控功能驗證非常有挑戰性，通常需要以訪談或詢問之方式檢驗有無偵測滲透測試的攻擊活動。偵測及應變對資安事件至關重要，但此類型之CVE/CVSS資料不多。儘管如此，此類型對於事件告警、可見性和鑑識仍然非常有影響力。此類型涵蓋CWE-778不足地記錄，CWE-117未經適當處理之日誌輸出，CWE-223遺漏安全相關資訊及CWE-532於日誌檔案置入敏感資訊。

## Description 

Returning to the OWASP Top 10 2021, this category is to help detect,
escalate, and respond to active breaches. Without logging and
monitoring, breaches cannot be detected. Insufficient logging,
detection, monitoring, and active response occurs any time:

在2021年OWASP Top 10，此類型有助於對進行中資安事件之偵測，升級及應變。缺乏記錄及監控時無法偵測資安事件發生。不足地記錄，偵測，監控及主動應變隨時會發生：

-   Auditable events, such as logins, failed logins, and high-value
    transactions, are not logged.
    
-   可稽核事件未記錄，如登入成功，登入失敗及高價值交易。

-   Warnings and errors generate no, inadequate, or unclear log
    messages.
    
-   警告或錯誤發生時未產生，產生不充足或產生不明確日誌。

-   Logs of applications and APIs are not monitored for suspicious
    activity.
    
-   未監控應用程式或應用程式介面(API)日誌中的可疑活動。

-   Logs are only stored locally.
    
-   日誌僅儲存於本地端。

-   Appropriate alerting thresholds and response escalation processes
    are not in place or effective.
    
-   未設有或設有無效之適當告警閥值及應變升級程序。

-   Penetration testing and scans by DAST tools (such as OWASP ZAP) do
    not trigger alerts.
    
-   滲透測試及DAST工具(如OWASP ZAP)掃描沒有觸發告警。

-   The application cannot detect, escalate, or alert for active attacks
    in real-time or near real-time.
    
-   應用程式無法接近即時或即時偵測，升級或警告進行中之攻擊。

You are vulnerable to information leakage by making logging and alerting
events visible to a user or an attacker (see A01:2021 – Broken Access
Control).

允許使用者或攻擊者讀取日誌或告警事件可能早成資訊洩漏(參考A01:2021權限控制失效)

## How to Prevent

Developers should implement some or all the following controls, d
epending on the risk of the application:

開發者應依據應用程式所面臨風險實作下列部分或全部的控制項：

-   Ensure all login, access control, and server-side input validation
    failures can be logged with sufficient user context to identify
    suspicious or malicious accounts and held for enough time to allow
    delayed forensic analysis.
    
-   確保記錄所有登入，存取控制及伺服器端輸入驗證之失敗，日誌應包含充足使用者情境以識別可疑或惡意帳號，日誌應存留充足時間以利未來可能之鑑識分析要求。

-   Ensure that logs are generated in a format that log management
    solutions can easily consume.
    
-   確保日誌格式符合一般日誌管理系統常用格式。

-   Ensure log data is encoded correctly to prevent injections or
    attacks on the logging or monitoring systems.
    
-   確保日誌經正確編碼以防止遭受注入攻擊或日誌/監控系統遭受攻擊。

-   Ensure high-value transactions have an audit trail with integrity
    controls to prevent tampering or deletion, such as append-only
    database tables or similar.
    
-   確保高價值交易進行時產生稽核軌跡(日誌)並實作完整性控制以避免竄改或刪除，如僅限附加的資料表或類似工具。

-   DevSecOps teams should establish effective monitoring and alerting
    such that suspicious activities are detected and responded to
    quickly.
    
-   DevSecOps團隊應建立有效地監控及告警機制以利偵測可疑活動並快速應變。

-   Establish or adopt an incident response and recovery plan, such as
    NIST 800-61r2 or later.
    
-   建立或導入事件應變及復原計畫，如NIST 800-61r2或更新版本。

There are commercial and open-source application protection frameworks
such as the OWASP ModSecurity Core Rule Set, and open-source log
correlation software, such as the ELK stack, that feature custom
dashboards and alerting.

現有多種商業化及開放原始碼應用程式保護架構，如OWASP ModSecurity Core Rule Set及開放原始碼日誌關聯軟體可客製化儀表板及告警，如 ELK stack。

## Example Attack Scenarios

**Scenario #1:** A childrens' health plan provider's website operator
couldn't detect a breach due to a lack of monitoring and logging. An
external party informed the health plan provider that an attacker had
accessed and modified thousands of sensitive health records of more than
3.5 million children. A post-incident review found that the website
developers had not addressed significant vulnerabilities. As there was
no logging or monitoring of the system, the data breach could have been
in progress since 2013, a period of more than seven years.

情境1：一家兒童健康計劃供應商的網站運營商因缺乏監控和記錄無法偵測資安事件。外部通知該健康計劃供應商，攻擊者已存取及修改超過 350 萬名兒童的敏感健康記錄。事後審查發現網站開發者沒有處理重大弱點。由於系統沒有記錄或監控，資料洩漏可能從 2013 年開始至今，時間超過七年。

**Scenario #2:** A major Indian airline had a data breach involving more
than ten years' worth of personal data of millions of passengers,
including passport and credit card data. The data breach occurred at a
third-party cloud hosting provider, who notified the airline of the
breach after some time.

情境2：印度一家大型航空公司發生涉及數百萬乘客超過十年包括護照及信用卡資料等個人資料的資料洩漏。資料洩漏發生在第三方供應商提供的雲端服務，該供應商在資料洩漏發生一段時間後通知航空公司。

**Scenario #3:** A major European airline suffered a GDPR reportable
breach. The breach was reportedly caused by payment application security
vulnerabilities exploited by attackers, who harvested more than 400,000
customer payment records. The airline was fined 20 million pounds as a
result by the privacy regulator.

情境3：一家大型歐洲航空公司發生依GDPR應報告之個資事故。 據報導，攻擊者利用支付應用系統之安全漏洞，取得超過40萬筆客戶支付紀錄。 該航空公司遭隱私主管機關裁罰兩千萬英鎊。

## References

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V8 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## List of Mapped CWEs

CWE-117 Improper Output Neutralization for Logs

CWE-117 未經適當處理之日誌輸出

CWE-223 Omission of Security-relevant Information

CWE-223 遺漏安全相關資訊

CWE-532 Insertion of Sensitive Information into Log File

CWE-532 於日誌檔案置入敏感資訊

CWE-778 Insufficient Logging

CWE-778 不足地記錄
