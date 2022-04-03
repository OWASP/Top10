# A09:2021 – セキュリティログとモニタリングの失敗

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## 概要

セキュリティロギングとモニタリングは、OWASP Top10 コミュニティによる調査にて第3位で、OWASP トップ 10 2017 の第 10 位からわずかに上昇しました。
ロギングとモニタリングはテストが難しく、インタビューやペネトレーションテストで攻撃が検出されたかどうかを確認することがよくあります。
このカテゴリの CVE/CVSS データはあまりありませんが、侵害を検知して対応することは重要です。
とはいえ、このカテゴリーで失敗が起きると、説明責任、可視化、インシデントアラート、フォレンジックなどに影響があります。
このカテゴリは、*CWE-778 ロギングの不足* だけでなく、*CWE-117 ログファイルへの不適切な出力*、*CWE-223 セキュリティに関連する情報の省略*、*CWE-532 ログファイルからの情報漏洩* なども含まれます。

## 説明

OWASP Top 10 2021 に話を戻すと、このカテゴリは、アクティブな違反の検出、エスカレーション、および対応を支援するものです。
ロギングとモニタリングがなければ、侵害を検知することはできません。
ロギングや検知、モニタリング、適時の対応が十分に行われないという状況は、いつでも発生します:

-   ログイン、失敗したログイン、重要なトランザクションなどの監査可能なイベントがログに記録されていない。

-   警告とエラーが発生してもログメッセージが生成されない、または不十分、不明確なメッセージが生成されている。

-   アプリケーションとAPIのログが、疑わしいアクティビティをモニタリングしていない。

-   ログがローカルにのみ格納されている。

-   アラートの適切なしきい値とレスポンスのエスカレーションプロセスが整えられていない、または有効ではない。

-   ペネトレーションテストやDAST(dynamic application security testing)ツール（OWASP ZAPなど）によるスキャンがアラートをあげない。

-   アプリケーションがリアルタイム、準リアルタイムにアクティブな攻撃を検知、エスカレート、またはアラートすることができない。

ユーザまたは攻撃者がログやアラートのイベントを閲覧できると、情報の漏えいが発生する可能性があります ([A01:2021-アクセス制御の不備](A01_2021-Broken_Access_Control.md) を参照).

## 防止方法

アプリケーションによって保存または処理されるデータのリスクに応じて対応する：

-   ログイン、アクセス制御の失敗、サーバサイドの入力検証の失敗を全てログとして記録するようにする。
    ログは、不審なアカウントや悪意のあるアカウントを特定するために十分なユーザコンテキストを持ち、
    後日、フォレンジック分析を行うのに十分な期間分保持するようにする。

-   統合ログ管理ソリューションで簡単に使用できる形式でログが生成されていることを確認する。

-   価値の高いトランザクションにおいて、監査証跡が取得されていること。
    その際、追記型データベースのテーブルなどのような、完全性を保つコントロールを用いて、改ざんや削除を防止する。

-   DevSecOps チームが疑わしい活動をタイムリーに検知して対応できるように、効果的なモニタリングとアラートを確立する。

-   NIST(National Institute of Standards and Technology) 800-61 rev 2（またはそれ以降）のような、インシデント対応および復旧計画を策定または採用する。

OWASP AppSensor、OWASP ModSecurity Core Rule Setを使用したModSecurityなどのWebアプリケーションファイアウォール、
カスタムダッシュボードとアラートを使用したログ相関分析ソフトウェア（Elasticsearch, Logstash, Kibana (ELK) ）など、商用およびオープンソースのアプリケーション保護フレームワークがあります。

## 攻撃シナリオの例

**シナリオ #1:** 

ある児童医療プランのウェブサイト運営者は、監視とログの不足のために侵害を検知できませんでした。
攻撃者が 350 万人以上の子どもたちの数千もの機密性の高い健康記録にアクセスし変更したという連絡が、外部の関係者から医療機関にありました。
事故後のレビューでは、ウェブサイトの開発者が重要な脆弱性に対処していなかったことが判明しました。
システムのロギングやモニタリングが行われていなかったため、データ侵害は 2013 年から 7 年以上にわたって進行していた可能性があります。

**シナリオ #2:** 

あるインドの大手航空会社で、パスポートやクレジットカードなど数百万人の乗客の 10 年分以上の個人情報を含むデータが流出しました。
このデータ流出は、第三者のクラウドホスティングプロバイダーで発生し、しばらくしてから航空会社に通知されました。

**シナリオ #3:** 

ある欧州の大手航空会社が、GDPRの報告対象となる侵害を受けました。
この違反は、決済アプリケーションのセキュリティ脆弱性が攻撃者に悪用され、40万件以上の顧客の決済記録が収集されたことが原因とされています。
この航空会社は、プライバシー規制機関から2,000万ポンドの罰金を科せられました。

## 参考資料

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP Application Security Verification Standard: V8 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html))   

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## 対応する CWE のリスト

[CWE-117 ログファイルへの不適切な出力](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 セキュリティに関連する情報の省略](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 ログファイルからの情報漏洩](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 ロギングの不足](https://cwe.mitre.org/data/definitions/778.html)

# A09:2021 – Security Logging and Monitoring Failures    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Overview

Security logging and monitoring came from the Top 10 community survey (#3), up
slightly from the tenth position in the OWASP Top 10 2017. Logging and
monitoring can be challenging to test, often involving interviews or
asking if attacks were detected during a penetration test. There isn't
much CVE/CVSS data for this category, but detecting and responding to
breaches is critical. Still, it can be very impactful for accountability, visibility,
incident alerting, and forensics. This category expands beyond *CWE-778
Insufficient Logging* to include *CWE-117 Improper Output Neutralization
for Logs*, *CWE-223 Omission of Security-relevant Information*, and
*CWE-532* *Insertion of Sensitive Information into Log File*.

## Description 

Returning to the OWASP Top 10 2021, this category is to help detect,
escalate, and respond to active breaches. Without logging and
monitoring, breaches cannot be detected. Insufficient logging,
detection, monitoring, and active response occurs any time:

-   Auditable events, such as logins, failed logins, and high-value
    transactions, are not logged.

-   Warnings and errors generate no, inadequate, or unclear log
    messages.

-   Logs of applications and APIs are not monitored for suspicious
    activity.

-   Logs are only stored locally.

-   Appropriate alerting thresholds and response escalation processes
    are not in place or effective.

-   Penetration testing and scans by dynamic application security testing (DAST) tools (such as OWASP ZAP) do
    not trigger alerts.

-   The application cannot detect, escalate, or alert for active attacks
    in real-time or near real-time.

You are vulnerable to information leakage by making logging and alerting
events visible to a user or an attacker (see [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## How to Prevent

Developers should implement some or all the following controls, 
depending on the risk of the application:

-   Ensure all login, access control, and server-side input validation
    failures can be logged with sufficient user context to identify
    suspicious or malicious accounts and held for enough time to allow
    delayed forensic analysis.

-   Ensure that logs are generated in a format that log management
    solutions can easily consume.

-   Ensure log data is encoded correctly to prevent injections or
    attacks on the logging or monitoring systems.

-   Ensure high-value transactions have an audit trail with integrity
    controls to prevent tampering or deletion, such as append-only
    database tables or similar.

-   DevSecOps teams should establish effective monitoring and alerting
    such that suspicious activities are detected and responded to
    quickly.

-   Establish or adopt an incident response and recovery plan, such as
    National Institute of Standards and Technology (NIST) 800-61r2 or later.

There are commercial and open-source application protection frameworks
such as the OWASP ModSecurity Core Rule Set, and open-source log
correlation software, such as the Elasticsearch, Logstash, Kibana (ELK)
stack, that feature custom dashboards and alerting.

## Example Attack Scenarios

**Scenario #1:** A childrens' health plan provider's website operator
couldn't detect a breach due to a lack of monitoring and logging. An
external party informed the health plan provider that an attacker had
accessed and modified thousands of sensitive health records of more than
3.5 million children. A post-incident review found that the website
developers had not addressed significant vulnerabilities. As there was
no logging or monitoring of the system, the data breach could have been
in progress since 2013, a period of more than seven years.

**Scenario #2:** A major Indian airline had a data breach involving more
than ten years' worth of personal data of millions of passengers,
including passport and credit card data. The data breach occurred at a
third-party cloud hosting provider, who notified the airline of the
breach after some time.

**Scenario #3:** A major European airline suffered a GDPR reportable
breach. The breach was reportedly caused by payment application security
vulnerabilities exploited by attackers, who harvested more than 400,000
customer payment records. The airline was fined 20 million pounds as a
result by the privacy regulator.

## References

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP Application Security Verification Standard: V8 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html))   

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## List of Mapped CWEs

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
