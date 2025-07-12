# A06:2021 – 脆弱で古くなったコンポーネント    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 | 最大網羅率 | 平均網羅率 | 加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## 概要

この項目は Top10 コミュニティによる調査では 2 位でしたが、Top10 に入る十分なデータもありました。
脆弱なコンポーネントは、テストやリスク評価に苦労する問題として知られており、含まれるCWE(Common Weakness Enumerations)にマッピングされたCWEがない唯一のカテゴリーです。
このため標準の攻撃の難易度および、攻撃による影響のウェイトは5.0を使用しています。
注目すべき CWE は CWE-1104 メンテナンスされていないサードパーティー製コンポーネントの使用と、OWASP Top10 2013 A9 および 2017 A9 を参照する２つの CWE です。

## 説明

以下に該当する場合、脆弱と言えます。

-   使用しているすべてのコンポーネントのバージョンを知らない場合（クライアントサイド・サーバサイドの両方について）。
    これには直接使用するコンポーネントだけでなく、ネストされた依存関係も含む。

-   ソフトウェアが脆弱な場合やサポートがない場合、また使用期限が切れている場合。
    これには、OSやWebサーバ、アプリケーションサーバ、データベース管理システム（DBMS）、アプリケーション、API、すべてのコンポーネント、ランタイム環境とライブラリを含む。

-   脆弱性スキャンを定期的にしていない場合や、使用しているコンポーネントに関するセキュリティ情報を購読していない場合。

-   基盤プラットフォームやフレームワークおよび依存関係をリスクに基づきタイムリーに修正またはアップグレードしない場合。
    パッチ適用が変更管理の下、月次や四半期のタスクとされている環境でよく起こる。
    これにより、当該組織は、解決済みの脆弱性について、何日も、場合によっては何ヶ月も不必要な危険にさらされることになる。

-   ソフトウェア開発者が、更新やアップグレードまたはパッチの互換性をテストしない場合。

-   コンポーネントの設定をセキュアにしていない場合。（A05-2021: セキュリティの設定ミス 参照）

## 防止方法

以下に示すパッチ管理プロセスが必要です。

-   未使用の依存関係、不要な機能、コンポーネント、ファイルや文書を取り除く。
    
-   Versions Maven Plugin, OWASP Dependency Check, Retire.jsなどのツールを使用して、クライアントおよびサーバの両方のコンポーネント（フレームワークやライブラリなど）とその依存関係の棚卸しを継続的に行う。
    コンポーネントの脆弱性についてCVE(Common Vulnerability and Exposures)やNVD(National Vulnerability Database)などの情報ソースを継続的にモニタリングする。ソフトウェア構成分析ツールを使用してプロセスを自動化する。
    使用しているコンポーネントに関するセキュリティ脆弱性の電子メールアラートに登録する。

-   安全なリンクを介し、公式ソースからのみコンポーネントを取得する。
    変更された悪意あるコンポーネントを取得する可能性を減らすため、署名付きのパッケージを選ぶようにする。
    (A08-2021: ソフトウェアとデータの整合性の不具合 参照)

-   メンテナンスされていない、もしくはセキュリティパッチが作られていない古いバージョンのライブラリとコンポーネントを監視する。
    パッチ適用が不可能な場合は、発見された問題を監視、検知または保護するために、仮想パッチの適用を検討する。
    
いかなる組織も、アプリケーションまたはポートフォリオの存続期間は、モニタリングとトリアージを行い更新または設定変更を行う継続的な計画があることを確認する必要があります。

## 攻撃シナリオの例

**シナリオ #1:** 

コンポーネントは通常、アプリケーション自体と同じ権限で実行されるため、どんなコンポーネントに存在する欠陥も、深刻な影響を及ぼす可能性があります。
そのような欠陥は、偶発的（例：コーディングエラー）または意図的（例：コンポーネントのバックドア）両方の可能性があります。
発見済みの悪用可能なコンポーネントの脆弱性の例：

-   Apache Struts 2においてリモートで任意のコードが実行される脆弱性CVE-2017-5638は、重大な侵害をもたらしています。
-   Internet of things (IoT)は、頻繁なパッチ適用が困難もしくは不可能ですが、一方でパッチ適用の重要性はますます高まっています。（例：医療機器）

攻撃者を助けるようなツールがあり、パッチが未適用なシステムやシステムの設定ミスを自動的に見つけることができます。
例えば、Shodan IoT search engineは、2014年4月にパッチが適用されたHeartbleedの脆弱性などセキュリティに問題のある機器を見つけることができます。

## 参考資料

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## 対応する CWE のリスト

[CWE-937 OWASP Top 10 2013 A9: 既知の脆弱性のあるコンポーネントの使用](https://cwe.mitre.org/data/definitions/937.html)

[CWE-1035 2017 Top 10 A9: 既知の脆弱性のあるコンポーネントの使用](https://cwe.mitre.org/data/definitions/1035.html)

[CWE-1104 メンテナンスされていないサードパーティー製コンポーネントの使用](https://cwe.mitre.org/data/definitions/1104.html)

# A06:2021 – Vulnerable and Outdated Components    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Overview

It was #2 from the Top 10 community survey but also had enough data to make the
Top 10 via data. Vulnerable Components are a known issue that we
struggle to test and assess risk and is the only category to not have
any Common Weakness Enumerations (CWEs) mapped to the included CWEs, so a default exploits/impact
weight of 5.0 is used. Notable CWEs included are *CWE-1104: Use of
Unmaintained Third-Party Components* and the two CWEs from Top 10 2013
and 2017.

## Description 

You are likely vulnerable:

-   If you do not know the versions of all components you use (both
    client-side and server-side). This includes components you directly
    use as well as nested dependencies.

-   If the software is vulnerable, unsupported, or out of date. This
    includes the OS, web/application server, database management system
    (DBMS), applications, APIs and all components, runtime environments,
    and libraries.

-   If you do not scan for vulnerabilities regularly and subscribe to
    security bulletins related to the components you use.

-   If you do not fix or upgrade the underlying platform, frameworks,
    and dependencies in a risk-based, timely fashion. This commonly
    happens in environments when patching is a monthly or quarterly task
    under change control, leaving organizations open to days or months
    of unnecessary exposure to fixed vulnerabilities.

-   If software developers do not test the compatibility of updated,
    upgraded, or patched libraries.

-   If you do not secure the components’ configurations (see
    A05:2021-Security Misconfiguration).

## How to Prevent

There should be a patch management process in place to:

-   Remove unused dependencies, unnecessary features, components, files,
    and documentation.

-   Continuously inventory the versions of both client-side and
    server-side components (e.g., frameworks, libraries) and their
    dependencies using tools like versions, OWASP Dependency Check,
    retire.js, etc. Continuously monitor sources like Common Vulnerability and 
    Exposures (CVE) and National Vulnerability Database (NVD) for
    vulnerabilities in the components. Use software composition analysis
    tools to automate the process. Subscribe to email alerts for
    security vulnerabilities related to components you use.

-   Only obtain components from official sources over secure links.
    Prefer signed packages to reduce the chance of including a modified,
    malicious component (See A08:2021-Software and Data Integrity
    Failures).

-   Monitor for libraries and components that are unmaintained or do not
    create security patches for older versions. If patching is not
    possible, consider deploying a virtual patch to monitor, detect, or
    protect against the discovered issue.

Every organization must ensure an ongoing plan for monitoring, triaging,
and applying updates or configuration changes for the lifetime of the
application or portfolio.

## Example Attack Scenarios

**Scenario #1:** Components typically run with the same privileges as
the application itself, so flaws in any component can result in serious
impact. Such flaws can be accidental (e.g., coding error) or intentional
(e.g., a backdoor in a component). Some example exploitable component
vulnerabilities discovered are:

-   CVE-2017-5638, a Struts 2 remote code execution vulnerability that
    enables the execution of arbitrary code on the server, has been
    blamed for significant breaches.

-   While the internet of things (IoT) is frequently difficult or
    impossible to patch, the importance of patching them can be great
    (e.g., biomedical devices).

There are automated tools to help attackers find unpatched or
misconfigured systems. For example, the Shodan IoT search engine can
help you find devices that still suffer from Heartbleed vulnerability
patched in April 2014.

## References

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## List of Mapped CWEs

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
