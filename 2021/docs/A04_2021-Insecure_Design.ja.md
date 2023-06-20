# A04:2021 - 安全が確認されない不安な設計   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} 

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## 概要

2021年の新カテゴリーでは、設計やアーキテクチャの欠陥に関するリスクに焦点を当てています。
私たちは脅威のモデル化、セキュアなデザインパターンおよび、リファレンスアーキテクチャなどをもっと利用していくことが必要です。
コミュニティとして、私たちはコーディングスペースでの「shift-left」を超え、Secure by Designの原則に不可欠なプレコーディング活動に移行する必要があります。
注目すべき CWE (Common Weakness Enumerations) は、CWE-209: エラーメッセージからの情報漏洩、CWE-256: 保護されていない認証情報の保存、CWE-501: 信頼境界線の侵害および、CWE-522: 適切に保護されていないクレデンシャル などです。

## 説明

安全が確認されない不安な設計とは、様々な脆弱性を表す広範なカテゴリーであり、「欠落した、あるいは不十分な制御設計」とも表されます。
安全が確認されない不安な設計は、他のTop10リスクカテゴリの原因ではありません。
安全でない設計と安全でない実装は異なります。設計上の欠陥と実装上の欠陥を区別するのには理由があり、根本的な原因と改善方法が異なるからです。
安全な設計であっても、実装上の欠陥があると、それが悪用される可能性のある脆弱性につながります。
安全でない設計は、完璧な実装によって修正することはできません。というのも、定義上、特定の攻撃を防御するために必要なセキュリティ制御が作成されたことはないからです。
安全でない設計の要因の一つとして、開発するソフトウェアやシステムに内在するビジネスリスクのプロファイリングが行われていないために、どのレベルのセキュリティ設計が必要なのかを判断できないことが挙げられます。

### 要件とリソースマネジメント

すべてのデータ資産の機密性、完全性、可用性、そして真正性に関する保護要件および、期待されるビジネスロジックなど、アプリケーションのビジネス要件を収集し、事業部門と協議します。
アプリケーションが公開される程度に応じて、（アクセス制御に加えて）テナントを分離する必要があるか検討してください。
機能的および非機能的なセキュリティ要件を含む、技術的な要件をまとめます。
セキュリティ活動を含む設計、構築、テストおよび、運用のすべてをカバーする予算を計画し、事業部門と協議します。

### 安全が確認された安心な設計

「安全が確認された安心な設計」とは、常に脅威を評価し、既知の攻撃方法を防ぐためにコードを堅牢に設計し、テストする文化と方法論のことです。
データフローやアクセスコントロールなどのセキュリティコントロールの変更を確認するセッション（または同様の活動）に脅威のモデル化を統合するべきです。
ユーザストーリーの開発においては、正常なフロー及び障害の状態を決定し、責任者および、影響を受ける当事者がそれらを十分に理解し合意していることを確認してください。
正常系と異常系のフローの仮説と条件を分析し、それらが正確であり期待される物であることを確認します。仮説を検証し、適切な動作に必要な条件を実行する方法を決定し、結果をユーザーストーリーとして確実に文書化しましょう。
失敗から学び、改善を促進するための積極的なインセンティブを提供していくことが肝要です。「安全が確認された安心な設計」とは、ソフトウェアに追加できるアドオンでもツールでもありません。

### Secure Development Lifecycle

「安全が確認された安心なソフトウェア」を実現するには、セキュア開発ライフサイクル、何らかのセキュアデザインパターン、「ペイブド・ロード」方法論、安全なコンポーネントライブラリ、ツール、および脅威のモデル化が必要です。
全てのソフトウェアの開発プロジェクトとメンテナンス期間を通して、ソフトウェアプロジェクトの開始時にセキュリティの専門家に声をかけてください。
[OWASP ソフトウエアセキュリティ保証成熟度モデル(OWASP SAMM)](https://owaspsamm.org) を活用して、安全なソフトウェア開発に取り組みましょう。

## 防止方法

-   セキュリティおよびプライバシー関連の管理策の評価および設計を支援するために、アプリケーションセキュリティの専門家とともにセキュアな開発ライフサイクルを確立し使用する
    
-   セキュアなデザインパターンまたは、信頼性が高く安全性も検証されているコンポーネントライブラリを構築し使用する

-   重要な認証、アクセスコントロール、ビジネスロジック、および暗号鍵の管理フローに脅威モデルを使用する

-   ユーザーストーリーにセキュリティ言語とコントロールを組み込む

-   (フロントエンドからバックエンドまで)アプリケーションの各層に妥当性チェックを統合する

-   ユニットテストおよび統合テストを実施し、すべての重要なフローが脅威モデルに対して耐性があることを検証する。アプリケーションの各階層のユースケース*と*ミスユースケースをまとめる

-   リスク管理における保護の必要性に応じて、システム層とネットワーク層の階層を分ける

-   すべての階層でテナントを分離した堅牢な設計を行う

-   ユーザーやサービスによる過剰なリソース消費を制限する

## 攻撃シナリオの例

**シナリオ #1:** 

クレデンシャルの回復フローには「秘密の質問と答え」が含まれることがあります。
「秘密の質問と答え」は、NIST 800-63b、OWASP ASVS、および OWASP Top 10 で禁止されています。
「秘密の質問と答え」は複数の人が答えを知ることができるため、アイデンティティの証拠として信頼できないためです。
このようなコードは削除し、より安全な設計に置き換えるべきです。

**シナリオ #2:** 

ある映画館チェーンでは団体予約による割引を認めており、最大 15 名までは予約保証金が必要ありません。
攻撃者は、このフローに対する脅威モデルを作成し、数回のリクエストで600席とすべての映画館を一度に予約できるかどうかをテストし、大規模な損失を引き起こすことができます。

**シナリオ #3:** 

ある小売チェーンの電子商取引サイトでは、ダフ屋がオークションサイトに転売するために高級ビデオカードを購入するボットへの対策がなされていません。
この結果、ビデオカードメーカーや小売チェーン店にとっては最悪の評判となり、これらのカードをまったく手に入れることができない熱狂的なファンにとっては不幸をもたらします。
注意深いボット対策の設計や、入手可能になってから数秒以内に購入された場合などのドメインロジックを作成することで、非正規の購入を識別し、そのような取引を拒否することができるかもしれません。

## 参考資料

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## 対応する CWE のリスト

[CWE-73 ファイル名やパス名の外部制御](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 許容範囲が広すぎる入力制限](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 エラーメッセージからの情報漏洩](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 互換性のないポリシーによる機密情報の漏洩](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 想定を超えたパラメータの不適切な処理](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 パスワードなどのアカウント情報が平文のまま格納されている問題](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 復元可能な形式で保存されたパスワード](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 不正確な特権の割り当て](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 不適切な特権管理](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 権限管理の不備](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 重要な情報を暗号化していない問題](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 重要な情報が平文のまま格納されている問題](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 ファイルやディスクに平文のまま格納されている問題](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 メモリ上に平文のまま格納されている問題](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 保護されていないプライマリーチャネル](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 誤ったハンドラーの配置](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 適切でないアップロートファイル制限](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 HTTPリクエストの矛盾した解釈（HTTPリクエストスマグリング）](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 ユーザーインターフェース（UI）による重要情報の誤表示](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 不変と仮定される Web パラメータの外部制御](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 信頼境界線の侵害](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 十分でない資格情報保護](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 機密情報を含むWebブラウザのキャッシュの使用](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 機密情報を含むパーシステントクッキーの使用](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EEのバッドプラクティス：セッションに格納されたシリアライズ不可能なオブジェクト](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 GETリクエストのクエリ文字列からの情報漏洩](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 サーバサイドのセキュリティをクライアントサイドで実施](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 重要な状態データの外部制御](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 外部から提供されたファイルのファイル名や拡張子への依存](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 サーバーサイドにおける HTTP メソッドへの過剰な信頼](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 不十分なコンパートメント化](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 隠ぺいによるセキュリティへの依存](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 セキュリティ設計原則の違反](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 適切でない相互作用に対する頻度制御](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 信頼できない入力に基づいた判断への依存](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 ビジネスロジックのエラー](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 ユーザーの振る舞いに基づいたワークフローに依存した不適切な処理の実施](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 センシティブなコミュニケーションへの暗黙的インテントの使用](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 レンダリングされたUIレイヤーやフレームの不適切な制限](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 バリデーションフレームワークの不適切な使用](https://cwe.mitre.org/data/definitions/1173.html)

# A04:2021 – Insecure Design   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} 

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## Overview

A new category for 2021 focuses on risks related to design and architectural flaws, with a call for more use of threat modeling, secure design patterns, and reference architectures. As a community we need to move beyond  "shift-left" in the coding space to pre-code activities that are critical for the principles of Secure by Design. Notable Common Weakness Enumerations (CWEs) include *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation*, and *CWE-522: Insufficiently Protected Credentials*.

## Description

Insecure design is a broad category representing different weaknesses, expressed as “missing or ineffective control design.” Insecure design is not the source for all other Top 10 risk categories. There is a difference between insecure design and insecure implementation. We differentiate between design flaws and implementation defects for a reason, they have different root causes and remediation. A secure design can still have implementation defects leading to vulnerabilities that may be exploited. An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks. One of the factors that contribute to insecure design is the lack of business risk profiling inherent in the software or system being developed, and thus the failure to determine what level of security design is required.

### Requirements and Resource Management

Collect and negotiate the business requirements for an application with the business, including the protection requirements concerning confidentiality, integrity, availability, and authenticity of all data assets and the expected business logic. Take into account how exposed your application will be and if you need segregation of tenants (additionally to access control). Compile the technical requirements, including functional and non-functional security requirements. Plan and negotiate the budget covering all design, build, testing, and operation, including security activities.

### Secure Design

Secure design is a culture and methodology that constantly evaluates threats and ensures that code is robustly designed and tested to prevent known attack methods. Threat modeling should be integrated into refinement sessions (or similar activities); look for changes in data flows and access control or other security controls. In the user story development determine the correct flow and failure states, ensure they are well understood and agreed upon by responsible and impacted parties. Analyze assumptions and conditions for expected and failure flows, ensure they are still accurate and desirable. Determine how to validate the assumptions and enforce conditions needed for proper behaviors. Ensure the results are documented in the user story. Learn from mistakes and offer positive incentives to promote improvements. Secure design is neither an add-on nor a tool that you can add to software.

### Secure Development Lifecycle

Secure software requires a secure development lifecycle, some form of secure design pattern, paved road methodology, secured component library, tooling, and threat modeling. Reach out for your security specialists at the beginning of a software project throughout the whole project and maintenance of your software. Consider leveraging the [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) to help structure your secure software development efforts.

## How to Prevent

-   Establish and use a secure development lifecycle with AppSec
    professionals to help evaluate and design security and
    privacy-related controls

-   Establish and use a library of secure design patterns or paved road
    ready to use components

-   Use threat modeling for critical authentication, access control,
    business logic, and key flows

-   Integrate security language and controls into user stories

-   Integrate plausibility checks at each tier of your application
    (from frontend to backend)

-   Write unit and integration tests to validate that all critical flows
    are resistant to the threat model. Compile use-cases *and* misuse-cases
    for each tier of your application.

-   Segregate tier layers on the system and network layers depending on the
    exposure and protection needs

-   Segregate tenants robustly by design throughout all tiers

-   Limit resource consumption by user or service

## Example Attack Scenarios

**Scenario #1:** A credential recovery workflow might include “questions
and answers,” which is prohibited by NIST 800-63b, the OWASP ASVS, and
the OWASP Top 10. Questions and answers cannot be trusted as evidence of
identity as more than one person can know the answers, which is why they
are prohibited. Such code should be removed and replaced with a more
secure design.

**Scenario #2:** A cinema chain allows group booking discounts and has a
maximum of fifteen attendees before requiring a deposit. Attackers could
threat model this flow and test if they could book six hundred seats and
all cinemas at once in a few requests, causing a massive loss of income.

**Scenario #3:** A retail chain’s e-commerce website does not have
protection against bots run by scalpers buying high-end video cards to
resell auction websites. This creates terrible publicity for the video
card makers and retail chain owners and enduring bad blood with
enthusiasts who cannot obtain these cards at any price. Careful anti-bot
design and domain logic rules, such as purchases made within a few
seconds of availability, might identify inauthentic purchases and
rejected such transactions.

## References

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## List of Mapped CWEs

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)
