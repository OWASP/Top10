# A04:2021 - 安全が確認されない不安な設計
# A04:2021 – Insecure Design

## 因子
## Factors

| 対応する CWE 数 | 最大発生率 | 平均発生率 | 最大網羅率 | 平均網羅率 | 加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 77.25%       | 42.51%       | 6.46                 | 6.78                | 262,407           | 2,691      |

## 概要
## Overview
2021年の新カテゴリーでは、設計やアーキテクチャの欠陥に関するリスクに焦点を当てています。
私たちは脅威のモデル化、セキュアなデザインパターンおよび、リファレンスアーキテクチャなどをもっと利用していくことが必要です。
注目すべき CWE は、CWE-209: エラーメッセージからの情報漏洩、CWE-256: 保護されていない認証情報の保存、CWE-501: 信頼境界線の侵害および、CWE-522: 適切に保護されていないクレデンシャル などです。

A new category for 2021 focuses on risks related to design and
architectural flaws, with a call for more use of threat modeling, secure
design patterns, and reference architectures. Notable CWEs include
*CWE-209: Generation of Error Message Containing Sensitive Information*,
*CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary
Violation*, and *CWE-522: Insufficiently Protected Credentials*.

## 説明
## Description 

「安全が確認されない不安な設計」とは、様々な弱点を表す幅広いカテゴリーで、「安全な設計が行われていない」または、「効果的ではない設計が行われている」と表現されます。
「安全な設計が行われていない」とは、管理策が欠如していることを意味します。例として、センシティブなデータを暗号化すべきコードに、暗号化するためのメソッドがない場合があげられます。
「効果的ではない設計が行われている」とは、脅威が発生する可能性があるにもかかわらず、ドメイン（ビジネス）ロジックの検証が不十分であるために、リスクが顕在化する場合を意味します。
例として、所得区分に基づいてパンデミック税の軽減措置を処理することになっているドメインロジックが、すべての入力が正しく署名されているかどうかを検証しておらず、本来付与されるべきものよりもはるかに大きな軽減措置を提供している場合が挙げられます。

Insecure design is a broad category representing many different
weaknesses, expressed as “missing or ineffective control design.”
Missing insecure design is where a control is absent. For example,
imagine code that should be encrypting sensitive data, but there is no
method. Ineffective insecure design is where a threat could be realized,
but insufficient domain (business) logic validation prevents the action.
For example, imagine domain logic that is supposed to process pandemic
tax relief based upon income brackets but does not validate that all
inputs are correctly signed and provides a much more significant relief
benefit than should be granted.

「安全が確認された安心な設計」とは、常に脅威を評価し、既知の攻撃方法を防ぐためにコードを堅牢に設計し、テストする文化と方法論のことです。
「安全が確認された安心な設計」には、セキュアな開発ライフサイクル、セキュアなデザインパターンまたは信頼性が高く安全性も検証されているコンポーネントライブラリまたはツール、および脅威のモデル化が必要です。

Secure design is a culture and methodology that constantly evaluates
threats and ensures that code is robustly designed and tested to prevent
known attack methods. Secure design requires a secure development
lifecycle, some form of secure design pattern or paved road component
library or tooling, and threat modeling.

## 防止方法
## How to Prevent

-   セキュリティおよびプライバシー関連の管理策の評価および設計を支援するために、アプリケーションセキュリティの専門家とともにセキュアな開発ライフサイクルを確立し、使用する
    
    Establish and use a secure development lifecycle with AppSec
    professionals to help evaluate and design security and
    privacy-related controls

-   セキュアなデザインパターンまたは、信頼性が高く安全性も検証されているコンポーネントライブラリを構築し、使用する

    Establish and use a library of secure design patterns or paved road
    ready to use components

-   重要な認証、アクセスコントロール、ビジネスロジック、および暗号鍵の管理フローに脅威モデルを使用する

    Use threat modeling for critical authentication, access control,
    business logic, and key flows

-   ユニットテストおよび統合テストを実施し、すべての重要なフローが脅威モデルに対して耐性があることを検証する

    Write unit and integration tests to validate that all critical flows
    are resistant to the threat model

## 攻撃シナリオの例
## Example Attack Scenarios

**シナリオ #1:** 
**Scenario #1:** 

クレデンシャルの回復フローには「秘密の質問と答え」が含まれることがあります。
「秘密の質問と答え」は、NIST 800-63b、OWASP ASVS、および OWASP Top 10 で禁止されています。
「秘密の質問と答え」は複数の人が答えを知ることができるため、アイデンティティの証拠として信頼できないためです。
このようなコードは削除し、より安全な設計に置き換えるべきです。

A credential recovery workflow might include “questions
and answers,” which is prohibited by NIST 800-63b, the OWASP ASVS, and
the OWASP Top 10. Questions and answers cannot be trusted as evidence of
identity as more than one person can know the answers, which is why they
are prohibited. Such code should be removed and replaced with a more
secure design.

**シナリオ #2:** 
**Scenario #2:** 

ある映画館チェーンでは団体予約による割引を認めており、最大 15 名までは予約保証金が必要ありません。
攻撃者は、このフローに対する脅威モデルを作成し、数回のリクエストで600席とすべての映画館を一度に予約できるかどうかをテストし、大規模な損失を引き起こすことができます。

A cinema chain allows group booking discounts and has a
maximum of fifteen attendees before requiring a deposit. Attackers could
threat model this flow and test if they could book six hundred seats and
all cinemas at once in a few requests, causing a massive loss of income.

**シナリオ #3:** 
**Scenario #3:** 

ある小売チェーンの電子商取引サイトでは、ダフ屋がオークションサイトに転売するために高級ビデオカードを購入するボットへの対策がなされていません。
この結果、ビデオカードメーカーや小売チェーン店にとっては最悪の評判となり、これらのカードをまったく手に入れることができない熱狂的なファンにとっては不幸をもたらします。
注意深いボット対策の設計や、入手可能になってから数秒以内に購入された場合などのドメインロジックを作成することで、非正規の購入を識別し、そのような取引を拒否することができるかもしれません。

A retail chain’s e-commerce website does not have
protection against bots run by scalpers buying high-end video cards to
resell auction websites. This creates terrible publicity for the video
card makers and retail chain owners and enduring bad blood with
enthusiasts who cannot obtain these cards at any price. Careful anti-bot
design and domain logic rules, such as purchases made within a few
seconds of availability, might identify inauthentic purchases and
rejected such transactions.

## 参考資料
## References

-   \[OWASP Cheat Sheet: Secure Design Principles\] (TBD)

-   NIST – Guidelines on Minimum Standards for Developer Verification of
    > Software  
    > https://www.nist.gov/system/files/documents/2021/07/09/Developer%20Verification%20of%20Software.pdf

## 対応する CWE のリスト
## List of Mapped CWEs

CWE-73 ファイル名やパス名の外部制御
CWE-73 External Control of File Name or Path

CWE-183 許容範囲が広すぎる入力制限
CWE-183 Permissive List of Allowed Inputs

CWE-209 エラーメッセージからの情報漏洩
CWE-209 Generation of Error Message Containing Sensitive Information

CWE-213 互換性のないポリシーによる機密情報の漏洩
CWE-213 Exposure of Sensitive Information Due to Incompatible Policies

CWE-235 想定を超えたパラメータの不適切な処理
CWE-235 Improper Handling of Extra Parameters

CWE-256 パスワードなどのアカウント情報が平文のまま格納されている問題
CWE-256 Unprotected Storage of Credentials

CWE-257 復元可能な形式で保存されたパスワード
CWE-257 Storing Passwords in a Recoverable Format

CWE-266 不正確な特権の割り当て
CWE-266 Incorrect Privilege Assignment

CWE-269 不適切な特権管理
CWE-269 Improper Privilege Management

CWE-280 権限管理の不備
CWE-280 Improper Handling of Insufficient Permissions or Privileges

CWE-311 重要な情報を暗号化していない問題
CWE-311 Missing Encryption of Sensitive Data

CWE-312 重要な情報が平文のまま格納されている問題
CWE-312 Cleartext Storage of Sensitive Information

CWE-313 ファイルやディスクに平文のまま格納されている問題
CWE-313 Cleartext Storage in a File or on Disk

CWE-316 メモリ上に平文のまま格納されている問題
CWE-316 Cleartext Storage of Sensitive Information in Memory

CWE-419 保護されていないプライマリーチャネル
CWE-419 Unprotected Primary Channel

CWE-430 誤ったハンドラーの配置
CWE-430 Deployment of Wrong Handler

CWE-434 適切でないアップロートファイル制限
CWE-434 Unrestricted Upload of File with Dangerous Type

CWE-444 HTTPリクエストの矛盾した解釈（HTTPリクエストスマグリング
CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')

CWE-451 ユーザーインターフェース（UI）による重要情報の誤表示
CWE-451 User Interface (UI) Misrepresentation of Critical Information

CWE-472 不変と仮定される Web パラメータの外部制御
CWE-472 External Control of Assumed-Immutable Web Parameter

CWE-501 信頼境界線の侵害
CWE-501 Trust Boundary Violation

CWE-522 十分でない資格情報保護
CWE-522 Insufficiently Protected Credentials

CWE-525 機密情報を含むWebブラウザのキャッシュの使用
CWE-525 Use of Web Browser Cache Containing Sensitive Information

CWE-539 機密情報を含むパーシステントクッキーの使用
CWE-539 Use of Persistent Cookies Containing Sensitive Information

CWE-579 J2EEのバッドプラクティス：セッションに格納されたシリアライズ不可能なオブジェクト
CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session

CWE-598 GETリクエストのクエリ文字列からの情報漏洩
CWE-598 Use of GET Request Method With Sensitive Query Strings

CWE-602 サーバサイドのセキュリティをクライアントサイドで実施
CWE-602 Client-Side Enforcement of Server-Side Security

CWE-642 重要な状態データの外部制御
CWE-642 External Control of Critical State Data

CWE-646 外部から提供されたファイルのファイル名や拡張子への依存
CWE-646 Reliance on File Name or Extension of Externally-Supplied File

CWE-650 サーバーサイドにおける HTTP メソッドへの過剰な信頼
CWE-650 Trusting HTTP Permission Methods on the Server Side

CWE-653 不十分なコンパートメント化
CWE-653 Insufficient Compartmentalization

CWE-656 隠ぺいによるセキュリティへの依存
CWE-656 Reliance on Security Through Obscurity

CWE-657 セキュリティ設計原則の違反
CWE-657 Violation of Secure Design Principles

CWE-799 適切でない相互作用に対する頻度制御
CWE-799 Improper Control of Interaction Frequency

CWE-807 信頼できない入力に基づいた判断への依存
CWE-807 Reliance on Untrusted Inputs in a Security Decision

CWE-840 ビジネスロジックのエラー
CWE-840 Business Logic Errors

CWE-841 ユーザーの振る舞いに基づいたワークフローに依存した不適切な処理の実施
CWE-841 Improper Enforcement of Behavioral Workflow

CWE-927 センシティブなコミュニケーションへの暗黙的インテントの使用
CWE-927 Use of Implicit Intent for Sensitive Communication

CWE-1021 レンダリングされたUIレイヤーやフレームの不適切な制限
CWE-1021 Improper Restriction of Rendered UI Layers or Frames

CWE-1173 バリデーションフレームワークの不適切な使用
CWE-1173 Improper Use of Validation Framework
