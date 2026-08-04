# A06:2025 安全性を欠いた設計 (Insecure Design) ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

「安全性を欠いた設計」は、前回から順位を2つ下げて第6位となりました。これは「セキュリティ設定の不備 (A02)」と「ソフトウェアサプライチェーンの失敗 (A03)」が急上昇し、本カテゴリを追い越した結果、こうなりました。2021年に導入されて以来、業界全体で脅威モデリング（Threat Modeling）への関心が高まり、設計の安全性を重視する傾向が強まったことで、一定の改善が見られます。本カテゴリは、設計やアーキテクチャの欠陥に起因するリスクに焦点を当てており、脅威モデリング、安全な設計パターン、およびリファレンスアーキテクチャのさらなる活用を求めています。これには、アプリケーション内部で予期しない状態変化を定義していないといった、ビジネスロジックの不備も含まれます。

私たちは、コーディングにおける「シフトレフト」を超え、セキュア・バイ・デザイン（Secure by Design）の原則に不可欠な、要件定義や設計といった「実装前のアクティビティ」を強化しなければなりません（[今日求められるアプリケーションセキュリティプログラムの確立: 計画・設計フェーズ](0x03_2025-Establishing_a_Modern_Application_Security_Program.md) を参照）。主要な CWE (共通弱点一覧) には、認証情報の保護されていない保存 (CWE-256)、不適切な特権管理 (CWE-269)、危険な種類のファイルの無制限アップロード (CWE-434)、信頼境界の侵害 (CWE-501)、および認証情報の保護不足 (CWE-522) が含まれます。

## スコアテーブル (Score Table)

<table>
  <tr>
   <td>紐付けられた CWE 数</td>
   <td>最大出現率</td>
   <td>平均出現率</td>
   <td>最大網羅率</td>
   <td>平均網羅率</td>
   <td>平均加重悪用スコア</td>
   <td>平均加重影響スコア</td>
   <td>出現総数</td>
   <td>CVE 総数</td>
  </tr>
  <tr>
   <td>39</td>
   <td>22.18%</td>
   <td>1.86%</td>
   <td>88.76%</td>
   <td>35.18%</td>
   <td>6.96</td>
   <td>4.05</td>
   <td>729,882</td>
   <td>7,647</td>
  </tr>
</table>

## 説明 (Description)

安全性を欠いた設計は、「制御設計の欠落または効果の不足」を意味する広範なカテゴリです。「安全性を欠いた設計 (Insecure Design)」と「不適切な実装 (Insecure Implementation)」は明確に区別されるべきです。これらは根本原因、発生フェーズ、および修正方法が異なります。設計が安全であっても実装に不備（バグ）が生じることはありますが、設計自体に欠陥がある場合、たとえ実装を完璧に行っても、特定の攻撃を防ぐためのセキュリティ制御がそもそも存在しないことになります。

安全な設計を実現するためには、以下の 3 要素を柱としたガバナンスが必要です。

### 1. 要件定義とリソース管理 (Requirements and Resource Management)
ビジネス部門と協力し、すべてのデータ資産の機密性、真正性、完全性、可用性に関する保護要件と、期待されるビジネスロジックを収集・調整してください。アプリケーションの露出状況を考慮し、アクセス制御とは別に、テナント間の隔離が必要かどうかを判断します。機能要件および非機能セキュリティ要件を含む技術要件を取りまとめてください。また、セキュリティ活動を含む、設計から運用までの全フェーズをカバーする予算を計画し、調整してください。

### 2. 安全な設計 (Secure Design)
安全な設計とは、脅威を絶えず評価し、既知の攻撃手法を防御できるよう堅牢に設計・テストする文化と手法です。脅威モデリングをリファインメントセッション（または類似のアクティビティ）に統合し、データフローやアクセス制御、その他のセキュリティ制御の変更を注視してください。ユーザーストーリー作成時には、正常なフローだけでなく「失敗時の状態 (Failure States)」を定義し、責任者および影響を受ける関係者間で十分に理解され、合意されていることを確認してください。正常系および異常系の前提条件を分析し、それらが正確かつ望ましい状態を維持していることを確認してください。前提条件を検証し、適切な挙動に必要な条件を強制する方法を決定してください。結果はユーザーストーリーに文書化してください。失敗から学び、改善を促進するためのポジティブなインセンティブを提供してください。安全な設計は、ソフトウェアに後付けできるアドオンやツールではありません。

### 3. 安全な開発ライフサイクル (Secure Development Lifecycle)
ソフトウェアの安全性を確保するには、安全な開発ライフサイクル (SDLC)、安全な設計パターン、舗装された道（Paved Road）の方法論、セキュアなコンポーネントライブラリ、適切なツール、脅威モデリング、およびプロセス改善のためのインシデントポストモータム（事後検証）が必要です。ソフトウェアプロジェクトの開始時から、プロジェクト全体を通じて、そして継続的なソフトウェア保守においても、セキュリティ専門家と連携してください。[OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/) を活用して、安全なソフトウェア開発の取り組みを構造化することを検討してください。

開発者自身が負うべき責任が大きいことは、ときに十分に自覚されていないものです。意識、責任、およびプロアクティブなリスク軽減の文化を醸成してください。セキュリティに関する定期的な意見交換（脅威モデリングセッション中など）は、重要な設計上の意思決定においてセキュリティを考慮するマインドセットを生み出すことができます。

## 防止方法 (How to Prevent) 

* セキュリティ専門家と協力し、セキュリティやプライバシーに関する制御を設計・評価するための SDLC を確立・運用してください。
* 安全な設計パターンのライブラリ、あるいは舗装された道（Paved Road）のコンポーネントを活用してください。
* 認証、アクセス制御、ビジネスロジック、および主要なデータフローに対して、脅威モデリングを継続的に実施してください。
* セキュリティマインドセットを醸成するための教育ツールとして、脅威モデリングを活用してください。
* セキュリティ要件と制御を、ユーザーストーリーに統合してください。
* 各層（フロントエンドからバックエンド）において、妥当性チェック (Plausibility Checks) を統合してください。
* ユニットテストおよび統合テストを作成し、主要なフローが脅威モデルに対して耐性を持っていることを検証してください。正常系 (Use-cases) だけでなく、異常系 (Misuse-cases) のテストも不可欠です。
* 露出状況や保護ニーズに応じて、システム層およびネットワーク層を分離（Segregate）してください。
* 設計段階から、すべての層において堅牢なテナント分離を徹底してください。

## 攻撃シナリオの例 (Example Attack Scenarios) 

**シナリオ #1：不適切な資格情報リカバリ**
資格情報の復旧ワークフローに「秘密の質問と回答」が含まれているケース。これは NIST 800-63b や OWASP ASVS で禁止されています。回答は本人以外も知りうるため、証拠として信頼できません。このような機能は削除し、より安全な設計に置き換える必要があります。

**シナリオ #2：ビジネスロジックの不備（大量予約）**
ある映画館チェーンが、15名以上の予約時にのみデポジットを要求していた。攻撃者がこのフローを分析し、デポジットなしで全館・全席を占有し続ける攻撃が可能であることを突き止めた。これにより、映画館側は甚大な収益損失を被ることになります。

**シナリオ #3：ボット対策の欠如（買い占め）**
eコマースサイトに、転売目的のボットによる買い占め対策が備わっていなかった。結果、高価なビデオカードが発売直後にボットに独占され、一般の愛好家が購入できない事態を招いた。発売から数秒以内の購入を識別して拒否するといった、ドメインロジックに基づいたアンチボット設計が必要です。

## 関連資料 (References)

* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)
* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)
* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)
* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)
* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)
* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)
* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)
* [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)
* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)
* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)

