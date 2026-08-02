# A09:2025 セキュリティログとアラートの不備 (Security Logging and Alerting Failures) ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

「セキュリティログとアラートの不備」は、前回から引き続き第 9 位となりました。今回の名称変更は、単にログを記録するだけでなく、有意義なログイベントに対して行動を促すための「アラート機能」の重要性を強調したものです。本カテゴリは、コミュニティ調査への参加者の投票により 3 回連続でリスト入りしました。自動テストによる検出が極めて困難なため、CVE/CVSS データ上の代表数は 723 件と全カテゴリ中で最小ですが、可視性の確保、インシデント発生時のアラート、およびフォレンジック (Forensics)（鑑識）において極めて甚大な影響を及ぼします。主要な CWE (共通弱点一覧) には、ログファイルへの出力エンコーディング不備 (CWE-117)、ログファイルへの機密情報の挿入 (CWE-532)、および不十分なロギング (CWE-778) が含まれます。

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
   <td>5</td>
   <td>11.33%</td>
   <td>3.91%</td>
   <td>85.96%</td>
   <td>46.48%</td>
   <td>7.19</td>
   <td>2.65</td>
   <td>260,288</td>
   <td>723</td>
  </tr>
</table>

## 説明 (Description)

ロギングと監視 (Monitoring) がなければ攻撃や侵害を検知できず、適切なアラート (Alerting) がなければ、セキュリティインシデント発生時に迅速かつ効果的な対応をとることが困難になります。

以下のような状況にある場合、アプリケーションは脆弱です。

* ログイン、ログイン失敗、および高価値な取引などの監査可能なイベントが記録されていない、あるいは不整合である（例：ログイン成功のみを記録し、失敗を記録していない）。
* 警告やエラーが発生しても、ログメッセージが生成されない、あるいは不適切で不明確である。
* ログの完全性 (Integrity) が保護されておらず、改ざんのリスクに晒されている。
* アプリケーションや API のログが、不審なアクティビティに対して監視されていない。
* ログがローカルに保存されるだけで、適切にバックアップされていない。
* 適切なアラート閾値やレスポンス・エスカレーションプロセスが機能しておらず、アラートが合理的な時間内に受信・確認されない。
* ペネトレーションテストや DAST (動的アプリケーションセキュリティテスト) ツール（Burp や ZAP 等）によるスキャンが、アラートをトリガーしない。
* アプリケーションが進行中の攻撃をリアルタイム、あるいはそれに近い速度で検知・通知・エスカレーションできない。
* ログやアラートの内容がユーザーや攻撃者に露出している（[A01:2025 アクセス制御の不備](A01_2025-Broken_Access_Control.md) 参照）、あるいは個人識別情報 (PII) や健康情報 (PHI) などの記録すべきでない機密情報がログに含まれている。
* ログデータが適切にエンコードされておらず、ロギングまたは監視システム自体へのインジェクション攻撃を許容している。
* エラーや例外的な状況の処理に失敗しているため、システムがエラーを認識できず、結果として問題を記録できない。
* 特定の異常事態を認識するための適切なアラート用「ユースケース」が不足している、あるいは陳腐化している。
* 誤検知 (False Positive) が多すぎて重要なアラートを判別できず、SOC (セキュリティ運用センター) チームが物理的な過負荷や「警報疲れ」を起こしている。
* プレイブック (Playbook)（対応手順書）が不完全、あるいは欠落しているため、検知されたアラートを正しく処理できない。

## 防止方法 (How to Prevent)

開発者は、アプリケーションのリスクに応じて以下の制御を実装してください。

* **十分なユーザーコンテキストの記録：** すべてのログイン、アクセス制御、およびサーバー側の入力検証の失敗を、悪意あるアカウントの特定に必要な情報とともに記録し、事後のフォレンジック分析が可能な期間保存してください。
* **網羅的なロギング：** セキュリティ制御が含まれるすべての箇所において、成否にかかわらずログを生成してください。
* **管理ソリューションへの適合：** ログ管理ソリューションが容易に処理できる形式でログを生成してください。
* **エンコーディングの徹底：** ロギングシステムへの攻撃を防ぐため、ログデータを正しくエンコードしてください。
* **監査証跡の保護：** ログの改ざんや消去を防ぐため、追加専用 (Append-only) のデータベーステーブルなどの完全性制御を備えた監査証跡を確保してください。
* **安全なエラー処理：** エラーが発生した取引は確実にロールバックしてください。常に安全な側で終了 (Fail closed) させてください。
* **積極的なアラート発行：** アプリケーションやユーザーが不審な挙動を示した際のアラート発行基準を開発者に提示するか、専用のシステムを導入してください。
* **運用の確立：** 監視とアラートのユースケースおよびプレイブックを確立し、SOC チームが迅速に対応できるようにしてください。
* **ハニートークン (Honeytokens) の活用：** ダミーデータや偽のユーザー識別子を「罠」として仕込み、そこへのアクセスによって誤検知のない即時アラートを生成してください。
* **行動分析と AI の支援：** 誤検知率を低く抑えるための追加手法として、行動分析や AI の活用を検討してください。
* **インシデント対応計画の策定：** NIST 800-61r2 等に基づいた対応・復旧計画を確立し、開発者に攻撃の予兆を報告する方法を教育してください。

オープンソース製品（OWASP ModSecurity Core Rule Set や ELK スタック等）や、商用の可観測性 (Observability) ツールを活用して、リアルタイムに近い速度での防御・対応体制を構築することを推奨します。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：長期にわたる侵害の放置**
ある小児医療保険サイトで監視が欠如していたため、350万人以上の子供の機密記録が攻撃者によって改ざんされていた事実に気づくことができませんでした。外部からの指摘で発覚した際、侵害は 2013 年から 7 年以上も続いていたことが判明しました。

**シナリオ #2：サードパーティ経由の漏洩**
インドの大手航空会社において、数百万人の乗客データ（パスポートやクレジットカード情報）が流出しました。侵害はクラウドホスティングプロバイダーで発生しており、航空会社がその事実を知らされたのは、侵害発生からかなりの時間が経過した後でした。

**シナリオ #3：決済アプリの脆弱性と制裁金**
欧州の大手航空会社が決済アプリの脆弱性を突かれ、40万件以上の顧客データを奪取されました。適切な検知と監視が行われていなかった結果、GDPR 違反として 2,000 万ポンドの制裁金を科されました。

## 関連資料 (References)

- [OWASP Proactive Controls: C9 ロギングと監視の実装](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)
- [OWASP Application Security Verification Standard: V16 セキュリティロギングとエラー処理](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)
- [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)
- [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)
- [NIST SP 800-61r2: インシデント対応ガイド](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Snowflake 侵害事件における実例](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)
* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)


