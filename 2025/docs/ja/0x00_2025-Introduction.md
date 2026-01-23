![OWASP Logo](../assets/TOP_10_logo_Final_Logo_Colour.png)

# ウェブアプリケーションにおける10の重大なセキュリティリスク (The Ten Most Critical Web Application Security Risks)

# 導入 (Introduction)

第8版となる「OWASP Top 10」へようこそ！

データ提供や調査にご協力いただいた皆様に、心より感謝申し上げます。皆様の知見なしには、今回の更新は成し得ませんでした。 **ありがとうございます！**

## OWASP Top 10:2025 の紹介

* [A01:2025 - アクセス制御の不備 (Broken Access Control)](A01_2025-Broken_Access_Control.md)
* [A02:2025 - セキュリティ設定の不備 (Security Misconfiguration)](A02_2025-Security_Misconfiguration.md)
* [A03:2025 - ソフトウェアサプライチェーンの不備 (Software Supply Chain Failures)](A03_2025-Software_Supply_Chain_Failures.md)
* [A04:2025 - 暗号化の不備 (Cryptographic Failures)](A04_2025-Cryptographic_Failures.md)
* [A05:2025 - インジェクション (Injection)](A05_2025-Injection.md)
* [A06:2025 - 安全性を欠いた設計 (Insecure Design)](A06_2025-Insecure_Design.md)
* [A07:2025 - 認証の不備 (Authentication Failures)](A07_2025-Authentication_Failures.md)
* [A08:2025 - ソフトウェアまたはデータの完全性の不備 (Software or Data Integrity Failures)](A08_2025-Software_or_Data_Integrity_Failures.md)
* [A09:2025 - セキュリティログとアラートの不備 (Security Logging and Alerting Failures)](A09_2025-Security_Logging_and_Alerting_Failures.md)
* [A10:2025 - 例外的な状況への不適切な対応 (Mishandling of Exceptional Conditions)](A10_2025-Mishandling_of_Exceptional_Conditions.md)


## 2025年版における主な変更点

2025年版では、2つのカテゴリが新設され、1つが統合されました。私たちは、表面的な「症状 (symptoms)」ではなく、可能な限り「根本原因 (root cause)」に焦点を当てるよう努めています。ソフトウェア開発とセキュリティの複雑さを考慮すると、カテゴリ間の重複を完全になくすことは事実上不可能です。

![Mapping](../assets/2025-mappings.png)

* **[A01:2025 - アクセス制御の不備](A01_2025-Broken_Access_Control.md)** は、最も深刻なリスクとして引き続き第1位となりました。テストされたアプリケーションの平均3.73%に、本カテゴリの40のCWE（共通弱点一覧 (Common Weakness Enumerations)）が1つ以上含まれています。上図の破線が示す通り、サーバーサイドリクエストフォージェリ (SSRF: Server-Side Request Forgery) は本カテゴリに統合されました。
* **[A02:2025 - セキュリティ設定の不備](A02_2025-Security_Misconfiguration.md)** は、2021年の第5位から第2位へと上昇しました。今回のデータでは設定の不備がより顕著に見られ、アプリケーションの3.00%に本カテゴリの16のCWEが含まれています。ソフトウェアエンジニアリングにおいて、アプリケーションの挙動が設定に依存する割合が増え続けている現状を反映しています。
* **[A03:2025 - ソフトウェアサプライチェーンの不備](A03_2025-Software_Supply_Chain_Failures.md)** は、2021年版の「脆弱で古くなったコンポーネント」を拡張したものです。依存関係、ビルドシステム、配布インフラの全体にわたる侵害を対象としています。本カテゴリはコミュニティ調査で圧倒的な票を集めました。現状、収集データ上の出現頻度は限定的ですが、CVEにおける平均的な悪用可能性 (exploit) と影響 (impact) のスコアが最も高くなっています。
* **[A04:2025 - 暗号化の不備](A04_2025-Cryptographic_Failures.md)** は、第2位から第4位へ後退しました。平均3.80%のアプリケーションに、本カテゴリの32のCWEが含まれています。本不備は、機密情報の露出 (sensitive data exposure) やシステムの侵害 (system compromise) を招く恐れがあります。
* **[A05:2025 - インジェクション](A05_2025-Injection.md)** は、第3位から第5位へ順位を下げました。最も多くテストされているカテゴリの一つであり、38のCWEに関連するCVE数が最大です。インジェクションには、クロスサイトスクリプティング (XSS)（高頻度・低影響）からSQLインジェクション（低頻度・高影響）まで、幅広い脆弱性が含まれます。
* **[A06:2025 - 安全性を欠いた設計](A06_2025-Insecure_Design.md)** は、第4位から第6位へ順位を下げました。2021年の導入以来、脅威モデリング (threat modeling) の普及など、安全な設計への意識向上と業界の進展が見られます。
* **[A07:2025 - 認証の不備](A07_2025-Authentication_Failures.md)** は、第7位を維持しました。実態を反映するため、名称を微修正しています。依然として重要な領域ですが、標準的な認証フレームワークの活用により、不備の発生が抑制され始めています。
* **[A08:2025 - ソフトウェアまたはデータの完全性の不備](A08_2025-Software_or_Data_Integrity_Failures.md)** は、引き続き第8位です。信頼境界の維持や、コード・データの完全性検証の失敗に焦点を当てています。
* **[A09:2025 - セキュリティログとアラートの不備](A09_2025-Security_Logging_and_Alerting_Failures.md)** は、第9位を維持しました。適切なアクションを促す「アラート機能」を強調するため、名称を変更しています。アラートを伴わないログ出力には、インシデント特定においてほとんど価値がありません。
* **[A10:2025 - 例外的な状況への不適切な対応](A10_2025-Mishandling_of_Exceptional_Conditions.md)** は、2025年版の新カテゴリです。エラー処理の不備やロジックエラー、フェイルオープンなど、異常状態に起因する24のCWEを含みます。


## 手法 (Methodology)

今回の OWASP Top 10 も、データに基づいた判断 (data-informed) を行っていますが、盲目的なデータ至上主義 (data-driven) ではありません。統計データから12のカテゴリをランク付けし、そのうち2つをコミュニティ調査の結果に基づいて選出しました。統計データは「過去」を示すものですが、実務者は「現場」で、テスト手法が確立される前の新たなリスクに直面しているからです。データに現れにくい本質的なリスクを反映させるため、フロントラインの専門家の声を重視しています。


## カテゴリの構造

今回、CWEの制限を設けずにデータを募った結果、分析対象は589件にまで拡大しました。この大幅な増加に伴い、カテゴリ構造を再設計しました。

私たちは、「症状 (symptom)」ではなく「根本原因 (root cause)」に基づいた分類を徹底しています。根本原因（例：暗号化の失敗）に焦点を当てることで、より論理的な修正ガイダンスの提供が可能になります。また、言語やフレームワークに応じて適切な学習ができるよう、1カテゴリあたりのCWE数を最大40件に制限しました。

トップ10を個別のCWEのリストにしない理由は2つあります。第一に、特定の言語やフレームワークに依存しない汎用性を持たせるためです。第二に、共通の脆弱性には複数のCWEが存在するため、これらをカテゴリとして括ることで、組織全体の意識の底上げを図るためです。


## カテゴリ選定におけるデータの活用

リスク評価にあたっては、CVEデータから「悪用可能性 (Exploitability)」と「技術面への影響 ( (Technical) Impact )」を算出しました。OWASP Dependency Check を活用し、約17万5千件のCVEレコードからCVSSスコアを抽出・分析しています。

CVSS v4.0 はスコアリングアルゴリズムが根本的に変更されており、v2/v3のようなスコア算出が困難なため、2025年版では採用を見送りました。今後の版での活用方法を検討する予定です。


## コミュニティ調査の意義

統計データは自動テストが可能な範囲に限定されがちで、最新のトレンドを反映するまでに時間がかかります。そのため、全10カテゴリのうち2つをコミュニティ調査から選出しています。これにより、データにはまだ現れていない「現場で認識されている高いリスク」をリストに反映させています。


## データ提供者の皆様への謝辞

以下の組織（および複数の匿名提供者）から、280万件以上のアプリケーションに関する貴重なデータをご提供いただきました。心より感謝申し上げます。

* Accenture (Prague)
* Anonymous (multiple)
* Bugcrowd
* Contrast Security
* CryptoNet Labs
* Intuitor SoftTech Services
* Orca Security
* Probely
* Semgrep
* Sonar
* usd AG
* Veracode
* Wallarm

## 主執筆者 (Lead Authors)
* Andrew van der Stock - X: [@vanderaj](https://x.com/vanderaj)
* Brian Glas - X: [@infosecdad](https://x.com/infosecdad)
* Neil Smithline - X: [@appsecneil](https://x.com/appsecneil)
* Tanya Janca - X: [@shehackspurple](https://x.com/shehackspurple)
* Torsten Gigler - Mastodon: [@torsten_gigler@infosec.exchange](https://infosec.exchange/@torsten_gigler)

## 課題の報告およびプルリクエスト

修正や課題の報告はこちらからお願いします。

### プロジェクトリンク：
* [ホームページ](https://owasp.org/www-project-top-ten/)
* [GitHub リポジトリ](https://github.com/OWASP/Top10)

