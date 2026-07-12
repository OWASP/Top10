# A03:2025 ソフトウェアサプライチェーンの不備 (Software Supply Chain Failures) ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

このカテゴリには圧倒的な関心が集まっており、コミュニティ調査における回答者のちょうど半数が、第1位に選んだものです。2013年版に「既知の脆弱性を持つコンポーネントの利用」として初登場して以来、その対象範囲は拡大し、現在では既知の脆弱性だけでなく、サプライチェーン全域の失敗 (Software Supply Chain Failures) を含むようになっています。範囲が広がった一方で、特定の CWE (共通弱点一覧) と CVE (共通脆弱性識別子) の紐付けが難しく、依然として識別の難しさが課題となっています。しかし、収集データによれば、本カテゴリの平均出現率 (Incidence Rate) は 5.19% と全カテゴリの中で最高を記録しています。主要な CWE には、廃止された機能の利用 (CWE-477)、保守されていないサードパーティ製コンポーネントの利用 (CWE-1104)、更新不可能なコンポーネントへの依存 (CWE-1329)、および脆弱なサードパーティ製コンポーネントへの依存 (CWE-1395) が含まれます。

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
   <td>6</td>
   <td>9.56%</td>
   <td>5.72%</td>
   <td>65.42%</td>
   <td>27.47%</td>
   <td>8.17</td>
   <td>5.23</td>
   <td>215,248</td>
   <td>11</td>
  </tr>
</table>

## 説明 (Description)

ソフトウェアサプライチェーンの失敗とは、ソフトウェアの構築、配布、または更新のプロセスにおける破綻や侵害を指します。これらは多くの場合、システムが依存しているサードパーティ製のコード、ツール、またはその他の依存関係における脆弱性や悪意のある変更によって引き起こされます。

以下の項目に当てはまる場合、脆弱である可能性が高いと言えます。

* 使用しているすべてのコンポーネント（クライアント側およびサーバー側の両方）のバージョンを正確に把握していない。これには、直接使用するコンポーネントだけでなく、入れ子になった（透過的な (transitive)）依存関係も含まれます。
* ソフトウェアが脆弱であるか、サポートが終了しているか、あるいは古くなっている。対象は OS、Web/アプリケーションサーバー、データベース (DBMS)、API、ライブラリ、実行環境など多岐にわたります。
* 脆弱性スキャンを定期的に実施しておらず、使用コンポーネントに関するセキュリティ情報の通知も受け取っていない。
* サプライチェーン内の変更を追跡・管理するプロセスが欠如している。IDE (統合開発環境) の拡張機能や更新、コードリポジトリ、ビルド環境、ライブラリの保存方法など、あらゆる変更を文書化する必要があります。
* アクセス制御と最小権限の原則 (Least Privilege) に重点を置いた、サプライチェーン全体の要塞化 (Hardening) が行われていない。
* 職務分掌 (Separation of Duty) が確立されていない。他者のレビューなしに、一人の担当者がコードの記述から本番環境への反映までを完結できてしまう状態は危険です。
* 信頼できないソースから入手したコンポーネントが、本番環境に使用されている、あるいは本番環境に影響を及ぼしうる状態にある。
* プラットフォームやフレームワークのアップデートをリスクに基づいて迅速に行っていない。パッチ適用を月次や四半期ごとのルーチンに固定していると、脆弱性の発覚から修正までの間に、組織が不必要なリスクに晒されることになります。
* 開発者が、パッチ適用後のライブラリの互換性テストを実施していない。
* システムのあらゆる箇所の設定を安全に構成していない（[A02:2025-セキュリティ設定の不備](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) 参照）。
* CI/CD パイプラインのセキュリティが、ビルド対象のシステムよりも脆弱である（特にパイプラインが複雑な場合）。

## 防止方法 (How to Prevent)

以下の項目を含むパッチ管理プロセスを確立してください。

* **SBOM の一元管理：** ソフトウェア全体のソフトウェア部品表 (SBOM: Software Bill of Materials) を一元的に生成・管理してください。
* **依存関係の追跡：** 直接的な依存関係だけでなく、透過的 (transitive) な依存関係もすべて追跡してください。
* **攻撃面の削減：** 未使用の依存関係、不要な機能、コンポーネント、ファイル、ドキュメントを削除してください。
* **継続的な目録化：** OWASP Dependency Track などのツールを用いて、コンポーネントとその依存関係のバージョンを常に目録化 (Inventory) してください。
* **継続的な監視：** CVE や NVD、[Open Source Vulnerabilities (OSV)](https://osv.dev/) を監視し、使用コンポーネントの脆弱性情報を自動的に取得してください。
* **信頼できるソースの利用：** コンポーネントは公式の信頼できるソースから、安全な通信経路を介してのみ入手してください。改ざんのリスクを減らすため、署名済みパッケージの利用を推奨します。
* **戦略的なアップデート：** 依存関係のバージョンは慎重に選択し、必要が生じた際にのみアップグレードしてください。保守されていないライブラリを監視し、パッチ適用が不可能な場合は代替コンポーネントへの移行や、バーチャルパッチ (Virtual Patch) の導入を検討してください。
* **開発ツールの更新：** CI/CD、IDE、その他の開発者向けツールを定期的に更新してください。
* **段階的なデプロイ：** 全システムへの同時アップデートを避け、段階的リリース (Staged Rollout) やカナリアデプロイ (Canary Deployment) を活用して、ベンダー侵害時の被害を最小化してください。

また、以下の変更を追跡するための変更管理プロセスまたは追跡システムを確立してください。

* CI/CD の設定（すべてのビルドツールとパイプライン）
* コードリポジトリ
* サンドボックス環境
* 開発者の IDE
* SBOM ツールおよび生成された成果物
* ログシステムとログ
* SaaS などのサードパーティ統合
* 成果物リポジトリ
* コンテナレジストリ

また、以下のシステムにおいて要塞化 (Hardening) を実施し、多要素認証 (MFA) の導入とアクセス管理 (IAM) を厳格化してください。

* **コードリポジトリ：** シークレットのコミット禁止、ブランチ保護、バックアップの実施。
* **開発者の端末：** 定期的なパッチ適用、監視の実施。
* **ビルドサーバーと CI/CD：** 職務分掌、署名付きビルド、環境ごとに分離されたシークレット管理、改ざん防止ログの導入。
* **成果物 (Artifacts)：** 署名やタイムスタンプによる完全性の確保。環境ごとに再ビルドするのではなく、同一の成果物を昇格させるプロセス（不変のビルド）を徹底してください。

すべての組織は、アプリケーションやポートフォリオのライフサイクル全体を通じて、アップデートや設定変更を監視・選別・適用するための継続的な計画を確保しなければなりません。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：信頼できるベンダーの侵害**
ベンダーがマルウェアに侵害され、アップデートを通じて利用者のシステムも侵害されるケースです。
* **SolarWinds 侵害事件 (2019 年)：** 約 18,000 の組織に影響を与えたサプライチェーン攻撃の代表例です。[詳細記事](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**シナリオ #2：特定条件でのみ発動する悪意ある挙動**
* **Bybit 資産奪取事件 (2025 年)：** [ウォレットソフトウェアへのサプライチェーン攻撃](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/)により、15 億ドルが盗まれました。この攻撃は、標的のウォレットが使用されている特定の条件下でのみ実行されるよう設計されていました。

**シナリオ #3：自己拡散型ワーム**
* **[`Shai-Hulud` サプライチェーン攻撃](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) (2025 年)：** npm エコシステムに影響を与えた、初の自己拡散型 npm ワームです。悪意のあるパッケージを起点に、インストール後スクリプト (Post-install Script) を介して機密データを窃取し、公開 GitHub リポジトリに流出させました。このワームは環境内の npm トークンを検知し、アクセス可能な他のパッケージにも自身を自動的にプッシュして拡散しました。npm によって阻止されるまでに 500 以上のパッケージバージョンに到達しました。このサプライチェーン攻撃は高度で拡散が速く、開発者のマシンを標的とすることで、開発者自身がサプライチェーン攻撃の主要な標的となっていることを示しました。

**シナリオ #4：コンポーネントの脆弱性の悪用**
* **Struts 2 (CVE-2017-5638)：** 任意コード実行 (RCE) を可能にする脆弱性で、多くの情報漏洩の原因となりました。
* **Log4Shell (CVE-2021-44228)：** Apache Log4j における RCE のゼロデイ脆弱性で、広範な攻撃キャンペーンに悪用されました。

## 関連資料 (References)

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Open Source Vulnerabilities (OSV)](https://osv.dev/)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)
* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)
* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)
* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)


