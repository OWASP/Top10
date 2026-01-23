# A08:2025 ソフトウェアまたはデータの完全性の不備 (Software or Data Integrity Failures) ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

「ソフトウェアまたはデータの完全性の失敗」は、前回に引き続き第8位となりました。名称は、範囲をより明確にするために「ソフトウェア *および* データの完全性の失敗」から微修正されています。このカテゴリは、信頼境界 (Trust Boundary) の維持に失敗し、ソフトウェア、コード、およびデータ資産の完全性検証を怠るリスクに焦点を当てています。これは「A03: ソフトウェアサプライチェーンの失敗」よりも低レイヤーな検証不備を対象としています。主要な CWE (共通弱点一覧) には、信頼できない制御球からの機能の取り込み (CWE-829)、動的に決定されるオブジェクト属性の不適切な修正 (CWE-915)、および信頼できないデータのデシリアライゼーション (CWE-502) が含まれます。

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
   <td>14</td>
   <td>8.98%</td>
   <td>2.75%</td>
   <td>78.52%</td>
   <td>45.49%</td>
   <td>7.11</td>
   <td>4.79</td>
   <td>501,327</td>
   <td>3,331</td>
  </tr>
</table>

## 説明 (Description)

本リスクは、コードやインフラにおいて、無効または信頼できないデータやコードを「妥当で信頼できるもの」として扱ってしまう不備に関連しています。

「出所不明なソフトウェアを検証なしに受け入れるのは、中身を確認せずに封筒を開封し、そこに書かれた指示に従ってしまうようなものです。たとえその指示が家を壊すものであっても、疑わずに実行してしまえば手遅れになります。」

以下のようなケースが脆弱性の典型例です。

* **信頼できないソースの利用：** 信頼できないリポジトリや CDN (コンテンツデリバリネットワーク) 上のプラグイン、ライブラリ、モジュールに依存している。
* **不セキュアな CI/CD パイプライン：** ソフトウェアの完全性チェックを伴わないパイプラインは、不正アクセスや悪意あるコードの混入、システム侵害を招く恐れがあります。
* **署名なき自動アップデート：** 多くのアプリケーションが備える自動更新機能において、ダウンロードされた更新ファイルの完全性を十分に検証せずに適用している。
* **不セキュアなデシリアライゼーション：** 攻撃者が内容を閲覧・改ざんできる構造（シリアライズされたオブジェクトやデータ）を、検証なしに復元して利用している。

## 防止方法 (How to Prevent)

* **デジタル署名の活用：** デジタル署名やそれに類する仕組みを用い、ソフトウェアやデータが意図したソースからのものであり、改ざんされていないことを検証してください。
* **信頼できるリポジトリの限定：** npm や Maven 等の依存関係管理において、信頼できるリポジトリのみを利用するように設定してください。リスクプロファイルが高い場合は、内部で精査済みのリポジトリをホスティングすることを検討してください。
* **変更レビュープロセスの確立：** コードや設定の変更に対するレビュープロセスを徹底し、悪意あるコードがパイプラインに混入する機会を最小限に抑えてください。
* **パイプラインの要塞化：** ビルドおよびデプロイプロセスを流れるコードの完全性を確保するため、CI/CD パイプラインに対して適切な分離、設定、およびアクセス制御を実施してください。
* **シリアライズデータの検証：** 信頼できないクライアントから、署名や暗号化のなされていないシリアライズされたデータを受け取らないでください。利用が必要な場合は、改ざんやリプレイ攻撃を検知するためのデジタル署名や完全性チェックを必ず実施してください。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：信頼できないソースからの機能取り込み**
ある企業が利便性のために、外部サービスプロバイダーの DNS マッピング（例：`support.myCompany.com`）を設定した。これにより、自社ドメインの認証 Cookie が外部プロバイダーへも送信されるようになり、プロバイダー側のインフラにアクセスできる攻撃者がユーザーのセッションを奪取可能になった。

**シナリオ #2：署名なきアップデート**
多くのホームルーターやセットトップボックスにおいて、署名されていないファームウェアによるアップデートが行われている。これは攻撃者にとって格好の標的となり、一度配布されてしまうと将来のバージョンで修正されるまで是正する手段がないという深刻な問題を引き起こします。

**シナリオ #3：信頼できないソースからのパッケージ利用**
開発者が公式のパッケージマネージャーではなく、Web サイトから直接署名のないパッケージをダウンロードして利用した。そのパッケージには悪意のあるコードが含まれており、完全性を検証する術がなかったために侵害が発生した。

**シナリオ #4：不セキュアなデシリアライゼーション**
React アプリケーションが Spring Boot マイクロサービスと通信する際、状態をシリアライズしてリクエストごとに受け渡していた。攻撃者が Java オブジェクトの署名（Base64 形式の "rO0"）に気づき、デシリアライゼーション・スキャナーを用いてアプリケーションサーバー上でリモートコード実行 (RCE) を達成した。

## 関連資料 (References)

* [OWASP Cheat Sheet: ソフトウェアサプライチェーンのセキュリティ](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: デシリアライゼーション](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [SAFECode: ソフトウェアの完全性制御 (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [SolarWinds 侵害事件の深層 (NPR 記事)](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

