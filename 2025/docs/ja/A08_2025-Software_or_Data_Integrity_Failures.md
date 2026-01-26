# A08:2025 ソフトウェアまたはデータの完全性の不備 (Software or Data Integrity Failures) ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

「ソフトウェアまたはデータの完全性の失敗」は、前回に引き続き第8位となりました。名称は、範囲をより明確にするために「ソフトウェア *および* データの完全性の失敗」から微修正されています。このカテゴリは、信頼境界 (Trust Boundary) の維持に失敗し、ソフトウェア、コード、およびデータ資産の完全性検証を怠るリスクに焦点を当てています。これは「A03: ソフトウェアサプライチェーンの不備」よりも低レイヤーな検証不備を対象としています。主要な CWE (共通弱点一覧) には、信頼できない制御球からの機能の取り込み (CWE-829)、動的に決定されるオブジェクト属性の不適切な修正 (CWE-915)、および信頼できないデータのデシリアライゼーション (CWE-502) が含まれます。

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

ソフトウェアおよびデータの完全性の不備は、無効または信頼できないコードやデータを、信頼できる妥当なものとして扱ってしまうコードやインフラに関連しています。たとえば、信頼できないソース、リポジトリ、CDN (コンテンツデリバリネットワーク) からのプラグイン、ライブラリ、モジュールに依存しているアプリケーションがこれに該当します。ソフトウェアの完全性チェックを提供・消費しない安全でない CI/CD パイプラインは、不正アクセス、悪意あるコード、またはシステム侵害の可能性をもたらします。また、信頼できない場所からコードや成果物を取得し、使用前に検証しない（署名の確認などを行わない）CI/CD も同様です。さらに、多くのアプリケーションは自動更新機能を備えていますが、十分な完全性検証なしに更新がダウンロードされ、以前は信頼されていたアプリケーションに適用されます。攻撃者は独自の更新をアップロードして配布し、すべてのインストール先で実行させる可能性があります。もう一つの例は、オブジェクトやデータが攻撃者が閲覧・改ざんできる構造にエンコードまたはシリアライズされている場合で、安全でないデシリアライゼーションに対して脆弱になります。

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

**シナリオ #4：安全でないデシリアライゼーション**
React アプリケーションが Spring Boot マイクロサービスと通信する際、状態をシリアライズしてリクエストごとに受け渡していた。攻撃者が Java オブジェクトの署名（Base64 形式の "rO0"）に気づき、デシリアライゼーション・スキャナーを用いてアプリケーションサーバー上でリモートコード実行 (RCE) を達成した。

## 関連資料 (References)

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
* [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
* [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)
* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
* [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)
* [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)
* [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)
* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
* [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)
* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
* [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)

