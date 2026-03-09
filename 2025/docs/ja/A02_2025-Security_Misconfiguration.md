# A02:2025 セキュリティ設定の不備 (Security Misconfiguration) ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## 背景 (Background)

本カテゴリは、前回の第5位から第2位へと上昇しました。テストされたアプリケーションの100%で何らかの設定不備が見つかっており、平均出現率は3.00%、CWE（共通弱点一覧）の発生数は71万9千件を超えています。高度な設定が可能なソフトウェアへの移行が進むなか、この順位の上昇は必然と言えます。主要なCWEには、設定 (CWE-16) や、XML外部実体参照 (XXE: XML External Entity) の不適切な制限 (CWE-611) が含まれます。


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
   <td>16</td>
   <td>27.70%</td>
   <td>3.00%</td>
   <td>100.00%</td>
   <td>52.35%</td>
   <td>7.96</td>
   <td>3.97</td>
   <td>719,084</td>
   <td>1,375</td>
  </tr>
</table>



## 説明 (Description)

セキュリティ設定の不備とは、システム、アプリケーション、またはクラウドサービスがセキュリティの観点から誤って構成され、脆弱性が生じている状態を指します。

以下の項目に当てはまる場合、アプリケーションは脆弱である可能性があります。

* アプリケーションスタックのいずれかの層において、適切なセキュリティ要塞化 (Hardening) が欠如している、あるいはクラウドサービスの権限設定が不適切である。
* 不要な機能（ポート、サービス、ページ、アカウント、テスト用フレームワーク、権限など）が有効化またはインストールされている。
* デフォルトのアカウントやパスワードが変更されずに有効なままである。
* 過剰なエラーメッセージを捕捉する中央集中型の設定が欠如しており、スタックトレースなどの詳細な情報がユーザーに露出している。
* システムのアップグレード時に、最新のセキュリティ機能が無効化されている、あるいは安全に設定されていない。
* 後方互換性を過度に優先した結果、安全でない設定が維持されている。
* アプリケーションサーバー、フレームワーク (Struts, Spring, ASP.NET 等)、ライブラリ、データベースなどのセキュリティ設定が安全な値になっていない。
* サーバーがセキュリティヘッダーやディレクティブを送信していない、あるいはそれらが安全な値に設定されていない。

反復可能で一貫したアプリケーションセキュリティ設定の要塞化プロセスがなければ、システムのリスクは高まり続けます。


## 防止方法 (How to Prevent)

安全なインストールプロセスを実装する必要があります。これには以下の対策が含まれます。

* **反復可能な要塞化プロセス：** 適切にロックダウンされた環境を、迅速かつ容易にデプロイできるプロセスを確立してください。開発、QA、本番の各環境は同一の設定とし、認証情報のみを環境ごとに使い分けるべきです。このプロセスを自動化し、安全な環境構築の負荷を最小限に抑えてください。
* **最小限のプラットフォーム：** 不要な機能、コンポーネント、ドキュメント、サンプルを含まない最小限のプラットフォームを構成してください。使用していない機能やフレームワークは削除するか、インストールしないでください。
* **設定レビューとパッチ管理：** パッチ管理プロセスの一環として、セキュリティノートやアップデート、パッチに基づき設定をレビュー・更新してください（[A03 ソフトウェアサプライチェーンの不備](A03_2025-Software_Supply_Chain_Failures.md) を参照）。クラウドストレージ（S3 バケット等）の権限設定も定期的にレビューしてください。
* **セグメント化されたアーキテクチャ：** コンテナ化、セグメンテーション、あるいはクラウドのセキュリティグループ (ACL) を活用し、コンポーネント間やテナント間を安全に分離してください。
* **セキュリティディレクティブの送信：** セキュリティヘッダーなどのディレクティブをクライアントへ送信してください。
* **自動検証プロセス：** すべての環境において、設定の有効性を自動で検証するプロセスを導入してください。
* **中央集中型のエラー管理：** 過剰なエラーメッセージをインターセプトする中央設定を、バックアップとして事前に導入してください。
* **手動検証の実施：** 検証が自動化されていない場合は、少なくとも年に一度は手動で検証を実施してください。
* **プラットフォーム機能の活用：** コードや設定ファイル、パイプラインに静的なキーやシークレットを埋め込むのではなく、プラットフォームが提供するアイデンティティ連携 (Identity Federation)、短命な認証情報 (Short-lived Credentials)、またはロールベースのアクセス制御を活用してください。


## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：** 本番サーバーからサンプルアプリケーションが削除されていなかった。攻撃者は、これらのサンプルに含まれる既知の脆弱性を悪用してサーバーを侵害した。さらに、管理コンソールのデフォルトパスワードが変更されていなかったため、攻撃者は管理者としてログインし、システムを完全に乗っ取った。

**シナリオ #2：** サーバーのディレクトリ一覧表示が無効化されていなかった。攻撃者はディレクトリ構造を把握し、コンパイル済みの Java クラスファイルをダウンロードした。これをデコンパイルしてソースコードをリバースエンジニアリングした結果、アプリケーションに重大なアクセス制御の欠陥があることを突き止めた。

**シナリオ #3：** アプリケーションサーバーの設定により、スタックトレースを含む詳細なエラーメッセージがユーザーに返されていた。これにより、機密情報や、使用されているコンポーネントのバージョン（脆弱性が既知のものを含む）といった内部情報が攻撃者に露呈した。

**シナリオ #4：** クラウドサービスプロバイダー (CSP) のデフォルト設定により、共有権限がインターネットに公開されていた。これにより、クラウドストレージ内に保存されていた機密データが第三者に奪取された。


## 関連資料 (References)

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)
* [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)
* [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)
* [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)
* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)
* [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)
* [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
* [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)
* [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
* [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
* [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
* [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)
* [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
* [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
* [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)


