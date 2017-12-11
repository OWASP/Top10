# A9:2017 既知の脆弱性を持つコンポーネントの使用

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用難易度 2 | 流行度 3 : 検出難易度 2 | 技術的影響度 2 : ビジネスへの影響 |
| 多くの既知の脆弱性に対し、公開されている攻撃方法を見つけることは簡単ですが、それ以外の脆弱性は攻撃方法を新たに開発する労力を要します。| この弱点はとても流行しています。コンポーネントを多用する開発スタイルは、開発チームがアプリケーションやAPIにおいて、どのコンポーネントを使用しているかを理解していないため、最新に保たれにくくなります。Retire.jsのような脆弱性スキャナーは、脆弱性を見つけるのに役立ちますが、悪用のしやすさを判断するには更なる労力が必要になります。| いくつかの既知の脆弱性は、軽微な影響に留まりますが、これまでの最大級のセキュリティ侵害は、コンポーネントの既知の脆弱性を悪用したものでした。守りたい資産によりますが、当リスクは、もっとも注意すべきリスクと言えるかも知れません。|

## 脆弱性有無の確認

下記に該当する場合、脆弱と言える:

* 使用しているすべてのコンポーネントのバージョンを知らない場合（クライアント側・サーバー側の両方について）。これには直接使用するコンポーネントだけでなく、ネストされた依存関係も含む。
* ソフトウェアが、脆弱な場合や、サポートがない場合、また使用期限が切れている場合。これには、OSやWebサーバー、アプリケーションサーバー、データベース管理システム（DBMS）、アプリケーション、API、すべてのコンポーネント、ランタイム環境とライブラリを含む。
* 脆弱性スキャンを定期的にしていない場合や、使用しているコンポーネントに関するセキュリティ情報を購読していない場合。
* 基盤プラットフォームやフレームワークおよび依存関係をリスクに基づきタイムリーに修正またはアップグレードしない場合。パッチ適用が変更管理の下、月次や四半期のタスクとされている環境でよく起こる。これにより、当該企業は、解決済みの脆弱性について、何日も、場合によっては何ヶ月も不必要な危険にさらされることになる。
* ソフトウェア開発者が、更新やアップグレードまたはパッチの互換性をテストしない場合
* コンポーネントの設定をセキュアにしていない場合（**A6:2017-Security Misconfiguration**参照）

## 防止方法

以下に示すパッチ管理プロセスが必要：

* 未使用の依存関係、不要な機能、コンポーネント、ファイルや文書を取り除く
* Versions Maven Plugin, OWASP Dependency Check, Retire.jsなどのツールを使用して、クライアントおよびサーバの両方のコンポーネント（フレームワークやライブラリなど）とその依存関係の棚卸しを継続的に行う
* コンポーネントの脆弱性についてCVEとNVDなどの情報ソースを継続的にモニタリングする。ソフトウェア構成分析ツールを使用してプロセスを自動化する。使用しているコンポーネントに関するセキュリティ脆弱性の電子メールアラートに登録する。
* 安全なリンクを介し、公式ソースからのみコンポーネントを取得する。変更された悪意あるコンポーネントを取得する可能性を減らすため、署名付きのパッケージを選ぶようにする。
* メンテナンスされていないもしくはセキュリティパッチが作られていない古いバージョンのライブラリとコンポーネントを監視する。パッチ適用が不可能な場合は、発見された問題を監視、検知または保護するために、仮想パッチの適用を検討する。

いかなる組織もアプリケーションまたはポートフォリオの存続期間は、モニタリングとトリアージを行い更新または設定変更を行う継続的な計画があることを確認する必要がある。

## 攻撃シナリオの例

**シナリオ #1**: コンポーネントは通常、アプリケーション自体と同じ権限で実行されるため、どんなコンポーネントに存在する欠陥も、深刻な影響を及ぼす可能性がある。そのような欠陥は、偶発的（例：コーディングエラー）または意図的（例：コンポーネントのバックドア）両方の可能性がある。
発見済みの悪用可能なコンポーネントの脆弱性の例：

* Apache Struts 2においてリモートで任意のコードが実行される脆弱性[CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638)は、重大な侵害をもたらしている。
* [internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things)は、頻繁なパッチ適用が困難もしくは不可能だが、パッチ適用の重要性はますます高まっている。（例：医療機器）

攻撃者を助けるような、パッチが未適用もしくはシステムの設定ミスを自動的に見つけるツールが存在する。例えば、[Shodan IoT search engine](https://www.shodan.io/report/89bnfUyJ)は、2014年4月にパッチが適用された[Heartbleed](https://en.wikipedia.org/wiki/Heartbleed)の脆弱性などセキュリティに問題のある機器を見つけることができる。

## 参考資料

### OWASP

* [OWASPアプリケーションセキュリティ検証標準: V1 アーキテクチャ、設計、脅威モデリング](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (Javaと.NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### その他

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
