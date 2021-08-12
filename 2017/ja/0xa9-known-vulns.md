# A9:2017-既知の脆弱性のあるコンポーネントの使用

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 2 | 蔓延度 3 : 検出のしやすさ 2 | 技術面への影響 2 : ビジネス面への影響 |
| 多くの既知の脆弱性に対し、公開されている攻撃方法を見つけることは簡単ですが、それ以外の脆弱性は攻撃方法を新たに開発する労力を要します。| この弱点は広く蔓延しています。コンポーネントを多用する開発スタイルは、開発チームがアプリケーションやAPIにおいて、どのコンポーネントを使用しているかを理解していないため、最新に保たれにくくなります。Retire.jsのような脆弱性スキャナは、脆弱性を見つけるのに役立ちますが、悪用のしやすさを判断するには更なる労力が必要になります。| いくつかの既知の脆弱性は、軽微な影響に留まりますが、これまでの最大級のセキュリティ侵害は、コンポーネントの既知の脆弱性を悪用したものでした。保護する資産によっては、おそらくこのリスクはもっとも注意すべきリスクであるはずです。|

## 脆弱性発見のポイント

以下に該当する場合、脆弱と言えます:

* 使用しているすべてのコンポーネントのバージョンを知らない場合（クライアントサイド・サーバサイドの両方について）。これには直接使用するコンポーネントだけでなく、ネストされた依存関係も含む。
* ソフトウェアが脆弱な場合やサポートがない場合、また使用期限が切れている場合。これには、OSやWebサーバ、アプリケーションサーバ、データベース管理システム（DBMS）、アプリケーション、API、すべてのコンポーネント、ランタイム環境とライブラリを含む場合。
* 脆弱性スキャンを定期的にしていない場合や、使用しているコンポーネントに関するセキュリティ情報を購読していない場合。
* 基盤プラットフォームやフレームワークおよび依存関係をリスクに基づきタイムリーに修正またはアップグレードしない場合。パッチ適用が変更管理の下、月次や四半期のタスクとされている環境でよく起こる。これにより、当該組織は、解決済みの脆弱性について、何日も、場合によっては何ヶ月も不必要な危険にさらされることになる。
* ソフトウェア開発者が、更新やアップグレードまたはパッチの互換性をテストしない場合。
* コンポーネントの設定をセキュアにしていない場合。（**A6:2017-不適切なセキュリティ設定**参照）

## 防止方法

以下に示すパッチ管理プロセスが必要です：

* 未使用の依存関係、不要な機能、コンポーネント、ファイルや文書を取り除く。
* Versions Maven Plugin, OWASP Dependency Check, Retire.jsなどのツールを使用して、クライアントおよびサーバの両方のコンポーネント（フレームワークやライブラリなど）とその依存関係の棚卸しを継続的に行う。
* コンポーネントの脆弱性についてCVEやNVDなどの情報ソースを継続的にモニタリングする。ソフトウェア構成分析ツールを使用してプロセスを自動化する。使用しているコンポーネントに関するセキュリティ脆弱性の電子メールアラートに登録する。
* 安全なリンクを介し、公式ソースからのみコンポーネントを取得する。変更された悪意あるコンポーネントを取得する可能性を減らすため、署名付きのパッケージを選ぶようにする。
* メンテナンスされていない、もしくはセキュリティパッチが作られていない古いバージョンのライブラリとコンポーネントを監視する。パッチ適用が不可能な場合は、発見された問題を監視、検知または保護するために、仮想パッチの適用を検討する。

いかなる組織も、アプリケーションまたはポートフォリオの存続期間は、モニタリングとトリアージを行い更新または設定変更を行う継続的な計画があることを確認する必要があります。

## 攻撃シナリオの例

**シナリオ #1**: コンポーネントは通常、アプリケーション自体と同じ権限で実行されるため、どんなコンポーネントに存在する欠陥も、深刻な影響を及ぼす可能性があります。そのような欠陥は、偶発的（例：コーディングエラー）または意図的（例：コンポーネントのバックドア）両方の可能性があります。
発見済みの悪用可能なコンポーネントの脆弱性の例：

* Apache Struts 2においてリモートで任意のコードが実行される脆弱性[CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638)は、重大な侵害をもたらしています。
* [Internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things)は、頻繁なパッチ適用が困難もしくは不可能ですが、一方でパッチ適用の重要性はますます高まっています。（例：医療機器）

攻撃者を助けるようなツールがあり、パッチが未適用なシステムやシステムの設定ミスを自動的に見つけることができます。例えば、[Shodan IoT search engine](https://www.shodan.io/)は、2014年4月にパッチが適用された[Heartbleed](https://en.wikipedia.org/wiki/Heartbleed)の脆弱性などセキュリティに問題のある機器を見つけることができます。

## 参考資料

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x10-V1-Architecture.md)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)

### 外部資料

* [The Unfortunate Reality of Insecure Libraries](https://cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)

* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
