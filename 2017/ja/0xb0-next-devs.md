# +D 開発者のための次のステップ

## 反復可能なセキュリティプロセスと標準セキュリティ制御の確立と使用

Webアプリケーションのセキュリティに関して不慣れか、これらのリスクに既に非常に精通しているかにかかわらず、セキュアなWebアプリケーションの構築や存在する脆弱性の修正は困難な場合があります。大規模なポートフォリオを管理しなければならない場合には、この作業はかなり気力をくじきます。

組織や開発者がコスト効率を考慮しながら、アプリケーションのセキュリティリスクを減らせるように、OWASPは、組織でのアプリケーションセキュリティに着手するための数々の無料でオープンなリソースを開発しています。セキュアなWebアプリケーションやAPIを構築するためにOWASPが開発してきた多くのリソースの一部を以下に示します。次のページでは、WebアプリケーションやAPIのセキュリティを検証する際に、組織が活用できるOWASPの他のリソースを記載しています。

| 活動 | 説明 |
| --- | --- |
| アプリケーションセキュリティ要件 | セキュアなWebアプリケーション開発のために、各アプリケーションにおけるセキュリティ要件を定義しなければなりません。OWASPでは、アプリケーションのセキュリティ要件設定におけるガイドとして[OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)を活用することを推奨します。もし開発を外部に委託するのであれば、[OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex)を参照して下さい。**注意**: このドキュメントは米国の契約法に基づきます。そのため、当該ドキュメントのサンプルを活用する前に、弁護士に相談してください。 |
| アプリケーションセキュリティアーキテクチャ | アプリケーションやAPIにセキュリティを後付けで組み込むよりもむしろ、開発初期段階からセキュリティを設計に組み込む方が、コスト効率がずっと良くなります。OWASPでは、まず開発初期からセキュリティを設計に組み込む指針に[OWASP Prevention Cheat Sheets](https://cheatsheetseries.owasp.org/)を推奨します。 |
| 標準的なセキュリティ制御 | 強力かつ可用なセキュリティ制御の構築は困難です。標準なセキュリティ制御を組み合わせることで、セキュアなアプリケーションまたはAPI開発を根本的に簡略化できます。開発者はまず[OWASP Prevention Cheat Sheets](https://cheatsheetseries.owasp.org/) を参照するとよいでしょう。そして、最新のフレームワークでは、認可・検証・CSRF対策などの標準的なセキュリティ制御を効率よく実装できます。 |
| セキュアな開発ライフサイクル | セキュアなアプリケーションやAPIを開発する際に、組織が従うべきプロセスを改善するため、OWASPは[OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/)を推奨しています。組織が直面する特定のリスクに適応するソフトウェアセキュリティの戦略を構築および実施する際に、このモデルが役に立ちます。 |
| アプリケーションセキュリティ教育 | [OWASP Education Committee](https://owasp.org/www-committee-education-and-training/)では、Webアプリケーションセキュリティに関する開発者向けトレーニングに役立つ教育コンテンツを公開しています。脆弱性に関する実地訓練には、[OWASP WebGoat](https://owasp.org/www-project-webgoat/)、[WebGoat.NET](https://github.com/jerryhoff/WebGoat.NET)、[OWASP NodeJS Goat](https://owasp.org/www-project-node.js-goat/)、[OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/)、そして[OWASP Broken Web Applications Project](https://github.com/chuckfw/owaspbwa/)を試して下さい。最新情報の入手には、[OWASP AppSec Conference](https://owasp.org/events/)、[OWASP Conference Training](https://owasp.org/events/)、そして各地で開催される[OWASP Chapter meetings](https://owasp.org/chapters/)に参加して下さい。 |

他にも数多くのOWASPの資料が入手できます。[OWASP Projects](https://owasp.org/projects/)にアクセスして下さい。そこでOWASP project inventoryを開くと、すべてのFlagship、Labs、Incubatorプロジェクトがあります。ほとんどのOWASPの資料は[wiki](https://owasp.org/)で閲覧ができます。そしてOWASPの多くの文書を[ハードコピーや電子書籍](https://stores.lulu.com/owasp)で注文できます。
