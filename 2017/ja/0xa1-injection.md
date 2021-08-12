# A1:2017-インジェクション

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 3 | 蔓延度 2 : 検出のしやすさ 3 | 技術面への影響 3 : ビジネス面への影響 |
| 環境変数、パラメータ、外部及び内部のWebサービス、そしてあらゆる種類のユーザといった、ほとんどすべてのデータソースはインジェクションの経路となりえます。[インジェクション欠陥](https://owasp.org/www-community/Injection_Flaws)は、攻撃者が悪意を持ったデータをインタープリタに送ることができる場合に発生します。 | インジェクション欠陥は、特にレガシーコードでは、とても一般的です。インジェクション脆弱性は、SQL、LDAP、XPath、あるいはNoSQLクエリ、OSコマンド、XMLパーサー、SMTPヘッダー、式言語、およびORMクエリでよく見られます。インジェクション欠陥は、コードを調べると簡単に発見できます。スキャナやファジングは、攻撃者がインジェクション欠陥を見つけるのに役立ちます。 |インジェクションは、データの損失、破壊、権限ない者への情報漏洩、アカウンタビリティの喪失、またはアクセス拒否につながる可能性があります。インジェクションは、ホストの完全な乗っ取りにつながることがあります。ビジネスへの影響は、アプリケーションとデータの重要性に依存します。|


## 脆弱性発見のポイント

次のような状況では、アプリケーションはこの攻撃に対して脆弱です:

* ユーザが提供したデータが、アプリケーションによって検証、フィルタリング、またはサニタイズされない。
* コンテキストに応じたエスケープが行われず、動的クエリまたはパラメータ化されていない呼出しがインタープリタに直接使用される。
* オブジェクト・リレーショナル・マッピング（ORM）の検索パラメータに悪意を持ったデータが使用され、重要なレコードを追加で抽出してしまう。
* 悪意を持ったデータを直接または連結して使う。例えば、動的クエリ、コマンド、ストアド・プロシージャにおいて構文に悪意を持ったデータを組み合わせる形でSQLやコマンドが組み立てられる。

より一般的なインジェクションとしては、SQL、NoSQL、OSコマンド、オブジェクト・リレーショナル・マッピング（ORM）、LDAP、およびEL式（Expression Language）またはOGNL式（Object Graph Navigation Library）のインジェクションがあります。コンセプトはすべてのインタープリタで同じです。ソースコードをレビューすれば、インジェクションに対してアプリケーションが脆弱であるか最も効果的に検出できます。そして、すべてのパラメータ、ヘッダー、URL、Cookie、JSON、SOAP、およびXMLデータ入力の完全な自動テストも効果的です。また、組織は静的ソースコード解析ツール([SAST](https://owasp.org/www-community/Source_Code_Analysis_Tools))と動的アプリケーションテストツール([DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools))をCI/CDパイプラインに導入できます。これにより、新たに作られてしまったインジェクション欠陥を稼働環境に展開する前に検出できます。

## 防止方法

インジェクションを防止するためにはコマンドとクエリからデータを常に分けておくことが必要です。

* 推奨される選択肢は安全なAPIを使用すること。インタープリタの使用を完全に避ける、パラメータ化されたインターフェースを利用する、または、オブジェクト・リレーショナル・マッピング・ツール（ORM）を使用するように移行すること。**注意**：パラメータ化されていたとしても、ストアドプロシージャでは、PL/SQLまたはT-SQLによってクエリとデータを連結したり、EXECUTE IMMEDIATEやexec()を利用して悪意のあるデータを実行することによって、SQLインジェクションを発生させることができる。
* ポジティブな、言い換えると「ホワイトリスト」によるサーバーサイドの入力検証を用いる。特殊文字を必要とする多くのアプリケーション、たとえばモバイルアプリケーション用のテキスト領域やAPIなどにおいては完全な防御方法とはならない。
* 上記の対応が困難な動的クエリでは、そのインタープリタ固有のエスケープ構文を使用して特殊文字をエスケープする。**注意**：テーブル名やカラム名などのSQLストラクチャに対してはエスケープができない。そのため、ユーザ指定のストラクチャ名は危険である。これはレポート作成ソフトウェアに存在する一般的な問題である。
* クエリ内でLIMIT句やその他のSQL制御を使用することで、SQLインジェクション攻撃が発生した場合のレコードの大量漏洩を防ぐ。

## 攻撃シナリオの例

**シナリオ #1**: あるアプリケーションは信頼できないデータを用いることで以下のような脆弱なSQL呼び出しを作ってしまいます。

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**シナリオ #2**: 同様に、アプリケーションがフレームワークを盲信すると、脆弱性のあるクエリになりえます (例えば、Hibernateクエリ言語(HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

これら両方のケースにおいて、攻撃者はブラウザでパラメータ'id'の値を' or '1'='1に変更します。例えば:

`https://example.com/app/accountView?id=' or '1'='1`

これで、両方のクエリの意味が変えられ、accountsテーブルにあるレコードが全て返されることになります。さらなる攻撃により、データの改ざんや削除、ストアドプロシージャの呼び出しが可能です。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md)
* [OWASP Testing Guide: SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection), [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), [ORM injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

### 外部資料

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
