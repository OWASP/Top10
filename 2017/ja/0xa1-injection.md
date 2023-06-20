# A1:2017-インジェクション

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点           | 影響               |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 3 | 蔓延度 2 : 検出のしやすさ 3 | 技術面への影響 3 : ビジネス面への影響 |
| 環境変数、パラメータ、外部及び内部のWebサービス、そしてあらゆる種類のユーザといった、ほとんどすべてのデータソースはインジェクションの経路となりえます。[インジェクション欠陥](https://www.owasp.org/index.php/Injection_Flaws)は、攻撃者が悪意を持ったデータをインタープリタに送ることができる場合に発生します。 | インジェクション欠陥は、特にレガシーコードでは、とても一般的です。インジェクション脆弱性は、SQL、LDAP、XPath、あるいはNoSQLクエリ、OSコマンド、XMLパーサー、SMTPヘッダー、式言語、およびORMクエリでよく見られます。インジェクション欠陥は、コードを調べると簡単に発見できます。スキャナやファジングは、攻撃者がインジェクション欠陥を見つけるのに役立ちます。 |インジェクションは、データの損失、破壊、権限ない者への情報漏洩、アカウンタビリティの喪失、またはアクセス拒否につながる可能性があります。インジェクションは、ホストの完全な乗っ取りにつながることがあります。ビジネスへの影響は、アプリケーションとデータの重要性に依存します。|


## 脆弱性発見のポイント

次のような状況では、アプリケーションはこの攻撃に対して脆弱です:

* ユーザが提供したデータが、アプリケーションによって検証、フィルタリング、またはサニタイズされない。
* コンテキストに応じたエスケープが行われず、動的クエリまたはパラメータ化されていない呼出しがインタープリタに直接使用される。
* オブジェクト・リレーショナル・マッピング（ORM）の検索パラメータに悪意を持ったデータが使用され、重要なレコードを追加で抽出してしまう。
* 悪意を持ったデータを直接または連結して使う。例えば、動的クエリ、コマンド、ストアド・プロシージャにおいて構文に悪意を持ったデータを組み合わせる形でSQLやコマンドが組み立てられる。

より一般的なインジェクションとしては、SQL、NoSQL、OSコマンド、オブジェクト・リレーショナル・マッピング（ORM）、LDAP、およびEL式（Expression Language）またはOGNL式（Object Graph Navigation Library）のインジェクションがあります。コンセプトはすべてのインタープリタで同じです。ソースコードをレビューすれば、インジェクションに対してアプリケーションが脆弱であるか最も効果的に検出できます。そして、すべてのパラメータ、ヘッダー、URL、Cookie、JSON、SOAP、およびXMLデータ入力の完全な自動テストも効果的です。また、組織は静的ソースコード解析ツール([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools))と動的アプリケーションテストツール([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools))をCI/CDパイプラインに導入できます。これにより、新たに作られてしまったインジェクション欠陥を稼働環境に展開する前に検出できます。

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

これら両方のケースにおいて、攻撃者はブラウザでパラメータ'id'の値を' UNION SELECT SLEEP(10);--に変更します。例えば:

`http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

これで、両方のクエリの意味が変えられ、accountsテーブルにあるレコードが全て返されることになります。さらなる攻撃により、データの改ざんや削除、ストアドプロシージャの呼び出しが可能です。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### 外部資料

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
