# A01:2025 アクセス制御の不備 (Broken Access Control) ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

「アクセス制御の不備」は、OWASP Top 10 の第1位を維持しています。テストされたすべてのアプリケーションで、何らかの形でアクセス制御の不備が見つかりました。主な CWE (共通弱点一覧) には、認可されていない者への機密情報の露出 (CWE-200)、送信データによる機密情報の露出 (CWE-201)、サーバーサイドリクエストフォージェリ (SSRF: CWE-918)、およびクロスサイトリクエストフォージェリ (CSRF: CWE-352) が含まれます。本カテゴリは、収集データにおいて出現回数が最も多く、関連する CVE (共通脆弱性識別子) 数は第2位を記録しています。

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
   <td>40</td>
   <td>20.15%</td>
   <td>3.74%</td>
   <td>100.00%</td>
   <td>42.93%</td>
   <td>7.04</td>
   <td>3.84</td>
   <td>1,839,701</td>
   <td>32,654</td>
  </tr>
</table>

## 説明 (Description)

アクセス制御は、ユーザーが意図された権限を超えて行動できないよう、ポリシーを強制することです。制御に失敗すると、通常は情報の不正開示、データの改ざんや破壊、あるいは権限外のビジネス機能の実行を招きます。一般的なアクセス制御の脆弱性は以下の通りです。

* **最小権限の原則 (Principle of Least Privilege) への違反：** 特定の機能やロールに対してのみアクセスを許可すべきところ、デフォルトですべてのユーザーにアクセスを許可している状態。
* **アクセス制御チェックの回避：** URL（パラメータの改ざんや強制ブラウズ）、アプリケーションの内部状態、HTML ページの改ざん、あるいは攻撃ツールによる API リクエストの変更を通じたチェックの回避。
* **IDOR (不セキュアな直接オブジェクト参照) ：** 一意の識別子を書き換えることで、他人のアカウントを表示・編集できる状態。
* **API の制御不備：** POST、PUT、DELETE に対するアクセス制御が欠如した API。
* **権限の昇格 (Elevation of Privilege) ：** ログインせずにユーザーとして行動することや、一般ユーザーが管理者権限を取得するなど、想定外の権限を得ること。
* **メタデータの操作：** JSON Web Token (JWT) や Cookie、隠しフィールドなどの改ざん、あるいは JWT の無効化処理の悪用による権限昇格。
* **CORS (オリジン間リソース共有) の設定ミス：** 認可されていない、あるいは信頼できないオリジンからの API アクセスを許可している状態。
* **強制ブラウズ (Forced Browsing) ：** 認証が必要なページや権限が必要なページに対して、URL を推測して直接アクセスを試みること。

## 防止方法 (How to Prevent)

アクセス制御が効果を発揮するのは、攻撃者がチェック処理やメタデータを変更できない、信頼できるサーバー側のコードまたはサーバーレス API で実装されている場合のみです。

* **デフォルトで拒否 (Deny by Default) ：** 公開リソースを除き、原則としてすべてのアクセスを拒否してください。
* **仕組みの再利用：** アクセス制御の仕組みは一度だけ実装し、CORS の使用を最小限に抑えるなど、アプリケーション全体で再利用してください。
* **レコード所有権の強制：** 単に作成・読み取り・更新・削除を許可するのではなく、各レコードの所有権に基づいたアクセス制御をモデル上で強制してください。
* **ドメインモデルでの制限：** アプリケーション固有のビジネス制限要件を、ドメインモデルによって強制してください。
* **ディレクトリ一覧の無効化：** Web サーバーのディレクトリ一覧表示機能を無効化してください。また、ファイルのメタデータ（.git など）やバックアップファイルが公開ディレクトリ内に存在しないことを確認してください。
* **ログとアラート：** アクセス制御の失敗をログに記録し、繰り返しの失敗などが必要な場合は管理者にアラートを通知してください。
* **レート制限 (Rate Limits) ：** 自動化された攻撃ツールによる被害を最小限に抑えるため、API やコントローラーへのアクセスにレート制限を導入してください。
* **セッションの無効化：** ログアウト後は、ステートフルなセッション識別子をサーバー側で無効化してください。ステートレスな JWT トークンは、攻撃の機会を減らすために有効期間を短く設定してください。長期有効な JWT の場合は、リフレッシュトークンの使用や OAuth 標準に準拠したアクセス取消を検討してください。
* **確立されたパターンの活用：** シンプルで宣言的なアクセス制御を提供する、実績のあるツールキットやパターンを使用してください。

開発者および QA 担当者は、ユニットテストおよび統合テストにアクセス制御の機能テストを組み込む必要があります。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：** アカウント情報へのアクセスに、検証されていないデータを使用した SQL 呼び出しが行われている。

```java
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );

```

攻撃者はブラウザの `acct` パラメータを書き換えるだけで、任意の口座番号を送信できます。適切に検証されていない場合、攻撃者は他人のアカウントにアクセスできてしまいます。

```
[https://example.com/app/accountInfo?acct=notmyacct](https://example.com/app/accountInfo?acct=notmyacct)

```

**シナリオ #2：** 攻撃者が管理ページなどの特定の URL に対して強制ブラウズを試みる。管理ページへのアクセスには管理者権限が必要です。

```
[https://example.com/app/getappInfo](https://example.com/app/getappInfo)
[https://example.com/app/admin_getappInfo](https://example.com/app/admin_getappInfo)

```

未認証のユーザーがどちらのページにもアクセスできる場合や、一般ユーザーが管理ページにアクセスできる場合は、不備があると言えます。

**シナリオ #3：** アプリケーションがアクセス制御をフロントエンドのみで実装している。ブラウザ上の JavaScript により `https://example.com/app/admin_getappInfo` へのアクセスがブロックされていても、攻撃者はコマンドラインから直接リクエストを実行できます。

```bash
$ curl [https://example.com/app/admin_getappInfo](https://example.com/app/admin_getappInfo)

```

## 関連資料 (References)

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)
* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)
* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)
* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)
* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)
* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)
* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)
* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)
* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)
* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)
* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)
* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)
* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)
* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)
* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)
* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)
* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)

