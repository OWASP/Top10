# A5:2017-アクセス制御の不備

| 脅威エージェント/攻撃手法 | セキュリティ上の弱点  | 影響 |
| -- | -- | -- |
| アクセスレベル : 悪用のしやすさ 2 | 蔓延度 2 : 検出のしやすさ 2 | 技術面への影響 3 : ビジネス面への影響 |
| アクセス制御の悪用は攻撃者の基本スキルです。 静的ソースコード解析ツール([SAST](https://owasp.org/www-community/Source_Code_Analysis_Tools))と動的アプリケーションテストツール([DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools))はアクセス制御の不存在を検出できますが、それが存在する場合にアクセス制御が有効に機能していることを検証することはできません。アクセス制御は、手作業で、場合によっては特定のフレームワークにおけるアクセス制御の不存在の自動チェックによって発見することができます。 | アクセス制御上の欠陥は、一般に、自動検出が行われないことやアプリケーション開発者による効果的な機能テストが行われないことによって生じます。 アクセス制御の検出は、通常は自動化された静的または動的テストには適していません。 手動テストは、HTTPメソッド（GET対PUTなど）、コントローラ、オブジェクト直接参照などでの欠落している、もしくは機能していないアクセス制御を検出するための最良の方法です。 | 技術への影響は、攻撃者が一般ユーザ、管理者、または特権機能を持ったユーザとして振る舞ったり、すべてのレコードの作成、アクセス、更新、削除を行ってしまうことです。ビジネスへの影響は、アプリケーションとデータの保護の重要性に依存します。 |

## 脆弱性発見のポイント

アクセス制御はユーザが予め与えられた権限から外れた行動をしないようにポリシーを適用します。ポリシー適用の失敗は、許可されていない情報の公開、すべてのデータの変更または破壊、またはユーザ制限から外れたビジネス機能の実行につながることが多いです。一般的なアクセス制御の脆弱性は以下のような場合に発生します:

* URL、内部のアプリケーションの状態、HTMLページを変更することやカスタムAPI攻撃ツールを単純に使用することによって、アクセス制御のチェックを迂回できてしまう。
* 主キーを他のユーザのレコードに変更することができ、他のユーザのアカウントを表示または編集できてしまう。
* 権限昇格。ログインすることなしにユーザとして行動したり、一般ユーザとしてログインした時に管理者として行動できてしまう。
* メタデータの操作。JSON Web Token（JWT）アクセス制御トークンや権限昇格するために操作されるCookieやhiddenフィールドを再生成または改ざんできたり、JWTの無効化を悪用できるなど。
* CORSの誤設定によって権限のないAPIアクセスが許可されてしまう。
* 認証されていないユーザを要認証ページへ、一般ユーザを要権限ページへ強制ブラウズできてしまう。 POST、PUT、DELETEメソッドへのアクセス制御がないAPIへアクセスができてしまう。

## 防止方法

攻撃者がアクセス制御のチェックやメタデータを変更することができず、信頼できるサーバーサイドのコードまたはサーバーレスAPIで実施される場合にのみ、アクセス制御は機能します。

* 公開リソースへのアクセスを除いて、アクセスを原則として拒否する。
* CORSの使用を最小限に抑えるように、アクセス制御メカニズムを一度実装し、アプリケーション全体で再利用する。
* アクセス制御モデルは、ユーザがどのようなレコードでも作成、読取、更新、または削除できるようにするのではなく、レコードの所有権があることを前提としなければならない。
* アプリケーション独自のビジネス上の制約要求はドメインモデルに表現される必要がある。
* Webサーバーのディレクトリリスティングを無効にし、ファイルのメタデータ（.gitなど）とバックアップファイルがウェブルートに存在しないことを確認する。
* アクセス制御の失敗をログに記録し、必要に応じて管理者に警告する（繰返して失敗しているなど）。
* レート制限するAPIとコントローラは自動攻撃ツールによる被害を最小限に抑えるための手段である。
* JWTトークンはログアウト後にはサーバー上で無効とされるべきである。

開発者とQAスタッフは、アクセス制御に関する機能面での単体及び結合テストを取り入れるべきです。

## 攻撃シナリオの例

**シナリオ #1**: アプリケーションが、アカウント情報にアクセスするSQL呼出しに未検証のデータを使用しています。

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

攻撃者は、単にブラウザでパラメータ'acct'を任意のアカウント番号に改変して送信します。適切な検証がない場合、攻撃者は任意のアカウントにアクセスできます。

`https://example.com/app/accountInfo?acct=notmyacct`

**シナリオ #2**: ある攻撃者は、ブラウザでURLを指定してアクセスします。管理者ページにアクセスするには管理者権限が必要です。

```
  https://example.com/app/getappInfo
  https://example.com/app/admin_getappInfo
```

認証されていないユーザがこれらのページにアクセスすることができるなら、欠陥があります。管理者でない人が管理者のページにアクセスできるなら、それも欠陥です。

## 参考資料

### OWASP

* [OWASP Proactive Controls: Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V4-Access-Control.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

### 外部資料

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
