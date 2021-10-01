# A01:2021 – アクセス制御の不備    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## 概要

アクセス制御の不備は、5位から順位を上げました。
94%のアプリケーションで、何らかの形でアクセス制御の不備が確認されています。平均発生率は3.81%で、提供されたデータセットで最も多い31万8千件の発生が確認されました。
注目すべき共通脆弱性識別子 (CWEs) は、*CWE-200:認証されていない動作主体への情報露出*、 *CWE-201:送信データを通じた情報露出*、そして*CWE-352:クロスサイトリクエストフォージェリ*です。

## 説明

アクセス制御は、ユーザに対して予め与えられた権限から外れた行動をしないようにポリシーを適用するものです。ポリシー適用の失敗により、許可されていない情報の公開、すべてのデータの変更または破壊、またはユーザ制限から外れたビジネス機能の実行が引き起こされます。アクセス制御の脆弱性は以下のようなものが多くみられます:

-  アクセスは特定のケイパビリティやロール、ユーザーに対してのみ許可され、また一方で誰もが利用可能であるべきという、最小特権の原則やデフォルト拒否の原則に対する違反。

-   URL (パラメータタンパリングや強制ブラウジング) や内部のアプリケーション状態、HTMLページを書き換えたり 、APIリクエストを書き換える攻撃ツールを使用したりすることでアクセス制御の確認を回避してしまう。

-   固有の識別子を与えることで、他の誰かのアカウントを閲覧したり編集したりすることを許可してしまう。(安全でないオブジェクトへの直接参照)

-   POST、PUT、DELETEメソッドへのアクセス制御がないAPIへアクセスができてしまう。

-   権限昇格。ログインすることなしにユーザとして行動したり、一般ユーザとしてログインした時に管理者として行動できてしまう。

-   メタデータの操作。JSON Web Token（JWT）アクセス制御トークンや権限昇格するために操作されるCookieやhiddenフィールドを再生成または改ざんできたり、JWTの無効化を悪用できるなど。

-   CORSの誤設定によって権限のない、あるいは信頼されていないオリジンからのAPIアクセスが許可されてしまう。

-   認証されていないユーザを要認証ページへ、一般ユーザを要権限ページへ強制ブラウズできてしまう。

## 防止方法

攻撃者がアクセス制御のチェックやメタデータを変更することができず、信頼できるサーバーサイドのコードまたはサーバーレスAPIで実施される場合によってのみ、アクセス制御が機能するようにします。

-   公開リソースへのアクセスを除いて、アクセスを原則として拒否する。

-   オリジン間リソース共有 (CORS) の使用箇所を最小限に抑えるなど、アクセス制御メカニズムを一か所で実装しアプリケーション全体でそれを再利用する。

-   アクセス制御モデルは、ユーザがどのようなレコードでも作成、読取、更新、または削除できるようにするのではなく、レコードの所有権があることを前提としなければならない。

-   アプリケーション独自のビジネス上の制約要求はドメインモデルによって表現される必要がある。

-   Webサーバーのディレクトリリスティングを無効にし、ファイルのメタデータ（.gitなど）やバックアップファイルがWebの経路上に存在しないことを確認する。

-   アクセス制御の失敗をログに記録し、必要に応じて管理者に警告する（繰り返し失敗しているなど）。

-   レート制限するAPIとコントローラは自動攻撃ツールによる被害を最小限に抑えるための手段である。

-   ステートフルなセッション識別子は、ログアウト後サーバーにて無効化する。
    ステートフルなJWTトークンは、攻撃者にとっての格好の機会を最小化するため、短い期間のみ有効であるべきである。
    長い期間有効なJWTについては、アクセスの取り消しに関するOAuthの標準に従うことが強く推奨される。

開発者とQAスタッフは、アクセス制御に関する機能面での単体及び結合テストを取り入れるべきです。

## 攻撃シナリオの例

**シナリオ #1:** アプリケーションが、アカウント情報にアクセスするSQL呼出しに未検証のデータを使用しています。

```
 https://example.com/app/accountInfo?acct=notmyacct
```

攻撃者は、単にブラウザでパラメータ'acct'を任意のアカウント番号に改変して送信します。適切な検証がない場合、攻撃者は任意のアカウントにアクセスできます。

https://example.com/app/accountInfo?acct=notmyacct

**シナリオ #2:** ある攻撃者は、ブラウザでURLを指定してアクセスします。管理者ページにアクセスするには管理者権限が必要です。

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```
認証されていないユーザがこれらのページにアクセスすることができるなら、欠陥があります。
管理者でない人が管理者のページにアクセスできるなら、それも欠陥です。

## 参考資料

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## 対応する CWE のリスト

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)

# A01:2021 – Broken Access Control    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## Overview

Moving up from the fifth position, 94% of applications were tested for
some form of broken access control with the average incidence rate of 3.81%, and has the most occurrences in the contributed dataset with over 318k. Notable Common Weakness Enumerations (CWEs) included are *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201:
Exposure of Sensitive Information Through Sent Data*, and *CWE-352:
Cross-Site Request Forgery*.

## Description

Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data or
performing a business function outside the user's limits. Common access
control vulnerabilities include:

-   Violation of the principle of least privilege or deny by default,
    where access should only be granted for particular capabilities,
    roles, or users, but is available to anyone.

-   Bypassing access control checks by modifying the URL (parameter
    tampering or force browsing), internal application state, or the
    HTML page, or by using an attack tool modifying API requests.

-   Permitting viewing or editing someone else's account, by providing
    its unique identifier (insecure direct object references)

-   Accessing API with missing access controls for POST, PUT and DELETE.

-   Elevation of privilege. Acting as a user without being logged in or
    acting as an admin when logged in as a user.

-   Metadata manipulation, such as replaying or tampering with a JSON
    Web Token (JWT) access control token, or a cookie or hidden field
    manipulated to elevate privileges or abusing JWT invalidation.

-   CORS misconfiguration allows API access from unauthorized/untrusted
    origins.

-   Force browsing to authenticated pages as an unauthenticated user or
    to privileged pages as a standard user.

## How to Prevent

Access control is only effective in trusted server-side code or
server-less API, where the attacker cannot modify the access control
check or metadata.

-   Except for public resources, deny by default.

-   Implement access control mechanisms once and re-use them throughout
    the application, including minimizing Cross-Origin Resource Sharing (CORS) usage.

-   Model access controls should enforce record ownership rather than
    accepting that the user can create, read, update, or delete any
    record.

-   Unique application business limit requirements should be enforced by
    domain models.

-   Disable web server directory listing and ensure file metadata (e.g.,
    .git) and backup files are not present within web roots.

-   Log access control failures, alert admins when appropriate (e.g.,
    repeated failures).

-   Rate limit API and controller access to minimize the harm from
    automated attack tooling.

-   Stateful session identifiers should be invalidated on the server after logout.
    Stateless JWT tokens should rather be short-lived so that the window of
    opportunity for an attacker is minimized. For longer lived JWTs it's highy recommended to
    follow the OAuth standards to revoke access.

Developers and QA staff should include functional access control unit
and integration tests.

## Example Attack Scenarios

**Scenario #1:** The application uses unverified data in a SQL call that
is accessing account information:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

An attacker simply modifies the browser's 'acct' parameter to send
whatever account number they want. If not correctly verified, the
attacker can access any user's account.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Scenario #2:** An attacker simply forces browses to target URLs. Admin
rights are required for access to the admin page.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```
If an unauthenticated user can access either page, it's a flaw. If a
non-admin can access the admin page, this is a flaw.

## References

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## List of Mapped CWEs

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
