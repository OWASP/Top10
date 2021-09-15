# A01:2021 – アクセス制御の不備
# A01:2021 – Broken Access Control

## 因子
## Factors

| 対応する CWE 数 | 最大発生率 | 平均発生率 | 最大網羅率 | 平均網羅率 | 加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 94.55%       | 47.72%       | 6.92                 | 5.93                | 318,487           | 19,013     |

## 概要
## Overview

アクセス制御の不備は、5位から順位を上げました。
94%のアプリケーションで、何らかの形でアクセス制御の不備が確認されています。
注目すべきCWEは、*CWE-200:認証されていない動作主体への情報露出*、 *CWE-201:送信データを通じた情報露出*、そして*CWE-352:クロスサイトリクエストフォージェリ*です。

Moving up from the fifth position, 94% of applications were tested for
some form of broken access control. Notable CWEs included are *CWE-200:
Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201:
Exposure of Sensitive Information Through Sent Data*, and *CWE-352:
Cross-Site Request Forgery*.

## 説明
## Description

アクセス制御はユーザが予め与えられた権限から外れた行動をしないようにポリシーを適用します。ポリシー適用の失敗は、許可されていない情報の公開、すべてのデータの変更または破壊、またはユーザ制限から外れたビジネス機能の実行につながることが多いです。一般的なアクセス制御の脆弱性は以下のような場合に発生します:

-   URL、内部のアプリケーションの状態、HTMLページを変更することやカスタムAPI攻撃ツールを単純に使用することによって、アクセス制御のチェックを迂回できてしまう。

-   主キーを他のユーザのレコードに変更することができ、他のユーザのアカウントを表示または編集できてしまう。

-   権限昇格。ログインすることなしにユーザとして行動したり、一般ユーザとしてログインした時に管理者として行動できてしまう。

-   メタデータの操作。JSON Web Token（JWT）アクセス制御トークンや権限昇格するために操作されるCookieやhiddenフィールドを再生成または改ざんできたり、JWTの無効化を悪用できるなど。

-   CORSの誤設定によって権限のないAPIアクセスが許可されてしまう。

-   認証されていないユーザを要認証ページへ、一般ユーザを要権限ページへ強制ブラウズできてしまう。 POST、PUT、DELETEメソッドへのアクセス制御がないAPIへアクセスができてしまう。

Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data or
performing a business function outside the user's limits. Common access
control vulnerabilities include:

-   Bypassing access control checks by modifying the URL, internal
    application state, or the HTML page, or simply using a custom API
    attack tool.

-   Allowing the primary key to be changed to another user's record,
    permitting viewing or editing someone else's account.

-   Elevation of privilege. Acting as a user without being logged in or
    acting as an admin when logged in as a user.

-   Metadata manipulation, such as replaying or tampering with a JSON
    Web Token (JWT) access control token, or a cookie or hidden field
    manipulated to elevate privileges or abusing JWT invalidation.

-   CORS misconfiguration allows unauthorized API access.

-   Force browsing to authenticated pages as an unauthenticated user or
    to privileged pages as a standard user. Accessing API with missing
    access controls for POST, PUT and DELETE.

## 防止方法
## How to Prevent

攻撃者がアクセス制御のチェックやメタデータを変更することができず、信頼できるサーバーサイドのコードまたはサーバーレスAPIで実施される場合にのみ、アクセス制御は機能します。

-   公開リソースへのアクセスを除いて、アクセスを原則として拒否する。

-   CORSの使用を最小限に抑えるように、アクセス制御メカニズムを一度実装し、アプリケーション全体で再利用する。

-   アクセス制御モデルは、ユーザがどのようなレコードでも作成、読取、更新、または削除できるようにするのではなく、レコードの所有権があることを前提としなければならない。

-   アプリケーション独自のビジネス上の制約要求はドメインモデルに表現される必要がある。

-   Webサーバーのディレクトリリスティングを無効にし、ファイルのメタデータ（.gitなど）とバックアップファイルがウェブルートに存在しないことを確認する。

-   アクセス制御の失敗をログに記録し、必要に応じて管理者に警告する（繰返して失敗しているなど）。

-   レート制限するAPIとコントローラは自動攻撃ツールによる被害を最小限に抑えるための手段である。

-   JWTトークンはログアウト後にはサーバー上で無効とされるべきである。

開発者とQAスタッフは、アクセス制御に関する機能面での単体及び結合テストを取り入れるべきです。

Access control is only effective in trusted server-side code or
server-less API, where the attacker cannot modify the access control
check or metadata.

-   Except for public resources, deny by default.

-   Implement access control mechanisms once and re-use them throughout
    the application, including minimizing CORS usage.

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

-   JWT tokens should be invalidated on the server after logout.

Developers and QA staff should include functional access control unit
and integration tests.

## 攻撃シナリオの例
## Example Attack Scenarios

**シナリオ #1:** アプリケーションが、アカウント情報にアクセスするSQL呼出しに未検証のデータを使用しています。

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

攻撃者は、単にブラウザでパラメータ'acct'を任意のアカウント番号に改変して送信します。適切な検証がない場合、攻撃者は任意のアカウントにアクセスできます。

https://example.com/app/accountInfo?acct=notmyacct

**シナリオ #2:** ある攻撃者は、ブラウザでURLを指定してアクセスします。管理者ページにアクセスするには管理者権限が必要です。

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

認証されていないユーザがこれらのページにアクセスすることができるなら、欠陥があります。
管理者でない人が管理者のページにアクセスできるなら、それも欠陥です。

**Scenario #1:** The application uses unverified data in a SQL call that
is accessing account information:

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

An attacker simply modifies the browser's 'acct' parameter to send
whatever account number they want. If not correctly verified, the
attacker can access any user's account.

https://example.com/app/accountInfo?acct=notmyacct

**Scenario #2:** An attacker simply forces browses to target URLs. Admin
rights are required for access to the admin page.

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

If an unauthenticated user can access either page, it's a flaw. If a
non-admin can access the admin page, this is a flaw.

## 参考資料
## References

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control]()

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## 対応する CWE のリスト
## List of Mapped CWEs

CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')

CWE-23 Relative Path Traversal

CWE-35 Path Traversal: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

CWE-201 Exposure of Sensitive Information Through Sent Data

CWE-219 Storage of File with Sensitive Data Under Web Root

CWE-264 Permissions, Privileges, and Access Controls (should no longer
be used)

CWE-275 Permission Issues

CWE-276 Incorrect Default Permissions

CWE-284 Improper Access Control

CWE-285 Improper Authorization

CWE-352 Cross-Site Request Forgery (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized
Actor

CWE-377 Insecure Temporary File

CWE-402 Transmission of Private Resources into a New Sphere ('Resource
Leak')

CWE-425 Direct Request ('Forced Browsing')

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

CWE-497 Exposure of Sensitive System Information to an Unauthorized
Control Sphere

CWE-538 Insertion of Sensitive Information into Externally-Accessible
File or Directory

CWE-540 Inclusion of Sensitive Information in Source Code

CWE-548 Exposure of Information Through Directory Listing

CWE-552 Files or Directories Accessible to External Parties

CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key

CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

CWE-639 Authorization Bypass Through User-Controlled Key

CWE-651 Exposure of WSDL File Containing Sensitive Information

CWE-668 Exposure of Resource to Wrong Sphere

CWE-706 Use of Incorrectly-Resolved Name or Reference

CWE-862 Missing Authorization

CWE-863 Incorrect Authorization

CWE-913 Improper Control of Dynamically-Managed Code Resources

CWE-922 Insecure Storage of Sensitive Information

CWE-1275 Sensitive Cookie with Improper SameSite Attribute
