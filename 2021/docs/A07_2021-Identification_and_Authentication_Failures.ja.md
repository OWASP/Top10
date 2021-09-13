# A07:2021 – 識別と認証の失敗

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 | 最大網羅率 | 平均網羅率 | 加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 79.51%       | 45.72%       | 7.40                 | 6.50                | 132,195           | 3,897      |

## 概要

このカテゴリは、これまでの版では*認証の不備*として知られていたものです。前回は第2位でしたが今回は第7位に順位を落としました。また、この版では識別の失敗に関するいくつかのCWEを含めています。考慮すべきCWEには、*CWE-297:ホストの不一致による証明書の不適切な検証*、*CWE-287:不適切な認証*、*CWE-384:セッションの固定化*があります。

## 解説

ユーザーのアイデンティ確認、認証そしてセッション管理は、認証関連の攻撃対策として極めて重要です。
もしアプリケーションに次に列挙するような問題があれば、認証に問題があると言えます。

-   パスワードリスト攻撃（クレデンシャル・スタッフィング攻撃）のような自動化された攻撃が出来てしまう。パスワードリスト攻撃とは、攻撃者が正当なユーザー名とパスワードの組み合わせを入手して行う攻撃手法のことです。

-   ブルートフォース攻撃（総当たり攻撃）などの自動化された攻撃が出来てしまう。

-   デフォルトのパスワード、弱いパスワード、良く使われるパスワードが利用できてしまう。たとえば「Password1」や「admin/admin」などです。

-   クレデンシャルの復旧やパスワードを忘れた場合のプロセスが弱い、あるいは効果がない。たとえば「秘密の質問」のようなやり方では安全とは言えない。

-   パスワードを保存する際に、プレーンテキストや暗号化して保存している。あるいは脆弱なハッシュ関数を利用している。（OWASP Top 10 2017 A3:機微な情報の露出　も参照）

-   多要素認証を採用していない。あるいは間違った使い方をしている。

-   セッションIDがURLの一部として露出してしまっている。（URLリライティングなどに注意）

-   ログイン後にセッションIDを変更していない。（セッション固定攻撃に注意）

-   セッションIDを正しいやり方で無効化していない。たとえば、ログアウトした際や一定期間リクエストが無い場合でも、ユーザーセッションや認証トークン（シングルサインオンのトークンなどが多い）が、無効化されない。

## 防止方法

-   多要素認証を可能な限り実装する。これにより、パスワードリスト攻撃、ブルートフォース攻撃、盗用したクレデンシャルの再利用など多くの自動化された攻撃を防ぐことができる。

-   デフォルトのクレデンシャルのままプログラム（サービス）をデプロイしない。特に管理者ユーザーのパスワードをデフォルト設定のままデプロイするのは言語道断である。

-   弱いパスワードを設定していないかチェックする機能を実装する。たとえばパスワードの新規設定や更新時には、「弱いパスワード　トップ10,000」などのリストを使って検証すると良いだろう。

-   パスワードの「長さ」や「複雑さ」そして「定期的な変更」などのパスワードポリシーについては、NISTガイドライン（800-63b セクション5.1.1:記憶シークレット）や、近代的で根拠に基づくポリシーに沿うようにする。

-   新規登録の場合、クレデンシャルリカバリーの場合、またAPI経由の場合であってもアカウント列挙攻撃に対して強化されていることを確認する。認証の際にはどのような結果であれ（成功でも失敗でも）同じメッセージを使うようにすること。

-   ログイン試行回数に制限を設けるか、ログインに繰り返し失敗するようなら徐々に処理を遅延させる。ログインの失敗はすべてログに記録すること。そしてパスワードリスト攻撃やブルートフォース攻撃などの攻撃を検知した際には管理者に通知する。

-   セッション管理はサーバ側で行い、安全でプログラム言語などに内蔵されているものを使う。ログイン毎にエントロピーの高いランダムなセッションIDを発行するセッション管理機構を利用すること。セッションIDはURLに含まれるべきではなく、安全に保管されなければならない。また、セッションIDはログアウトした際、一定期間アクセスが無い場合、タイムアウト時間を経過した場合には無効にしなければならない。

## 攻撃シナリオの例

**シナリオ #1:** 既知のパスワードリストを使う、パスワードリスト攻撃はよくある攻撃手法です。もしあるアプリケーションには、このようなリストを使う連続攻撃や、パスワードリスト攻撃への防御が組み込まれていなかったとしましょう。すると、そのアプリケーションはパスワードの神託所として利用されてしまいます。つまり、クレデンシャルが有効かどうかを判定することができてしまうのです。

**シナリオ #2:** 認証を狙う攻撃の多くは、パスワードを唯一の認証要素として使い続けていることに起因します。「パスワードの定期的な変更」や「複雑なパスワードの要求」は、以前はベストプラクティスと考えられていましたが、ユーザーはかえって弱いパスワードをあちこちのサイトで使いまわすようになります。NIST 800-63のガイドラインに従って、このような昔ながらの慣習はもう辞めにしましょう、そして多要素認証を使いましょう。

**シナリオ #3:** アプリケーションのセッションタイムアウトが正しく設定されていない。ユーザーは公共のコンピュータからアクセスしているかもしれません。もしユーザーが「ログアウト」をクリックせずに、表示しているブラウザのタブを閉じてどこかへ行ってしまったらどうなるでしょうか。セッションタイムアウトを設定していないと、攻撃者は１時間後にそのブラウザで先のユーザーになりすましてアプリケーションを利用できてしまいます。

## 参考資料

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   OWASP Testing Guide: Identity, Authentication

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Credential Stuffing

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Session Management

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## 対応する CWE のリスト

CWE-255 証明書・パスワードの管理

CWE-259 ハードコードされたパスワードの使用

CWE-287 不適切な認証

CWE-288 代替パスまたはチャネルを使用した認証回避

CWE-290 スプーフィングによる認証回避

CWE-294 Capture-replay による認証回避

CWE-295 不正な証明書検証

CWE-297 ホストの不一致による証明書の不適切な検証

CWE-300 中間者の問題

CWE-302 認証回避の脆弱性

CWE-304 認証における重要なステップの欠落

CWE-306 重要な機能に対する認証の欠如

CWE-307 過度な認証試行の不適切な制限

CWE-346 同一生成元ポリシー違反

CWE-384 セッションの固定化

CWE-521 脆弱なパスワードの要求

CWE-613 不適切なセッション期限

CWE-620 未検証のパスワード変更

CWE-640 パスワードを忘れた場合の脆弱なパスワードリカバリの仕組み

CWE-798 ハードコードされた認証情報の使用

CWE-940 通信チャネルソースの不適切な検証

CWE-1216 ロックアウト機構の不備


# A07:2021 – Identification and Authentication Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 79.51%       | 45.72%       | 7.40                 | 6.50                | 132,195           | 3,897      |

## Overview

Previously known as *Broken Authentication*, this category slid down
from the second position and now includes CWEs related to identification
failures. Notable CWEs included are *CWE-297: Improper Validation of
Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, and
*CWE-384: Session Fixation*.

## Description 

Confirmation of the user's identity, authentication, and session
management is critical to protect against authentication-related
attacks. There may be authentication weaknesses if the application:

-   Permits automated attacks such as credential stuffing, where the
    attacker has a list of valid usernames and passwords.

-   Permits brute force or other automated attacks.

-   Permits default, weak, or well-known passwords, such as "Password1"
    or "admin/admin. "

-   Uses weak or ineffective credential recovery and forgot-password
    processes, such as "knowledge-based answers," which cannot be made
    safe.

-   Uses plain text, encrypted, or weakly hashed passwords (see
    A3:2017-Sensitive Data Exposure).

-   Has missing or ineffective multi-factor authentication.

-   Exposes Session IDs in the URL (e.g., URL rewriting).

-   Do not rotate Session IDs after successful login.

-   Does not correctly invalidate Session IDs. User sessions or
    authentication tokens (mainly single sign-on (SSO) tokens) aren't
    properly invalidated during logout or a period of inactivity.

## How to Prevent

-   Where possible, implement multi-factor authentication to prevent
    automated credential stuffing, brute force, and stolen credential
    reuse attacks.

-   Do not ship or deploy with any default credentials, particularly for
    admin users.

-   Implement weak password checks, such as testing new or changed
    passwords against the top 10,000 worst passwords list.

-   Align password length, complexity, and rotation policies with NIST
    800-63b's guidelines in section 5.1.1 for Memorized Secrets or other
    modern, evidence-based password policies.

-   Ensure registration, credential recovery, and API pathways are
    hardened against account enumeration attacks by using the same
    messages for all outcomes.

-   Limit or increasingly delay failed login attempts. Log all failures
    and alert administrators when credential stuffing, brute force, or
    other attacks are detected.

-   Use a server-side, secure, built-in session manager that generates a
    new random session ID with high entropy after login. Session IDs
    should not be in the URL, be securely stored, and invalidated after
    logout, idle, and absolute timeouts.

## Example Attack Scenarios

**Scenario #1:** Credential stuffing, the use of lists of known
passwords, is a common attack. Suppose an application does not implement
automated threat or credential stuffing protection. In that case, the
application can be used as a password oracle to determine if the
credentials are valid.

**Scenario #2:** Most authentication attacks occur due to the continued
use of passwords as a sole factor. Once considered, best practices,
password rotation, and complexity requirements encourage users to use
and reuse weak passwords. Organizations are recommended to stop these
practices per NIST 800-63 and use multi-factor authentication.

**Scenario #3:** Application session timeouts aren't set correctly. A
user uses a public computer to access an application. Instead of
selecting "logout," the user simply closes the browser tab and walks
away. An attacker uses the same browser an hour later, and the user is
still authenticated.

## References

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   OWASP Testing Guide: Identity, Authentication

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Credential Stuffing

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Session Management

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## List of Mapped CWEs

CWE-255 Credentials Management Errors

CWE-259 Use of Hard-coded Password

CWE-287 Improper Authentication

CWE-288 Authentication Bypass Using an Alternate Path or Channel

CWE-290 Authentication Bypass by Spoofing

CWE-294 Authentication Bypass by Capture-replay

CWE-295 Improper Certificate Validation

CWE-297 Improper Validation of Certificate with Host Mismatch

CWE-300 Channel Accessible by Non-Endpoint

CWE-302 Authentication Bypass by Assumed-Immutable Data

CWE-304 Missing Critical Step in Authentication

CWE-306 Missing Authentication for Critical Function

CWE-307 Improper Restriction of Excessive Authentication Attempts

CWE-346 Origin Validation Error

CWE-384 Session Fixation

CWE-521 Weak Password Requirements

CWE-613 Insufficient Session Expiration

CWE-620 Unverified Password Change

CWE-640 Weak Password Recovery Mechanism for Forgotten Password

CWE-798 Use of Hard-coded Credentials

CWE-940 Improper Verification of Source of a Communication Channel

CWE-1216 Lockout Mechanism Errors
