# A07:2021 – 識別と認証の失敗

## 因子

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 79.51%       | 45.72%       | 7.40                 | 6.50                | 132,195           | 3,897      |

## 概要

このカテゴリは、これまでの版では*認証の不備*として知られていたものです。前回は第2位でしたが今回は第7位に順位を落としました。また、この版では識別の失敗に関するいくつかのCWEを含めています。考慮すべきCWEには、*CWE-297:ホストの不一致による証明書の不適切な検証*、*CWE-287:不適切な認証*、*CWE-384:セッションの固定化*があります。

## 解説

ユーザーのアイデンティ確認、認証そしてセッション管理は、認証関連の攻撃対策として極めて重要です。
もしアプリケーションに次に列挙するような問題があれば、認証に問題があると言えます。

-   パスワードリスト攻撃のような自動化された攻撃が出来てしまう。パスワードリスト攻撃とは、攻撃者が正当なユーザー名とパスワードの組み合わせを入手して行う攻撃手法のことです。

-   ブルートフォース攻撃（総当たり攻撃）などの自動化された攻撃が出来てしまう。

-   デフォルトのパスワード、弱いパスワード、良く使われるパスワードが利用できてしまう。たとえば「Password1」や「admin/admin」などです。

-   クレデンシャルの復旧やパスワードを忘れた場合のプロセスが弱い、あるいは効果がない。たとえば「秘密の質問」のようなやり方では安全とは言えない。

-   パスワードを保存する際に、プレーンテキストや暗号化して保存している。あるいは脆弱なハッシュ関数を利用している。（OWASP Top 10 2017 A3:機微な情報の露出　も参照）

-   多要素認証を採用していない。あるいは間違った使い方をしている。

-   セッションIDがURLの一部として露出してしまっている。（URLリライティングなどに注意）

-   ログイン後にセッションIDを変更していない。（セッション固定攻撃に注意）

-   セッションIDを正しいやり方で無効化されていない。たとえば、ユーザーセッションや認証トークン（シングルサインオンのトークンなどが多い）が、ログアウトした際や一定期間リクエストが無くても正しく無効化されていない。


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
