# A02:2021 – 暗号化の失敗

## 因子

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              | 79.33%       | 34.85%       | 7.29                 | 6.81                | 233,788           | 3,075      |

## 概要

前回から順位を一つ上げたこのカテゴリは、以前は*機微な情報の露出*として知られていたものです。
このカテゴリは根本的な要因よりも、暗号化技術の不適切な使用、または暗号化の欠如に関連した幅広い障害に焦点を当てています。こうした障害は、時に機微な情報の露出を結果としてもたらします。
考慮すべきCWEには、*CWE-259:ハードコードされたパスワードの使用*、*CWE-327:不適切な暗号化アルゴリズム*、*CWE-331:不十分なエントロピー*があります。

## 解説

まず、送信あるいは保存するデータが保護を必要とするか見極めます。例えば、パスワード、クレジットカード番号、健康記録、個人データやビジネス上の機密は特別な保護が必要になります。データに対して、EUの一般データ保護規則(GDPR)のようなプライバシー関連の法律が適用される場合、また、PCIデータセキュリティスタンダード(PCI DSS)など金融の情報保護の要求があるような規定がある場合には、特に注意が必要です。そのようなデータすべてについて、以下を確認してください:

-   どんなデータであれ平文で送信していないか。これは、HTTP、SMTP、FTPのようなプロトコルを使っている場合に該当する。外部インターネットへのトラフィックは危険である。また、ロードバランサー、Webサーバー、バックエンドシステムなどの内部の通信もすべて確認すること。

-   古いまたは脆弱な暗号アルゴリズムを初期設定のまま、または古いコードで使っていないか。

-   初期値のままの暗号鍵の使用、弱い暗号鍵を生成または再利用、適切な暗号鍵管理または鍵のローテーションをしていない、これらの該当する箇所はないか。

-   ユーザーエージェント（ブラウザ）のセキュリティに関するディレクティブやヘッダーが欠落しているなど、暗号化が強制されていない箇所はないか。

-   アプリ、メールクライアントなどのユーザエージェントが受信したサーバー証明書が正当なものか検証していない箇所はないか。

ASVS Crypto (V7)、Data Protection (V9)、および SSL/TLS (V10) を参照。

## 防止方法

最低限実施すべきことを以下に挙げます。そして、参考資料を検討してください:

-   アプリケーションごとに処理するデータ、保存するデータ、送信するデータを分類する。そして、どのデータがプライバシー関連の法律・規則の要件に該当するか、またどのデータがビジネス上必要なデータか判定する。

-   前述の分類をもとにアクセス制御を実装する。

-   必要のない機微な情報を保存しない。できる限りすぐにそのような機微な情報を破棄するか、PCI DSSに準拠したトークナイゼーションまたはトランケーションを行う。データが残っていなければ盗まれない。

-   保存時にすべての機微な情報を暗号化しているか確認する。

-   最新の暗号強度の高い標準アルゴリズム、プロトコル、暗号鍵を実装しているか確認する。そして適切に暗号鍵を管理する。

-   前方秘匿性(PFS)を有効にしたTLS、サーバーサイドによる暗号スイートの優先度決定、セキュアパラメータなどのセキュアなプロトコルで、通信経路上のすべてのデータを暗号化する。HTTP Strict Transport Security (HSTS)のようなディレクティブで暗号化を強制する。

-   機微な情報を含むレスポンスのキャッシングを無効にする。

-   パスワードを保存する際、Argon2、scrypt、bcrypt、PBKDF2のようなワークファクタ(遅延ファクタ)のある、強くかつ適応可能なレベルのソルト付きハッシュ関数を用いる。

-   設定とその設定値がそれぞれ独立して効果があるか検証する。

## 攻撃シナリオの例

**シナリオ #1**: あるアプリケーションは、データベースの自動暗号化を使用し、クレジットカード番号を暗号化します。しかし、そのデータが取得されるときに自動的に復号されるため、SQLインジェクションによって平文のクレジットカード番号を取得できてしまいます。

**シナリオ #2**: あるサイトは、すべてのページでTLSを使っておらず、ユーザにTLSを強制していません。また、そのサイトでは弱い暗号アルゴリズムをサポートしています。攻撃者はネットワークトラフィックを監視し（例えば、暗号化していない無線ネットワークで）、HTTPS通信をHTTP通信にダウングレードしそのリクエストを盗聴することで、ユーザのセッションクッキーを盗みます。そして、攻撃者はこのクッキーを再送しユーザの(認証された)セッションを乗っ取り、そのユーザの個人データを閲覧および改ざんできます。また、攻撃者はセッションを乗っ取る代わりに、すべての送信データ（例えば、入金の受取人）を改ざんできます。

**シナリオ #3**: あるパスワードデータベースは、ソルトなしのハッシュまたは単純なハッシュでパスワードを保存しています。もしファイルアップロードの欠陥があれば、攻撃者はそれを悪用してパスワードデータベースを取得できます。事前に計算されたハッシュのレインボーテーブルで、すべてのソルトなしのハッシュが解読されてしまいます。そして、たとえソルトありでハッシュ化されていても、単純または高速なハッシュ関数で生成したハッシュはGPUで解読されてしまうかもしれません。

## 参考資料

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Password and Cryptographic Storage

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   OWASP Testing Guide: Testing for weak cryptography


## 対応するCWE一覧

CWE-261 Weak Encoding for Password

CWE-296 Improper Following of a Certificate's Chain of Trust

CWE-310 Cryptographic Issues

CWE-319 Cleartext Transmission of Sensitive Information

CWE-321 Use of Hard-coded Cryptographic Key

CWE-322 Key Exchange without Entity Authentication

CWE-323 Reusing a Nonce, Key Pair in Encryption

CWE-324 Use of a Key Past its Expiration Date

CWE-325 Missing Required Cryptographic Step

CWE-326 Inadequate Encryption Strength

CWE-327 Use of a Broken or Risky Cryptographic Algorithm

CWE-328 Reversible One-Way Hash

CWE-329 Not Using a Random IV with CBC Mode

CWE-330 Use of Insufficiently Random Values

CWE-331 Insufficient Entropy

CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator
(PRNG)

CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)

CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)

CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator
(PRNG)

CWE-340 Generation of Predictable Numbers or Identifiers

CWE-347 Improper Verification of Cryptographic Signature

CWE-523 Unprotected Transport of Credentials

CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications

CWE-757 Selection of Less-Secure Algorithm During Negotiation
('Algorithm Downgrade')

CWE-759 Use of a One-Way Hash without a Salt

CWE-760 Use of a One-Way Hash with a Predictable Salt

CWE-780 Use of RSA Algorithm without OAEP

CWE-818 Insufficient Transport Layer Protection

CWE-916 Use of Password Hash With Insufficient Computational Effort

# A02:2021 – Cryptographic Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              | 79.33%       | 34.85%       | 7.29                 | 6.81                | 233,788           | 3,075      |

## Overview

Shifting up one position to #2, previously known as *Sensitive Data
Exposure*, which is more of a broad symptom rather than a root cause,
the focus is on failures related to cryptography (or lack thereof).
Which often lead to exposure of sensitive data. Notable CWEs included
are *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky
Crypto Algorithm*, and *CWE-331 Insufficient Entropy* .

## Description 

The first thing is to determine the protection needs of data in transit
and at rest. For example, passwords, credit card numbers, health
records, personal information, and business secrets require extra
protection, mainly if that data falls under privacy laws, e.g., EU's
General Data Protection Regulation (GDPR), or regulations, e.g.,
financial data protection such as PCI Data Security Standard (PCI DSS).
For all such data:

-   Is any data transmitted in clear text? This concerns protocols such
    as HTTP, SMTP, and FTP. External internet traffic is hazardous.
    Verify all internal traffic, e.g., between load balancers, web
    servers, or back-end systems.

-   Are any old or weak cryptographic algorithms used either by default
    or in older code?

-   Are default crypto keys in use, weak crypto keys generated or
    re-used, or is proper key management or rotation missing?

-   Is encryption not enforced, e.g., are any user agent (browser)
    security directives or headers missing?

-   Does the user agent (e.g., app, mail client) not verify if the
    received server certificate is valid?

See ASVS Crypto (V7), Data Protection (V9), and SSL/TLS (V10)

## How to Prevent

Do the following, at a minimum, and consult the references:

-   Classify data processed, stored, or transmitted by an application.
    Identify which data is sensitive according to privacy laws,
    regulatory requirements, or business needs.

-   Apply controls as per the classification.

-   Don't store sensitive data unnecessarily. Discard it as soon as
    possible or use PCI DSS compliant tokenization or even truncation.
    Data that is not retained cannot be stolen.

-   Make sure to encrypt all sensitive data at rest.

-   Ensure up-to-date and strong standard algorithms, protocols, and
    keys are in place; use proper key management.

-   Encrypt all data in transit with secure protocols such as TLS with
    perfect forward secrecy (PFS) ciphers, cipher prioritization by the
    server, and secure parameters. Enforce encryption using directives
    like HTTP Strict Transport Security (HSTS).

-   Disable caching for response that contain sensitive data.

-   Store passwords using strong adaptive and salted hashing functions
    with a work factor (delay factor), such as Argon2, scrypt, bcrypt or
    PBKDF2.

-   Verify independently the effectiveness of configuration and
    settings.

## Example Attack Scenarios

**Scenario #1**: An application encrypts credit card numbers in a
database using automatic database encryption. However, this data is
automatically decrypted when retrieved, allowing a SQL injection flaw to
retrieve credit card numbers in clear text.

**Scenario #2**: A site doesn't use or enforce TLS for all pages or
supports weak encryption. An attacker monitors network traffic (e.g., at
an insecure wireless network), downgrades connections from HTTPS to
HTTP, intercepts requests, and steals the user's session cookie. The
attacker then replays this cookie and hijacks the user's (authenticated)
session, accessing or modifying the user's private data. Instead of the
above they could alter all transported data, e.g., the recipient of a
money transfer.

**Scenario #3**: The password database uses unsalted or simple hashes to
store everyone's passwords. A file upload flaw allows an attacker to
retrieve the password database. All the unsalted hashes can be exposed
with a rainbow table of pre-calculated hashes. Hashes generated by
simple or fast hash functions may be cracked by GPUs, even if they were
salted.

## References

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Password and Cryptographic Storage

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   OWASP Testing Guide: Testing for weak cryptography


## List of Mapped CWEs

CWE-261 Weak Encoding for Password

CWE-296 Improper Following of a Certificate's Chain of Trust

CWE-310 Cryptographic Issues

CWE-319 Cleartext Transmission of Sensitive Information

CWE-321 Use of Hard-coded Cryptographic Key

CWE-322 Key Exchange without Entity Authentication

CWE-323 Reusing a Nonce, Key Pair in Encryption

CWE-324 Use of a Key Past its Expiration Date

CWE-325 Missing Required Cryptographic Step

CWE-326 Inadequate Encryption Strength

CWE-327 Use of a Broken or Risky Cryptographic Algorithm

CWE-328 Reversible One-Way Hash

CWE-329 Not Using a Random IV with CBC Mode

CWE-330 Use of Insufficiently Random Values

CWE-331 Insufficient Entropy

CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator
(PRNG)

CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)

CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)

CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator
(PRNG)

CWE-340 Generation of Predictable Numbers or Identifiers

CWE-347 Improper Verification of Cryptographic Signature

CWE-523 Unprotected Transport of Credentials

CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications

CWE-757 Selection of Less-Secure Algorithm During Negotiation
('Algorithm Downgrade')

CWE-759 Use of a One-Way Hash without a Salt

CWE-760 Use of a One-Way Hash with a Predictable Salt

CWE-780 Use of RSA Algorithm without OAEP

CWE-818 Insufficient Transport Layer Protection

CWE-916 Use of Password Hash With Insufficient Computational Effort
