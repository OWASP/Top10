# A08:2021 – ソフトウェアとデータの整合性の不具合

## 因子

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 75.04%       | 45.35%       | 6.94                 | 7.94                | 47,972            | 1,152      |

## 概要

これは2021年に新設されたカテゴリーで、ソフトウェアの更新、重要なデータを、CI/CDパイプラインにおいて整合性を検証せずに見込みで進めることによる問題にフォーカスしています。
CVSSのデータから最も重大な影響を受けたものの1つです。
注目すべきCWEは、*CWE-502: 信頼できないデータのデシリアライゼーション*, *CWE-829: 信頼できない制御領域からの機能の組み込み*, そして*CWE-494: ダウンロードしたコードの完全性検証不備*です。

## 説明

Software and data integrity failures relate to code and infrastructure
that does not protect against integrity violations. For example, where
objects or data are encoded or serialized into a structure that an
attacker can see and modify is vulnerable to insecure deserialization.
Another form of this is where an application relies upon plugins,
libraries, or modules from untrusted sources, repositories, and content
delivery networks (CDNs). An insecure CI/CD pipeline can introduce the
potential for unauthorized access, malicious code, or system compromise.
Lastly, many applications now include auto-update functionality, where
updates are downloaded without sufficient integrity verification and
applied to the previously trusted application. Attackers could
potentially upload their own updates to be distributed and run on all
installations.

## 防止方法

-   シリアライズされたデータの改ざんや再生成を検出する何らかの整合性確認やデジタル署名を行うことなしに、信頼されていないクライアントに対して未署名もしくは暗号化されていないシリアライズされたデータを送信しません。

-   署名あるいは類似のメカニズムを用いて、ソフトウェアやデータが意図されたソースから取得されたものであることを検証します。

-   npmやMavenなど、ライブラリや依存関係が信頼されたリポジトリを使用していることを確認します。

-   コンポーネントが既知の脆弱性を含まないことを検証するために、OWASP Dependency CheckやOWASP CycloneDXといったソフトウェアサプライチェーンセキュリティツールが使用されていることを確認します。

-   CI/CDパイプラインが適切に設定されアクセス制御が行われていること、また、ビルドやデプロイのプロセスに至るコードフローの整合性が確保されていることを確認します。

## 攻撃シナリオの例

**シナリオ #1 安全でないデシリアライゼーション:** Reactアプリケーションが、一連のSpring Bootマイクロサービスを呼び出します。
関数型言語のプログラマーは、イミュータブルなコードを書こうとします。
そこで、プログラマーは、呼び出しの前後でシリアライズしたユーザーの状態を渡す、と言う解決策を思いつきます。
攻撃者は "rO0" というJavaオブジェクトのシグネチャに気づき、Java Serial Killerツールを使用してアプリケーションサーバ上でリモートコードを実行します。

**シナリオ #2 署名のないアップデート:** 多くのホームルーター、セットトップボックス、デバイスファームウェア等は、署名済みファームウェアによるアップデートの検証を行いません。
未署名のファームウェアは、攻撃者にとって拡大しつつある標的であり、悪化の一途が予想されます。
多くの場合においてこの問題を解決するためには、将来のバージョンにて修正を行った上で以前のバージョンが使用されなくなるのを待つほかないことから、これは非常に大きな懸念事項です。

**シナリオ #3 SolarWindsの悪意のあるアップデート**: 最近の注目すべき攻撃がSolarWinds Orionでの攻撃であるということと併せて、国家はアップデートの機構を攻撃することが知られています。
そのソフトウェアを開発した企業は、安全なビルドとアップデートの整合プロセスを備えていました。
しかし、それらは破壊することが可能であったために、その企業は、数ヶ月にわたって、高度に標的化された悪意のあるアップデートを18,000を超える組織に配信し、そのうち100ほどの組織が影響を受けました。
この一件は、この類の侵害としては、歴史上最も広範囲に影響が広がり、また最も重大であったものの一つです。

## 参考資料

-   \[OWASP Cheat Sheet: Deserialization\](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   \[OWASP Cheat Sheet: Software Supply Chain Security\]()

-   \[OWASP Cheat Sheet: Secure build and deployment\]()

-   \[SAFECode Software Integrity Controls\](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   \[A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack\](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   <https://www.manning.com/books/securing-devops>

## 対応する CWE のリスト

CWE-345 Insufficient Verification of Data Authenticity

CWE-353 Missing Support for Integrity Check

CWE-426 Untrusted Search Path

CWE-494 Download of Code Without Integrity Check

CWE-502 Deserialization of Untrusted Data

CWE-565 Reliance on Cookies without Validation and Integrity Checking

CWE-784 Reliance on Cookies without Validation and Integrity Checking in
a Security Decision

CWE-829 Inclusion of Functionality from Untrusted Control Sphere

CWE-830 Inclusion of Web Functionality from an Untrusted Source

CWE-915 Improperly Controlled Modification of Dynamically-Determined
Object Attributes


# A08:2021 – Software and Data Integrity Failures

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 75.04%       | 45.35%       | 6.94                 | 7.94                | 47,972            | 1,152      |

## Overview

A new category for 2021 focuses on making assumptions related to
software updates, critical data, and CI/CD pipelines without verifying
integrity. One of the highest weighted impacts from CVE/CVSS data.
Notable CWEs include *CWE-502: Deserialization of Untrusted Data*,
*CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, and
*CWE-494: Download of Code Without Integrity Check*.

## Description

Software and data integrity failures relate to code and infrastructure
that does not protect against integrity violations. For example, where
objects or data are encoded or serialized into a structure that an
attacker can see and modify is vulnerable to insecure deserialization.
Another form of this is where an application relies upon plugins,
libraries, or modules from untrusted sources, repositories, and content
delivery networks (CDNs). An insecure CI/CD pipeline can introduce the
potential for unauthorized access, malicious code, or system compromise.
Lastly, many applications now include auto-update functionality, where
updates are downloaded without sufficient integrity verification and
applied to the previously trusted application. Attackers could
potentially upload their own updates to be distributed and run on all
installations.

## How to Prevent

-   Ensure that unsigned or unencrypted serialized data is not sent to
    untrusted clients without some form of integrity check or digital
    signature to detect tampering or replay of the serialized data

-   Verify the software or data is from the expected source via signing
    or similar mechanisms

-   Ensure libraries and dependencies, such as npm or Maven, are
    consuming trusted repositories

-   Ensure that a software supply chain security tool, such as OWASP
    Dependency Check or OWASP CycloneDX, is used to verify that
    components do not contain known vulnerabilities

-   Ensure that your CI/CD pipeline has proper configuration and access
    control to ensure the integrity of the code flowing through the
    build and deploy processes.

## Example Attack Scenarios

**Scenario #1 Insecure Deserialization:** A React application calls a
set of Spring Boot microservices. Being functional programmers, they
tried to ensure that their code is immutable. The solution they came up
with is serializing the user state and passing it back and forth with
each request. An attacker notices the "R00" Java object signature and
uses the Java Serial Killer tool to gain remote code execution on the
application server.

**Scenario #2 Update without signing:** Many home routers, set-top
boxes, device firmware, and others do not verify updates via signed
firmware. Unsigned firmware is a growing target for attackers and is
expected to only get worse. This is a major concern as many times there
is no mechanism to remediate other than to fix in a future version and
wait for previous versions to age out.

**Scenario #3 SolarWinds malicious update**: Nation-states have been
known to attack update mechanisms, with a recent notable attack being
the SolarWinds Orion attack. The company that develops the software had
secure build and update integrity processes. Still, these were able to
be subverted, and for several months, the firm distributed a highly
targeted malicious update to more than 18,000 organizations, of which
around 100 or so were affected. This is one of the most far-reaching and
most significant breaches of this nature in history.

## References

-   \[OWASP Cheat Sheet: Deserialization\](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   \[OWASP Cheat Sheet: Software Supply Chain Security\]()

-   \[OWASP Cheat Sheet: Secure build and deployment\]()

-   \[SAFECode Software Integrity Controls\](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   \[A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack\](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   <https://www.manning.com/books/securing-devops>

## List of Mapped CWEs

CWE-345 Insufficient Verification of Data Authenticity

CWE-353 Missing Support for Integrity Check

CWE-426 Untrusted Search Path

CWE-494 Download of Code Without Integrity Check

CWE-502 Deserialization of Untrusted Data

CWE-565 Reliance on Cookies without Validation and Integrity Checking

CWE-784 Reliance on Cookies without Validation and Integrity Checking in
a Security Decision

CWE-829 Inclusion of Functionality from Untrusted Control Sphere

CWE-830 Inclusion of Web Functionality from an Untrusted Source

CWE-915 Improperly Controlled Modification of Dynamically-Determined
Object Attributes
