# A10:2021 - サーバーサイドリクエストフォージェリ (SSRF)

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 | 最大網羅率 | 平均網羅率 | 加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 67.72%       | 67.72%       | 8.28                 | 6.72                | 9,503             | 385        |

## 概要

このカテゴリは業界の調査（第1位）から追加されました。
調査データからわかることは、よくあるテストより広範な範囲において、問題の発生率は比較的低いものの、問題が起きた場合のエクスプロイトとインパクトは平均以上のものとなり得ます。
このSSRFのような新しい項目は、注意と認識を上げるために単一または小さなCWEの集合であることが多く、注目を集めることで将来のバージョンにてより大きなカテゴリに集約されるよう期待されています。

## 説明

SSRFの欠陥は、Webアプリケーション上からリモートのリソースを取得する際に、ユーザーから提供されたURLを検証せずに使用することで発生します。
ファイアウォールやVPNあるいはその他の種類のネットワークACLによってアプリケーションが保護されている場合であっても、SSRFによりアプリケーションに対して意図しない宛先へ細工されたリクエストを強制的に発行させることができます。

モダンなアプリケーションではエンドユーザーに便利な機能を提供するようになり、アプリケーション側でURLを取得することは珍しい状況ではなくなりました。
そのためSSRFの発生が増加しています。
またSSRFの深刻度も、クラウドサービスやアーキテクチャの複雑性を背景として、段々と大きくなりつつあります。

## 防止方法

開発者は以下の多層防御の制御の一部ないし全てを実装することにより、SSRFを防ぐことができます。

## **ネットワーク層から**

-   SSRFの影響を減らすために、リモートのリソースへアクセスする機能を分離されたネットワークに切り出します。

-   必須のイントラネット通信を除き全ての通信をブロックするよう、「デフォルト拒否」のファイアウォールポリシーまたはネットワークアクセス制御を強制します。

## **アプリケーション層から:**

-   クライアントが提供した全ての入力データをサニタイズし、検証します。

-   明確な許可リスト用いてURLスキーム、ポート、宛先を強制します。

-   生のレスポンスをクライアントに送信しないようにします。

-   HTTPのリダイレクトを無効化します。

-   DNSリバインディングや"time of check, time of use" (TOCTOU) 競合状態といった攻撃を防ぐために、URLの整合性に注意します。

拒否リストや正規表現を用いてのSSRF対策を実装しないでください。攻撃者は拒否リストを回避するためのペイロードのリスト、ツール、そして技術を備えています。

## 攻撃シナリオの例

攻撃者は以下のようなシナリオで、Webアプリケーションファイアウォールやファイアウォール、もしくはネットワークACLによって保護されたアプリケーションを攻撃することができます:

**シナリオ #1:** 内部サーバーへのポートスキャン。セグメント化されていないネットワークアーキテクチャの場合、攻撃者は内部ネットワークを標的として、SSRFペイロードの接続結果もしくは接続や拒否されるまでにかかった時間をもとに内部サーバーのポートがオープンかクローズかを調べます。

**シナリオ #2:** 機微な情報の露出。攻撃者は機微な情報を取得するために、<file:///etc/passwd> のようなローカルファイルまたは内部サーバーにアクセスします。

**シナリオ #3:** クラウドサービスのメタデータストレージへのアクセス。多くのクラウドプロバイダは <http://169.254.169.254/> のようなメタデータストレージを提供しています。攻撃者は機微な情報を取得するためにメタデータを読み取ります。

**シナリオ #4:** 内部サービスの乗っ取り - 攻撃者はリモートコード実行 (RCE) やサービス拒否 (DoS) のようなさらなる攻撃を行うために内部サービスを悪用します。

## 参考資料

-   [OWASP - Server-Side Request Forgery Prevention Cheat
    Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery
    (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery
    (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF
    bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming
    Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## 対応する CWE のリスト

CWE-918 Server-Side Request Forgery (SSRF)

# A10:2021 – Server-Side Request Forgery (SSRF)

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 67.72%       | 67.72%       | 8.28                 | 6.72                | 9,503             | 385        |

## Overview

This category is added from the industry survey (#1). The data shows a
relatively low incidence rate with above average testing coverage and
above-average Exploit and Impact potential ratings. As new entries are
likely to be a single or small cluster of CWEs for attention and
awareness, the hope is that they are subject to focus and can be rolled
into a larger category in a future edition.

## Description

SSRF flaws occur whenever a web application is fetching a remote
resource without validating the user-supplied URL. It allows an attacker
to coerce the application to send a crafted request to an unexpected
destination, even when protected by a firewall, VPN, or another type of
network ACL.

As modern web applications provide end-users with convenient features,
fetching a URL becomes a common scenario. As a result, the incidence of
SSRF is increasing. Also, the severity of SSRF is becoming higher due to
cloud services and the complexity of architectures.

## How to Prevent

Developers can prevent SSRF by implementing some or all the following
defense in depth controls:

## **From Network layer**

-   Segment remote resource access functionality in separate networks to
    reduce the impact of SSRF

-   Enforce “deny by default” firewall policies or network access
    control rules to block all but essential intranet traffic

## **From Application layer:**

-   Sanitize and validate all client-supplied input data

-   Enforce the URL schema, port, and destination with a positive allow
    list

-   Do not send raw responses to clients

-   Disable HTTP redirections

-   Be aware of the URL consistency to avoid attacks such as DNS
    rebinding and “time of check, time of use” (TOCTOU) race conditions

Do not mitigate SSRF via the use of a deny list or regular expression.
Attackers have payload lists, tools, and skills to bypass deny lists.

## Example Attack Scenarios

Attackers can use SSRF to attack systems protected behind web
application firewalls, firewalls, or network ACLs, using scenarios such
as:

**Scenario #1:** Port scan internal servers. If the network architecture
is unsegmented, attackers can map out internal networks and determine if
ports are open or closed on internal servers from connection results or
elapsed time to connect or reject SSRF payload connections.

**Scenario #2:** Sensitive data exposure. Attackers can access local
files such as <file:///etc/passwd> or internal services to gain
sensitive information.

**Scenario #3:** Access metadata storage of cloud services. Most cloud
providers have metadata storage such as <http://169.254.169.254/>. An
attacker can read the metadata to gain sensitive information.

**Scenario #4:** Compromise internal services – The attacker can abuse
internal services to conduct further attacks such as Remote Code
Execution (RCE) or Denial of Service (DoS).

## References

-   [OWASP - Server-Side Request Forgery Prevention Cheat
    Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery
    (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery
    (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF
    bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming
    Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## List of Mapped CWEs

CWE-918 Server-Side Request Forgery (SSRF)
