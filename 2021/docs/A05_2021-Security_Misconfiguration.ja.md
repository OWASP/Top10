# A05:2021-セキュリティの設定ミス    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 89.58%       | 44.84%       | 8.12                 | 6.56                | 208,387           | 789        |

## 概要

前回の 6 位から順位を上げました。アプリケーションの 90 ％には何らかの設定ミスが確認され、平均発生率は 4 ％であり、20 万 8 千以上のCWEが発生していました。
高度な設定が可能なソフトウェアへの移行が進む中で、このカテゴリーの順位が上がったことは当然と言えます。
注目すべき CWE (Common Weakness Enumeration) は *CWE-16 設定の問題* と *CWE-611 外部に置かれたファイルを呼び出す XXE (Xml eXternal Entity) 問題* です。

## 説明

アプリケーションが下記のようなら、恐らく脆弱です:

-   アプリケーションスタックのいずれかの部分におけるセキュリティ堅牢化の不足、あるいはクラウドサービスでパーミッションが不適切に設定されている

-   必要のない機能が有効、あるいはインストールされている(例えば、必要のないポートやサービス、ページ、アカウント、特権)

-   デフォルトのアカウントとパスワードが有効になったまま変更されていない

-   エラー処理がユーザに対して、スタックトレースやその他余計な情報を含むエラーメッセージを見せる

-   アップグレードしたシステムでは、最新のセキュリティ機能が無効になっているか正しく設定されていない

-   アプリケーションサーバやアプリケーションフレームワーク(例えば、Struts、Spring、 ASP.NET)、ライブラリ、データベース等のセキュリティの設定が、安全な値に設定されていない

-   サーバがセキュリテイヘッダーやディレクティブを送らなかったり、安全な値に設定されていなかったりする

-   ソフトウェアが古いか脆弱である。([# A06:2021 – 脆弱で古くなったコンポーネント](A06_2021-Vulnerable_and_Outdated_Components.md) を参照)

アプリケーションのセキュリティを設定するプロセスを協調して繰り返すことができなければ、システムはより高いリスクにさらされます。

## 防止方法

安全にインストールするプロセスにおいて、以下のことを実施すべきです:

-   繰り返し堅牢化するプロセスは、素早くかつ容易に他の環境に展開され、正しくロックダウンすること。
    開発やQA、本番環境は完全に同じように設定し、それぞれの環境で別々の認証情報を使用すること。
    このプロセスを自動化し、新しい安全な環境をセットアップする際には、手間を最小限にすること。

-   プラットフォームは最小限のものとし、必要のない機能やコンポーネント、ドキュメント、サンプルを除くこと。
    使用しない機能とフレームワークは、削除もしくはインストールしないこと。

-   レビューを実施して、セキュリティ関連の記録と更新の全てに加え、パッチを管理するプロセスの一環としてパッチの設定を適切に更新すること([# A06:2021 – 脆弱で古くなったコンポーネント](A06_2021-Vulnerable_and_Outdated_Components.md) を参照)。
    クラウドストレージのパーミッションは、詳細にレビューすること (例えば、S3 バケットのパーミッション)。

-   セグメント化したアプリケーションアーキテクチャは、セグメンテーションやコンテナリゼーション、クラウドのセキュリティグループ(ACL)をともなったコンポーネントやテナント間に、効果的で安全な仕切りをもたらす。

-   セキュリティディレクティブをクライアントへ送ること。例としては セキュリティヘッダー が挙げられる。

-   プロセスを自動化して設定の有効性を検証し、環境すべてに適用すること。

## 攻撃シナリオの例

**シナリオ #1:** 

アプリケーションのサンプルが付属しているアプリケーションサーバであるにもかかわらず、プロダクションサーバからサンプルが削除されていません。
このサンプルアプリケーションには、攻撃者がサーバに侵入する際によく使う既知の脆弱性があります。
そのアプリケーションが管理用のコンソールでデフォルトのアカウントが変更されていないと、攻撃者はデフォルトのパスワードを使ってログインし、乗っ取ってしまいます。

**シナリオ #2:** 

ディレクトリリスティングがサーバ上で無効になっていません。攻撃者はそれを見つけ出し、やすやすとディレクトリを表示してしまいます。
攻撃者はコンパイル済みのJavaクラスを見つけてダウンロードし、デコンパイルしてからリバースエンジニアリングしてコードを見ます。
そして攻撃者は、そのアプリケーションの深刻なアクセス制御上の穴を見つけます。

**シナリオ #3:** 

アプリケーションサーバの設定が、詳細なエラーメッセージ(例えば、スタックトレース)をユーザに返すようになっています。
これによって機微な情報や脆弱であるとされているコンポーネントのバージョンといった潜在的な欠陥がさらされる恐れがあります。

**シナリオ #4:** 

クラウドサービスプロバイダ (CSP) は、他のCSPユーザによるデフォルトでインターネットに公開された共有パーミッションを用意しています。
こうなると、機微な情報がクラウドストレージに保存され、アクセスされてしまいます。

## 参考資料

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   [Application Security Verification Standard V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## 対応する CWE のリスト

[CWE-2 環境設定](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET における設定ミス: デバッグバイナリの作成](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET における設定ミス: パスワードが設定ファイルに格納されている問題](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 システムやコンフィグレーション設定の外部制御](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 設定の問題](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 パスワードが設定ファイルに格納されている問題](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 クッキーへの機密情報の平文保存](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET における設定ミス: 偽装の使用](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 環境変数による機密情報の暴露](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 機密情報を含む Java ランタイムエラーメッセージ](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 インクルードファイルへの機密情報の取り込み](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 ハードコードされたセキュリティ関連の定数の使用](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 外部に置かれたファイルを呼び出す XXE (Xml eXternal Entity) 問題](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 'Secure' 属性のない HTTPS セッションにおける機密性の高いクッキー](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 カスタムエラーページが表示されない問題](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 適切でない再帰的なエンティティ参照制限 (XML Entity Expansion) 問題](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 過剰に許可されたクロスドメイン・ホワイトリスト](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 'HttpOnly' フラグのない 機密性の高いクッキー](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - 不適切なセキュリティ設定](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET における設定ミス: 不適切なモデル検証](https://cwe.mitre.org/data/definitions/1174.html)

# A05:2021 – Security Misconfiguration    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 8.12                 | 6.56                | 89.58%       | 44.84%       | 208,387           | 789        |

## Overview

Moving up from #6 in the previous edition, 90% of applications were
tested for some form of misconfiguration, with an average incidence rate of 4.%, and over 208k occurences of a Common Weakness Enumeration (CWE) in this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up.
Notable CWEs included are *CWE-16 Configuration* and *CWE-611 Improper
Restriction of XML External Entity Reference*.

## Description 

The application might be vulnerable if the application is:

-   Missing appropriate security hardening across any part of the
    application stack or improperly configured permissions on cloud
    services.

-   Unnecessary features are enabled or installed (e.g., unnecessary
    ports, services, pages, accounts, or privileges).

-   Default accounts and their passwords are still enabled and
    unchanged.

-   Error handling reveals stack traces or other overly informative
    error messages to users.

-   For upgraded systems, the latest security features are disabled or
    not configured securely.

-   The security settings in the application servers, application
    frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases,
    etc., are not set to secure values.

-   The server does not send security headers or directives, or they are
    not set to secure values.

-   The software is out of date or vulnerable (see [A06:2021-Vulnerable
    and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)).

Without a concerted, repeatable application security configuration
process, systems are at a higher risk.

## How to Prevent

Secure installation processes should be implemented, including:

-   A repeatable hardening process makes it fast and easy to deploy
    another environment that is appropriately locked down. Development,
    QA, and production environments should all be configured
    identically, with different credentials used in each environment.
    This process should be automated to minimize the effort required to
    set up a new secure environment.

-   A minimal platform without any unnecessary features, components,
    documentation, and samples. Remove or do not install unused features
    and frameworks.

-   A task to review and update the configurations appropriate to all
    security notes, updates, and patches as part of the patch management
    process (see [A06:2021-Vulnerable
    and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)). Review
    cloud storage permissions (e.g., S3 bucket permissions).

-   A segmented application architecture provides effective and secure
    separation between components or tenants, with segmentation,
    containerization, or cloud security groups (ACLs).

-   Sending security directives to clients, e.g., Security Headers.

-   An automated process to verify the effectiveness of the
    configurations and settings in all environments.

## Example Attack Scenarios

**Scenario #1:** The application server comes with sample applications
not removed from the production server. These sample applications have
known security flaws attackers use to compromise the server. Suppose one
of these applications is the admin console, and default accounts weren't
changed. In that case, the attacker logs in with default passwords and
takes over.

**Scenario #2:** Directory listing is not disabled on the server. An
attacker discovers they can simply list directories. The attacker finds
and downloads the compiled Java classes, which they decompile and
reverse engineer to view the code. The attacker then finds a severe
access control flaw in the application.

**Scenario #3:** The application server's configuration allows detailed
error messages, e.g., stack traces, to be returned to users. This
potentially exposes sensitive information or underlying flaws such as
component versions that are known to be vulnerable.

**Scenario #4:** A cloud service provider (CSP) has default sharing
permissions open to the Internet by other CSP users. This allows
sensitive data stored within cloud storage to be accessed.

## References

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   [Application Security Verification Standard V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## List of Mapped CWEs

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
