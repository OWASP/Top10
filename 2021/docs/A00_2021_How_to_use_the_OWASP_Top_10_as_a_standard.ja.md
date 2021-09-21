# OWASP Top 10 をスタンダードとして使うには

OWASP Top 10 は、主に意識向上を目的とした文書です。
しかし 2003 年に開始されて以来、組織は事実上の業界におけるアプリケーションセキュリティのスタンダードとして使い続けています。
OWASP トップ 10 をコーディングやテストの基準として使用したい場合は、それが最低限のものであり、出発点に過ぎないことを知っておいてください。

OWASP トップ 10 をスタンダードとして使うことの難しさの 1 つは、OWASP Top 10 はアプリケーションセキュリティのリスクを文書化しているものであり、必ずしも簡単にテストできるわけではないということです。
例えば「A04:2021-安全が確認されない不安な設計」は、ほとんどの形式のテストの範囲を超えています。
他の例としては、設置、使用、効果的なロギングとモニタリングのテストがあります。これらのテストは、インタビューを行い効果的なインシデントレスポンスのサンプルを要求しなければ実施できません。
静的なコード解析ツールは、ロギングが行われていないかどうかを調べることができますが、ビジネスロジックやアクセス制御が重要なセキュリティ違反のロギングを行っているかどうかを判断することは不可能かもしれません。
侵入テスト担当者は、本番環境と同じように監視されることがほとんどないテスト環境で、インシデントレスポンスを起動したことを判断することしかできない可能性があります。

ここでは、OWASP Top 10 を使用することが推奨されるユースケースを示します。

| ユースケース                | OWASP Top 10 2021 | OWASPアプリケーションセキュリティ検証標準 (OWASP ASVS) |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| 意識向上               | 推奨               |                                                  |
| 訓練                | 入門レベル       | 包括的                                    |
| 設計とアーキテクチャ | 適切である場合もある      | 推奨                                              |
| コーディングスタンダード         | 必要最低限      | 推奨                                              |
| セキュアコードレビュー      | 必要最低限      | 推奨                                              |
| ピアレビューにおけるチェックリスト   | 必要最低限      | 推奨                                              |
| ユニットテスト            | 適切である場合もある      | 推奨                                              |
| 統合テスト     | 適切である場合もある      | 推奨                                              |
| 侵入テスト     | 必要最低限      | 推奨                                              |
| ツール支援            | 必要最低限      | 推奨                                              |
| セキュアサプライチェーン     | 適切である場合もある      | 推奨                                              |

アプリケーション・セキュリティにおけるスタンダードをを採用したいと考えている人には、OWASP Application Security Verification Standard（ASVS）を使用することをお勧めします。

OWASP ASVS は、ツールベンダーにとって唯一受け入れられる選択肢です。
OWASP トップ 10 におけるリスクの性質上、ツールは OWASP トップ 10 を包括的に検出、テスト、あるいは保護することはできません。例えば「A04:2021-安全が確認されない不安な設計」があげられます。
OWASP は、ツールが OWASP トップ 10 を完全に網羅していると主張することは、単純に事実と異なるため、推奨しません。

# How to use the OWASP Top 10 as a standard

The OWASP Top 10 is primarily an awareness document. However, this has
not stopped organizations using it as a de facto industry AppSec
standard since its inception in 2003. If you want to use the OWASP Top
10 as a coding or testing standard, know that it is the bare minimum and
just a starting point.

One of the difficulties of using the OWASP Top 10 as a standard is that
we document appsec risks, and not necessarily easily testable issues.
For example, A04:2021-Insecure Design is beyond the scope of most forms
of testing. Another example is testing in place, in use, and effective
logging and monitoring can only be done with interviews and requesting a
sampling of effective incident responses. A static code analysis tool
can look for the absence of logging, but it might be impossible to
determine if business logic or access control is logging critical
security breaches. Penetration testers may only be able to determine
that they have invoked incident response in a test environment, which
are rarely monitored in the same way as production.

Here are our recommendations for when it is appropriate to use the OWASP
Top 10:

| Use Case                | OWASP Top 10 2021 | OWASP Application Security Verification Standard |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| Awareness               | Yes               |                                                  |
| Training                | Entry level       | Comprehensive                                    |
| Design and architecture | Occasionally      | Yes                                              |
| Coding standard         | Bare minimum      | Yes                                              |
| Secure Code review      | Bare minimum      | Yes                                              |
| Peer review checklist   | Bare minimum      | Yes                                              |
| Unit testing            | Occasionally      | Yes                                              |
| Integration testing     | Occasionally      | Yes                                              |
| Penetration testing     | Bare minimum      | Yes                                              |
| Tool support            | Bare minimum      | Yes                                              |
| Secure Supply Chain     | Occasionally      | Yes                                              |

We would encourage anyone wanting to adopt an application security
standard to use the OWASP Application Security Verification Standard
(ASVS), as it’s designed to be verifiable and tested, and can be used in
all parts of a secure development lifecycle.

The ASVS is the only acceptable choice for tool vendors. Tools cannot
comprehensively detect, test, or protect against the OWASP Top 10 due to
the nature of several of the OWASP Top 10 risks, with reference to
A04:2021-Insecure Design. OWASP discourages any claims of full coverage
of the OWASP Top 10, because it’s simply untrue.
