# OWASP Top 10 を使ってアプリケーションセキュリティプログラムを始めるには

これまでは OWASP トップ 10 は、アプリケーションセキュリティプログラムの基礎となるようには設計されていませんでした。
しかしアプリケーションセキュリティの道を歩み始めたばかりの多くの組織にとっては、基礎となる物が不可欠です。
OWASP トップ 10 2021 は、チェックリストなどのベースラインとしては良いスタートとなりますが、それだけでは十分ではありません。

## ステージ1. 自社のセキュリティプログラムのギャップと目標を特定する

アプリケーション・セキュリティプログラムの多くは、地道に丁寧に進めるのではなく、一気に進められようとします。このような取り組みは、失敗する運命にあります。
私たちは、CISO と アプリケーションセキュリティのリーダーに、[ソフトウエアセキュリティ保証成熟度モデル](https://owaspsamm.org) (OWASP SAMM) を使用して、1～3 年の期間で弱点と改善点を特定することを強くお勧めします。
最初のステップは、現在の状況を評価し、すぐに解決しなければならないガバナンス、設計、実装、検証、および運用におけるギャップと、後回しにしてもよいギャップを特定し、15 の OWASP SAMM セキュリティ・プラク ティスの実施または改善を優先することです。
OWASP SAMM は、ソフトウェア保証の取り組みを構築し、成熟度を測定するのに役立ちます。

## ステージ 2. 信頼性が高く安全性も検証されているセキュア開発ライフサイクルの計画

従来はいわゆる「ユニコーン企業」のものでしたが、「ペイブド・ロード」コンセプトは、年々増加する開発チームの速度に合わせてアプリケーションセキュリティリソースを拡張し、最大の効果を上げるための最も簡単な方法です。

「ペイブド・ロード」コンセプトは、「最も簡単な方法は、最も安全な方法でもある」というもので、開発チームとセキュリティチームの間に深いパートナーシップの文化が必要であり、できれば両者が同じチームであることが望ましいとされます。
「ペイブド・ロード」コンセプトは、継続的な改善、測定、検出、および安全でないコンポーネントの交換を目的としており、企業全体で安全な代替品としてそのまま置換え可能なライブラリと、「ペイブド・ロード」コンセプトを採用することで改善できる箇所を確認するためのツールを備えています。
これにより、既存の開発ツールが安全ではないビルドを報告し、開発チームが安全ではないコンポーネントを自己修正することができます。

「ペイブド・ロード」コンセプトは、多くのことを吸収するように見えるかもしれませんが、時間をかけて段階的に構築していくべきです。
アプリケーションセキュリティプログラムには、マイクロソフトアジャイルセキュア開発ライフサイクルをはじめとする他の形態もあります。
すべてのセキュリティプログラムの手法がすべてのビジネスに適しているわけではありません。

## ステージ 3. 「ペイブド・ロード」コンセプトを開発チームで実行する

「ペイブド・ロード」コンセプトは、関連する開発チームと運用チームの同意と直接の関与を得て構築されます。
「ペイブド・ロード」コンセプトはビジネスと戦略的に連携し、より安全なアプリケーションをより早く提供するのに役立つものでなければなりません。
「ペイブド・ロード」コンセプトにおける開発は、昔のようにアプリケーションごとの応急処置ではなく、企業やアプリケーションのエコシステム全体を対象とした全体的な取り組みでなければなりません。

## ステージ 4. 今後発売されるアプリケーションや既存のアプリケーションをすべて「ペイブド・ロード」コンセプトに移行する

開発時に信頼性が高く安全性も検証されている検出ツールを追加し、開発チームがこれらの要素を直接採用し、アプリケーションのセキュリティを向上させるための情報を提供します。
「ペイブド・ロード」コンセプトのある側面が採用されたら、組織は、禁止されている選択肢を使用している既存のコードやチェックインを検査し、ビルドやチェックインを警告または拒否する継続的統合チェックを実施する必要があります。
これにより、安全でない選択肢が時間の経過とともにコードに入り込むことを防ぎ、技術的負債や欠陥のある安全でないアプリケーションを防ぐことができます。
安全な代替案にリンクして、開発チームがすぐに正しい答えを得られるようにする警告を出す必要があります。
開発チームはリファクタリングを行い、信頼性が高く安全性も検証されているコンポーネントを迅速に採用することができます。

## ステージ 5. 「ペイブド・ロード」コンセプトが OWASP トップ 10 で発見された問題を軽減していることをテストする

「ペイブド・ロード」コンポーネントは、OWASP トップ 10 の重要な問題に対処する必要があります。
例えば、脆弱なコンポーネントを自動的に検出または修正する方法や、インジェクションを検出するための静的コード分析 IDE プラグイン、さらにはインジェクションに対して安全であることが知られているライブラリなどがあります。
このような安全なそのまま置換え可能な代替品がチームに提供されればされるほど良いでしょう。
アプリケーションセキュリティチームの重要な任務は、これらのコンポーネントのセキュリティを継続的に評価し、改善することです。
改善されたら、そのコンポーネントの消費者との何らかのコミュニケーションチャネルで、アップグレードが必要であることを示す必要があります。
可能な限り自動的に、そうでない場合は少なくともダッシュボードなどで強調表示されるようにします。

## ステージ 6. 自社のプログラムを成熟したアプリケーションセキュリティプログラムにする

OWASP トップ 10 だけで終わらせてはいけません。それは、10 のリスクカテゴリーしかカバーしていないからです。
私たちは、組織が OWASP アプリケーションセキュリティ検証標準 (OWASP ASVS) を採用し、開発するアプリケーションのリスクレベルに応じて、「ペイブド・ロード」コンポーネントとレベル 1、2、3 のテストを段階的に追加していくことを強く推奨します。

## その先へ

優れたアプリケーションセキュリティプログラムは、最低限のことしかしません。
アプリケーションセキュリティの脆弱性を把握するためには、誰もが継続しなければなりません。

-   **コンセプトの完全性**
    成熟したアプリケーションセキュリティプログラムは、クラウド、エンタープライズ・セキュリティ・アーキテクチャ、脅威モデルなど、何らかのセキュリティ・アーキテクチャの概念を含んでいる必要があります。

-   **自動化とスケール**
    成熟したアプリケーションセキュリティプログラムでは、複雑な侵入テストの手順をエミュレートするスクリプト、開発チームが直接利用できる静的コード解析ツール、アプリケーションセキュリティユニットテストや統合テストの構築における開発チームの支援など、成果物を可能な限り自動化しようとしています。

-   **文化**
    成熟したアプリケーションセキュリティプログラムは、脇役ではなく開発チームの一員となることで、安全でない設計と、既存コードの技術的負債を解消しようとします。
    開発チームを "我々 "と "彼ら "として見ているアプリケーションセキュリティチームは、失敗する運命にあります。

-   **継続的改善**
    成熟したアプリケーションセキュリティプログラムは、常に向上を目指しています。
    機能していないものがあれば、それをやめます。何かが不便であったり、拡張性がなかったりする場合は、それを改善するために努力します。
    開発チームが使用していないもので、影響がない、または限定的なものであれば、何か違うことをします。
    1970年代にデスクチェックのようなテストを行っていたからといって、それが良いアイデアだとは限りません。測定し、評価し、そして構築または改善していきます。


# How to start an AppSec Program with the OWASP Top 10 

Previously, the OWASP Top 10 was never designed to be the basis for an
AppSec program. However, it's essential to start somewhere for many
organizations just starting out on their application security journey.
The OWASP Top 10 2021 is a good start as a baseline for checklists and
so on, but it's not in itself sufficient.

## Stage 1. Identify the gaps and goals of your appsec program

Many Application Security (AppSec) programs try to run before they can
crawl or walk. These efforts are doomed to failure. We strongly
encourage CISOs and AppSec leadership to use [OWASP Software Assurance
Maturity Model (SAMM)](https://owaspsamm.org) to identify weaknesses
and areas for improvement over a 1-3 year period. The first step is to
evaluate where you are now, identify the gaps in governance, design,
implementation, verification, and operations you need to resolve
immediately versus those that can wait, and prioritize implementing or
improving the fifteen OWASP SAMM security practices. OWASP SAMM can help
you build and measure improvements in your software assurance efforts.

## Stage 2. Plan for a paved road secure development lifecycle

Traditionally the preserve of so-called "unicorns," the paved road
concept is the easiest way to make the most impact and scale AppSec
resources with development team velocity, which only increases every
year.

The paved road concept is "the easiest way is also the most secure way"
and should involve a culture of deep partnerships between the
development team and the security team, preferably such that they are
one and the same team. The paved road aims to continuously improve,
measure, detect and replace insecure alternatives by having an
enterprise-wide library of drop-in secured replacements, with tooling to
help see where improvements can be made by adopting the paved road. This
allows existing development tools to report on insecure builds and help
development teams self-correct away from insecure alternatives.

The paved road might seem a lot to take in, but it should be built
incrementally over time. There are other forms of appsec programs out
there, notably the Microsoft Agile Secure Development Lifecycle. Not
every appsec program methodology suits every business.

## Stage 3. Implement the paved road with your development teams

Paved roads are built with the consent and direct involvement of the
relevant development and operations teams. The paved road should be
aligned strategically with the business and help deliver more secure
applications faster. Developing the paved road should be a holistic
exercise covering the entire enterprise or application ecosystem, not a
per-app band-aid, as in the old days.

## Stage 4. Migrate all upcoming and existing applications to the paved road

Add paved road detection tools as you develop them and provide
information to development teams to improve the security of their
applications by how they can directly adopt elements of the paved road.
Once an aspect of the paved road has been adopted, organizations should
implement continuous integration checks that inspect existing code and
check-ins that use prohibited alternatives and warn or reject the build
or check-in. This prevents insecure options from creeping into code over
time, preventing technical debt and a defective insecure application.
Such warnings should link to the secure alternative, so the development
team is given the correct answer immediately. They can refactor and
adopt the paved road component quickly.

## Stage 5. Test that the paved road has mitigated the issues found in the OWASP Top 10

Paved road components should address a significant issue with the OWASP
Top 10, for example, how to automatically detect or fix vulnerable
components, or a static code analysis IDE plugin to detect injections or
even better start using a library that is known safe against injection.
The more of these secure drop-in replacements provided to teams, the better.
A vital task of the appsec team is to ensure that the security of these
components is continuously evaluated and improved.
Once they are improved, some form of communication pathway with
consumers of the component should indicate that an upgrade should occur,
preferably automatically, but if not, as least highlighted on a
dashboard or similar.

## Stage 6. Build your program into a mature AppSec program

You must not stop at the OWASP Top 10. It only covers 10 risk
categories. We strongly encourage organizations to adopt the Application
Security Verification Standard and progressively add paved road
components and tests for Level 1, 2, and 3, depending on the developed
applications' risk level.

## Going beyond

All great AppSec programs go beyond the bare minimum. Everyone must keep
going if we're ever going to get on top of appsec vulnerabilities.

-   **Conceptual integrity**. Mature AppSec programs must contain some
    concept of security architecture, whether a formal cloud or
    enterprise security architecture or threat modeling

-   **Automation and scale**. Mature AppSec programs try to automate as
    much of their deliverables as possible, using scripts to emulate
    complex penetration testing steps, static code analysis tools
    directly available to the development teams, assisting dev teams in
    building appsec unit and integration tests, and more.

-   **Culture**. Mature AppSec programs try to build out the insecure
    design and eliminate the technical debt of existing code by being a
    part of the development team and not to the side. AppSec teams who
    see development teams as "us" and "them" are doomed to failure.

-   **Continuous improvement**. Mature AppSec programs look to
    constantly improve. If something is not working, stop doing it. If
    something is clunky or not scalable, work to improve it. If
    something is not being used by the development teams and has no or
    limited impact, do something different. Just because we've done
    testing like desk checks since the 1970s doesn't mean it's a good
    idea. Measure, evaluate, and then build or improve.
