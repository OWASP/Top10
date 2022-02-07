# 導入

## OWASP Top 10 - 2021 へようこそ

![OWASP Top 10 ロゴ](./assets/TOP_10_logo_Final_Logo_Colour.png){:class="img-responsive"}

OWASP トップ 10 の最新版へようこそ! OWASP トップ 10 2021年版は、グラフィックデザインが一新され、1ページのインフォグラフィックになっています。インフォグラフィックは、ホームページから入手でき、印刷することができます。

今回のトップ10の作成にあたって、貴重な時間やデータを提供してくださったすべての皆さんに感謝します。皆様のご協力なくしては、OWASP トップ 10 2021年版は存在し得ません。**本当に、感謝いたします**。

## 2021年版トップ10の変更点

2021年版トップ10では、3つの新しいカテゴリー、4つのカテゴリーの名称とスコープの変更がありました。統合されたものもいくつかあります。

![マッピング](assets/mapping.png)

- **[A01:2021-アクセス制御の不備](A01_2021-Broken_Access_Control.ja.md)** は、5位から最も深刻なWebアプリケーションのセキュリティリスクへと順位を上げました。the contributed data indicates that on average, 3.81% of applications tested had one or more Common Weakness Enumerations (CWEs) with more than 318k occurrences of CWEs in this risk category. また、「アクセス制御の欠陥」にあたる34件のCWEは、他のカテゴリーよりもアプリケーションで多く発生しています。
- **[A02:2021-暗号化の失敗](A02_2021-Cryptographic_Failures.ja.md)** は、ひとつ順位を上げて2位になっています。以前は、**A3:2017-機微な情報の露出** と呼ばれていましたが、これは根本的な原因というより幅広くみられる症状と言えます。ここでは、機密データの漏えいやシステム侵害に多く関連する、暗号技術にまつわる失敗に焦点を当てています。
- **[A03:2021-インジェクション](A03_2021-Injection.ja.md)** は、3位に下がっています。94%のアプリケーションで何らかのインジェクションに関する問題が確認されています。最大発生率は19%、平均発生率は3.37%であり、このカテゴリにあたる33のCWEは、アプリケーションでの発生数が2番目に多く見られます。発生数は27万4千件でした。今回から、クロスサイトスクリプティングは、このカテゴリに含まれています。
- **[A04:2021-安全が確認されない不安な設計](A04_2021-Insecure_Design.ja.md)** は、2021年に新設されたカテゴリーで、設計上の欠陥に関するリスクに焦点を当てています。一業界として、我々が純粋に「シフトレフト」することを望むのであれば、脅威モデリングや、安全な設計パターンと原則、また、リファレンス・アーキテクチャをもっと利用していくことが必要です。 An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks.
- **[A05:2021-セキュリティの設定ミス](A05_2021-Security_Misconfiguration.ja.md)** は、前回の6位から順位を上げました。アプリケーションの90％には何らかの設定ミスが見られます。90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.5%, and over 208k occurrences of CWEs mapped to this risk category. 高度な設定が可能なソフトウェアへの移行が進む中で、このカテゴリーの順位が上がったことは当然と言えます。以前の、**A4:2017-XML 外部エンティティ参照 (XXE)**のカテゴリーは、このカテゴリーに含まれています。
- **[A06:2021-脆弱で古くなったコンポーネント](A06_2021-Vulnerable_and_Outdated_Components.ja.md)** は、以前は「既知の脆弱性のあるコンポーネントの使用」というタイトルでした。この問題は、Top 10コミュニティの調査では2位であり、データ分析によってトップ10に入るだけのデータもありました。このカテゴリーは2017年の9位から順位を上げました。これは、テストやリスク評価に苦労する、よく知られた問題です。また、含まれるCWEにあたる共通脆弱性識別子 (CVE)のない、唯一のカテゴリであるため、デフォルトのエクスプロイトとインパクトの重みは5.0としてスコアに反映されています。
- **[A07:2021-識別と認証の失敗](A07_2021-Identification_and_Authentication_Failures.ja.md)** は以前、「認証の不備」と呼ばれていましたが、この版では第2位から順位を落とし、識別の失敗に関連するCWEをより多く含む意味合いのカテゴリとなっています。このカテゴリーは依然としてトップ10に示すべき重要な項目ですが、標準化されたフレームワークの利用が進んだことが功を奏しているようです。
- **[A08:2021-ソフトウェアとデータの整合性の不具合](A08_2021-Software_and_Data_Integrity_Failures.ja.md)** は、2021年に新設されたカテゴリーで、ソフトウェアの更新、重要なデータを、CI/CDパイプラインにおいて整合性を検証せずに見込みで進めることによる問題にフォーカスしています。共通脆弱性識別子/共通脆弱性評価システム (CVE/CVSS) のデータから最も重大な影響を受けたものの1つが、このカテゴリーの10のCWEにマッピングされています。**A8:2017-安全でないデシリアライゼーション** は、このカテゴリーの一部となりました。
- **[A09:2021-セキュリティログとモニタリングの失敗](A09_2021-Security_Logging_and_Monitoring_Failures.ja.md)** は、従来は**A10:2017-不十分なロギングとモニタリング**でしたが、Top 10コミュニティの調査（第3位）から追加され、従来の第10位からランクアップしました。このカテゴリは、より多くの種類の失敗を含むように拡張されています。これは、テストが困難なものであり、かつ、CVE/CVSSのデータにはあまり反映されないものです。とはいえ、このカテゴリーで失敗が起きると、可視性、インシデントアラート、フォレンジックなどに直接影響を与える可能性があります。
- **[A10:2021-サーバーサイドリクエストフォージェリ(SSRF)](A10_2021-Server-Side_Request_Forgery_(SSRF).ja.md)** は、Top 10コミュニティの調査（第1位）から追加されたものです。調査データからわかることは、よくあるテストより広範な範囲において、問題の発生率は比較的低いものの、問題が起きた場合のエクスプロイトとインパクトは平均以上のものとなり得ます。このカテゴリは、現時点でデータとして現れるものではありませんでしたが、複数の業界の専門家により重要との示唆を得たシナリオとして反映しています。

## 方法論

今回のトップ10は、これまで以上にデータを重視していますが、やみくもにデータを重視しているわけではありません。10項目のうち8項目は提供されたデータから、2項目はTop 10コミュニティの調査から高いレベルで選びました。こうすることにはひとつの根本的な理由があります。提供されたデータを見ることは、過去を見ることを意味している、ということです。アプリケーションセキュリティのリサーチャーが新しい脆弱性や、それをテストする新しい方法を見つけるのには時間がかかります。これらのテストをツールやプロセスに組み込むには時間がかかります。こうした弱点を広く確実にテストできるようになるまでには、何年もかかってしまうことでしょう。そこで、データではわからないような本質的な弱点は何かということについては、業界の第一線で活躍されている方々にお聞きすることでバランスをとる、というわけです。

トップ10を継続的に成熟させるために私たちが採用した、重要な変更点がいくつかあります。

## カテゴリの構成について

前回のOWASP Top 10からいくつかのカテゴリーが変更されています。以下に今回のカテゴリーの変更点を大まかにまとめます。

前回のデータ収集活動は、約30個のCWEからなる規定のサブセットに焦点を当て、追加として現場での調査結果を求めていました。この方法では、現場の組織は、主にこのリクエストした30のCWEだけに焦点を当てて報告をくれることになり、実際に観察したCWEを追加してくれることはまれだということがわかりました。そこで今回は、リクエストするCWEに制限を設けずに、データを提供してもらうことにしました。ある年に（今回は2017年以降）テストしたアプリケーションの数と、テストでCWE登録されている例が1つ以上見つかったアプリケーションの数を出してくれるよう依頼しました。これにより、アプリケーション全体を母集団としてとった上で、それぞれのCWEがどの程度蔓延しているかを把握することができます。

目的を踏まえて、当該CWEの発見頻度については無視しました。頻度は他の状況では必要性があるかもしれませんが、アプリケーションの母集団においては、現実の蔓延率を隠すことになってしまいます。例えば、あるアプリケーションに、ある特定のCWEの脆弱性が4例見つかることもあれば、4,000例見つかることもあるかもしれませんが、その発生頻度はトップ10の計算に影響させないというわけです。こうして、データセットで分析できたCWEは約30個から約400個になりました。今後、私たちは追加のデータ解析を行い、Top 10に補足する計画です。このようにCWEの数が大幅に増えたことで、カテゴリーの構成方法を変更する必要があります。

CWEのグループ化と分類に数ヶ月を費やしました。さらに数ヶ月続けることもできたかもしれませんが、どこかの時点で止めなければなりません。CWEには「根本原因」と「症状」があり、「根本原因」には「暗号の欠陥」や「設定ミス」などがあり、「症状」には「機密データの漏えい」や「サービス妨害」などがあります。そこで私たちは、可能な限り根本的な原因に焦点を当てることにしました。識別と修復のためのガイダンスを提供するのに適しているからです。「症状」ではなく「根本原因」に焦点を当てることは、今に始まったコンセプトではありません。どの版のTop 10も、症状と原因が混在してきました。CWEもまた、「症状」と「根本原因」が混在しています。私たちはそのことをより慎重に考え、呼びかけています。今回のカテゴリごとに含まれるCWE数は平均19.6件で、最少で **A10:2021-サーバーサイドリクエストフォージェリ(SSRF)** の1件、そして最多のものは **A04:2021-安全が確認されない不安な設計** の40件となっています。このカテゴリー構造の変更はトレーニングにさらなる効果をもたらします。たとえば企業は、利用している言語やフレームワークにとって意味のあるCWEに集中して教えることができるでしょう。

## How the data is used for selecting categories

In 2017, we selected categories by incidence rate to determine likelihood, then ranked them by team discussion based on decades of experience for *Exploitability*, *Detectability* (also *likelihood*), and *Technical Impact*. For 2021, we want to use data for *Exploitability* and *(Technical) Impact* if possible.

We downloaded OWASP Dependency Check and extracted the CVSS Exploit, and Impact scores grouped by related CWEs. It took a fair bit of research and effort as all the CVEs have CVSSv2 scores, but there are flaws in CVSSv2 that CVSSv3 should address. After a certain point in time, all CVEs are assigned a CVSSv3 score as well. Additionally, the scoring ranges and formulas were updated between CVSSv2 and CVSSv3.

In CVSSv2, both *Exploit* and *(Technical) Impact* could be up to 10.0, but the formula would knock them down to 60% for *Exploit* and 40% for *Impact*. In CVSSv3, the theoretical max was limited to 6.0 for *Exploit* and 4.0 for *Impact*. With the weighting considered, the Impact scoring shifted higher, almost a point and a half on average in CVSSv3, and exploitability moved nearly half a point lower on average.

There are 125k records of a CVE mapped to a CWE in the National Vulnerability Database (NVD) data extracted from OWASP Dependency Check, and there are 241 unique CWEs mapped to a CVE. 62k CWE maps have a CVSSv3 score, which is approximately half of the population in the data set.

For the Top Ten 2021, we calculated average *exploit* and *impact* scores in the following manner. We grouped all the CVEs with CVSS scores by CWE and weighted both *exploit* and *impact* scored by the percentage of the population that had CVSSv3 + the remaining population of CVSSv2 scores to get an overall average. We mapped these averages to the CWEs in the dataset to use as *Exploit* and *(Technical) Impact* scoring for the other half of the risk equation.

## Why not just pure statistical data?

The results in the data are primarily limited to what we can test for in an automated fashion. Talk to a seasoned AppSec professional, and they will tell you about stuff they find and trends they see that aren't yet in the data. It takes time for people to develop testing methodologies for certain vulnerability types and then more time for those tests to be automated and run against a large population of applications. Everything we find is looking back in the past and might be missing trends from the last year, which are not present in the data.

Therefore, we only pick eight of ten categories from the data because it's incomplete. The other two categories are from the Top 10 community survey. It allows the practitioners on the front lines to vote for what they see as the highest risks that might not be in the data (and may never be expressed in data).

## Why incidence rate instead of frequency?

There are three primary sources of data. We identify them as Human-assisted Tooling (HaT), Tool-assisted Human (TaH), and raw Tooling.

Tooling and HaT are high-frequency finding generators. Tools will look for specific vulnerabilities and tirelessly attempt to find every instance of that vulnerability and will generate high finding counts for some vulnerability types. Look at Cross-Site Scripting, which is typically one of two flavors: it's either a more minor, isolated mistake or a systemic issue. When it's a systemic issue, the finding counts can be in the thousands for a single application. This high frequency drowns out most other vulnerabilities found in reports or data.

TaH, on the other hand, will find a broader range of vulnerability types but at a much lower frequency due to time constraints. When humans test an application and see something like Cross-Site Scripting, they will typically find three or four instances and stop. They can determine a systemic finding and write it up with a recommendation to fix on an application-wide scale. There is no need (or time) to find every instance.

Suppose we take these two distinct data sets and try to merge them on frequency. In that case, the Tooling and HaT data will drown the more accurate (but broad) TaH data and is a good part of why something like Cross-Site Scripting has been so highly ranked in many lists when the impact is generally low to moderate. It's because of the sheer volume of findings. (Cross-Site Scripting is also reasonably easy to test for, so there are many more tests for it as well).

In 2017, we introduced using incidence rate instead to take a fresh look at the data and cleanly merge Tooling and HaT data with TaH data. The incidence rate asks what percentage of the application population had at least one instance of a vulnerability type. We don't care if it was one-off or systemic. That's irrelevant for our purposes; we just need to know how many applications had at least one instance, which helps provide a clearer view of the testing is findings across multiple testing types without drowning the data in high-frequency results. This corresponds to a risk related view as an attacker needs only one instance to attack an application successfully via the category.

## What is your data collection and analysis process?

We formalized the OWASP Top 10 data collection process at the Open Security Summit in 2017. OWASP Top 10 leaders and the community spent two days working out formalizing a transparent data collection process. The 2021 edition is the second time we have used this methodology.

We publish a call for data through social media channels available to us, both project and OWASP. On the OWASP Project page, we list the data elements and structure we are looking for and how to submit them. In the GitHub project, we have example files that serve as templates. We work with organizations as needed to help figure out the structure and mapping to CWEs.

We get data from organizations that are testing vendors by trade, bug bounty vendors, and organizations that contribute internal testing data. Once we have the data, we load it together and run a fundamental analysis of what CWEs map to risk categories. There is overlap between some CWEs, and others are very closely related (ex. Cryptographic vulnerabilities). Any decisions related to the raw data submitted are documented and published to be open and transparent with how we normalized the data.

We look at the eight categories with the highest incidence rates for inclusion in the Top 10. We also look at the Top 10 community survey results to see which ones may already be present in the data. The top two votes that aren't already present in the data will be selected for the other two places in the Top 10. Once all ten were selected, we applied generalized factors for exploitability and impact; to help rank the Top 10 2021 in a risk based order.

## Data Factors

There are data factors that are listed for each of the Top 10 Categories, here is what they mean:

- CWEs Mapped: The number of CWEs mapped to a category by the Top 10 team.
- Incidence Rate: Incidence rate is the percentage of applications vulnerable to that CWE from the population tested by that org for that year.
- (Testing) Coverage: The percentage of applications tested by all organizations for a given CWE.
- Weighted Exploit: The Exploit sub-score from CVSSv2 and CVSSv3 scores assigned to CVEs mapped to CWEs, normalized, and placed on a 10pt scale.
- Weighted Impact: The Impact sub-score from CVSSv2 and CVSSv3 scores assigned to CVEs mapped to CWEs, normalized, and placed on a 10pt scale.
- Total Occurrences: Total number of applications found to have the CWEs mapped to a category.
- Total CVEs: Total number of CVEs in the NVD DB that were mapped to the CWEs mapped to a category.

## Thank you to our data contributors

この最も大規模で包括的なアプリケーションセキュリティのデータセットを作り上げるために、（何名かの匿名の提供者とともに）以下の組織には 50,000 を超えるアプリケーションに関するデータを提供いただきました。 これは皆様のご協力なくしては成し得ませんでした。

- AppSec Labs
- Cobalt.io
- Contrast Security
- GitLab
- HackerOne
- HCL Technologies
- Micro Focus
- PenTest-Tools
- Probely
- Sqreen
- Veracode
- WhiteHat (NTT)

## Thank you to our sponsor

OWASP Top 10 2021 チームは、資金面での援助をいただいた Secure Code Warrior に心より感謝いたします。

[![Secure Code Warrior](assets/securecodewarrior.png)](https://securecodewarrior.com)
