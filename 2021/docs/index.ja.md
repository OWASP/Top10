# 導入

## OWASP Top 10 - 2021 へようこそ

![OWASP Top 10 ロゴ](./assets/TOP_10_logo_Final_Logo_Colour.png){:class="img-responsive"}

OWASP トップ 10 の最新版へようこそ! OWASP トップ 10 2021年版は、グラフィックデザインが一新され、1ページのインフォグラフィックになっています。インフォグラフィックは、ホームページから入手でき、印刷することができます。

今回のトップ10の作成にあたって、貴重な時間やデータを提供してくださったすべての皆さんに感謝します。皆様のご協力なくしては、OWASP トップ 10 2021年版は存在し得ません。**本当に、感謝いたします**。

## 2021年版トップ10の変更点

2021年版トップ10では、3つの新しいカテゴリー、4つのカテゴリーの名称とスコープの変更がありました。統合されたものもいくつかあります。

![マッピング](assets/mapping.png)

- **[A01:2021-アクセス制御の不備](A01_2021-Broken_Access_Control.ja.md)**は、5位から最も深刻なWebアプリケーションのセキュリティリスクへと順位を上げました。the contributed data indicates that on average, 3.81% of applications tested had one or more Common Weakness Enumerations (CWEs) with more than 318k occurrences of CWEs in this risk category. また、「アクセス制御の欠陥」にあたる34件のCWEは、他のカテゴリーよりもアプリケーションで多く発生しています。
- **[A02:2021-暗号化の失敗](A02_2021-Cryptographic_Failures.ja.md)**は、ひとつ順位を上げて2位になっています。以前は、**A3:2017-機微な情報の露出** と呼ばれていましたが、これは根本的な原因というより幅広くみられる症状と言えます。ここでは、機密データの漏えいやシステム侵害に多く関連する、暗号技術にまつわる失敗に焦点を当てています。
- **[A03:2021-インジェクション](A03_2021-Injection.ja.md)**は、3位に下がっています。94%のアプリケーションで何らかのインジェクションに関する問題が確認されています。最大発生率は19%、平均発生率は3.37%であり、このカテゴリにあたる33のCWEは、アプリケーションでの発生数が2番目に多く見られます。発生数は27万4千件でした。今回から、クロスサイトスクリプティングは、このカテゴリに含まれています。
- **[A04:2021-安全が確認されない不安な設計](A04_2021-Insecure_Design.ja.md)**は、2021年に新設されたカテゴリーで、設計上の欠陥に関するリスクに焦点を当てています。一業界として、我々が純粋に「シフトレフト」することを望むのであれば、脅威モデリングや、安全な設計パターンと原則、また、リファレンス・アーキテクチャをもっと利用していくことが必要です。 An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks.
- **[A05:2021-セキュリティの設定ミス](A05_2021-Security_Misconfiguration.ja.md)**は、前回の6位から順位を上げました。アプリケーションの90％には何らかの設定ミスが見られます。90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.5%, and over 208k occurrences of CWEs mapped to this risk category. 高度な設定が可能なソフトウェアへの移行が進む中で、このカテゴリーの順位が上がったことは当然と言えます。以前の、**A4:2017-XML 外部エンティティ参照 (XXE)**のカテゴリーは、このカテゴリーに含まれています。
- **[A06:2021-脆弱で古くなったコンポーネント](A06_2021-Vulnerable_and_Outdated_Components.ja.md)** は、以前は「既知の脆弱性のあるコンポーネントの使用」というタイトルでした。この問題は、Top 10コミュニティの調査では2位であり、データ分析によってトップ10に入るだけのデータもありました。このカテゴリーは2017年の9位から順位を上げました。これは、テストやリスク評価に苦労する、よく知られた問題です。また、含まれるCWEにあたる共通脆弱性識別子 (CVE)のない、唯一のカテゴリであるため、デフォルトのエクスプロイトとインパクトの重みは5.0としてスコアに反映されています。
- **[A07:2021-識別と認証の失敗](A07_2021-Identification_and_Authentication_Failures.ja.md)**は以前、「認証の不備」と呼ばれていましたが、この版では第2位から順位を落とし、識別の失敗に関連するCWEをより多く含む意味合いのカテゴリとなっています。このカテゴリーは依然としてトップ10に示すべき重要な項目ですが、標準化されたフレームワークの利用が進んだことが功を奏しているようです。
- **[A08:2021-ソフトウェアとデータの整合性の不具合](A08_2021-Software_and_Data_Integrity_Failures.ja.md)**は、2021年に新設されたカテゴリーで、ソフトウェアの更新、重要なデータを、CI/CDパイプラインにおいて整合性を検証せずに見込みで進めることによる問題にフォーカスしています。共通脆弱性識別子/共通脆弱性評価システム (CVE/CVSS) のデータから最も重大な影響を受けたものの1つが、このカテゴリーの10のCWEにマッピングされています。**A8:2017-安全でないデシリアライゼーション**は、このカテゴリーの一部となりました。
- **[A09:2021-セキュリティログとモニタリングの失敗](A09_2021-Security_Logging_and_Monitoring_Failures.ja.md)**は、従来は**A10:2017-不十分なロギングとモニタリング**でしたが、Top 10コミュニティの調査（第3位）から追加され、従来の第10位からランクアップしました。このカテゴリは、より多くの種類の失敗を含むように拡張されています。これは、テストが困難なものであり、かつ、CVE/CVSSのデータにはあまり反映されないものです。とはいえ、このカテゴリーで失敗が起きると、可視性、インシデントアラート、フォレンジックなどに直接影響を与える可能性があります。
- **[A10:2021-サーバーサイドリクエストフォージェリ](A10_2021-Server-Side_Request_Forgery_(SSRF).ja.md)** は、Top 10コミュニティの調査（第1位）から追加されたものです。調査データからわかることは、よくあるテストより広範な範囲において、問題の発生率は比較的低いものの、問題が起きた場合のエクスプロイトとインパクトは平均以上のものとなり得ます。このカテゴリは、現時点でデータとして現れるものではありませんでしたが、複数の業界の専門家により重要との示唆を得たシナリオとして反映しています。

## 方法論

今回のトップ10は、これまで以上にデータを重視していますが、やみくもにデータを重視しているわけではありません。10項目のうち8項目は提供されたデータから、2項目はTop 10コミュニティの調査から高いレベルで選びました。こうすることにはひとつの根本的な理由があります。提供されたデータを見ることは、過去を見ることを意味している、ということです。アプリケーションセキュリティのリサーチャーが新しい脆弱性や、それをテストする新しい方法を見つけるのには時間がかかります。これらのテストをツールやプロセスに組み込むには時間がかかります。こうした弱点を広く確実にテストできるようになるまでには、何年もかかってしまうことでしょう。そこで、データではわからないような本質的な弱点は何かということについては、業界の第一線で活躍されている方々にお聞きすることでバランスをとる、というわけです。

トップ10を継続的に成熟させるために私たちが採用した、重要な変更点がいくつかあります。

## How the categories are structured

A few categories have changed from the previous installment of the OWASP Top Ten. Here is a high-level summary of the category changes.

Previous data collection efforts were focused on a prescribed subset of approximately 30 CWEs with a field asking for additional findings. We learned that organizations would primarily focus on just those 30 CWEs and rarely add additional CWEs that they saw. In this iteration, we opened it up and just asked for data, with no restriction on CWEs. We asked for the number of applications tested for a given year (starting in 2017), and the number of applications with at least one instance of a CWE found in testing. This format allows us to track how prevalent each CWE is within the population of applications. We ignore frequency for our purposes; while it may be necessary for other situations, it only hides the actual prevalence in the application population. Whether an application has four instances of a CWE or 4,000 instances is not part of the calculation for the Top 10. We went from approximately 30 CWEs to almost 400 CWEs to analyze in the dataset. We plan to do additional data analysis as a supplement in the future. This significant increase in the number of CWEs necessitates changes to how the categories are structured.

We spent several months grouping and categorizing CWEs and could have continued for additional months. We had to stop at some point. There are both *root cause* and *symptom* types of CWEs, where *root cause* types are like "Cryptographic Failure" and "Misconfiguration" contrasted to *symptom* types like "Sensitive Data Exposure" and "Denial of Service." We decided to focus on the *root cause* whenever possible as it's more logical for providing identification and remediation guidance. Focusing on the *root cause* over the *symptom* isn't a new concept; the Top Ten has been a mix of *symptom* and *root cause*. CWEs are also a mix of *symptom* and *root cause*; we are simply being more deliberate about it and calling it out. There is an average of 19.6 CWEs per category in this installment, with the lower bounds at 1 CWE for **A10:2021-Server-Side Request Forgery (SSRF)** to 40 CWEs in **A04:2021-Insecure Design**. This updated category structure offers additional training benefits as companies can focus on CWEs that make sense for a language/framework.

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

# Introduction

## Welcome to the OWASP Top 10 - 2021

![OWASP Top 10 Logo](./assets/TOP_10_logo_Final_Logo_Colour.png){:class="img-responsive"}

Welcome to the latest installment of the OWASP Top 10! The OWASP Top 10 2021 is all-new, with a new graphic design and an available one-page infographic you can print or obtain from our home page.

A huge thank you to everyone that contributed their time and data for this iteration. Without you, this installment would not happen. **THANK YOU!**

## What's changed in the Top 10 for 2021

There are three new categories, four categories with naming and scoping changes, and some consolidation in the Top 10 for 2021. We've changed names when necessary to focus on the root cause over the symptom.

![Mapping](assets/mapping.png)

- **[A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)** moves up from the fifth position to the category with the most serious web application security risk; the contributed data indicates that on average, 3.81% of applications tested had one or more Common Weakness Enumerations (CWEs) with more than 318k occurrences of CWEs in this risk category. The 34 CWEs mapped to Broken Access Control had more occurrences in applications than any other category.
- **[A02:2021-Cryptographic Failures](A02_2021-Cryptographic_Failures.md)** shifts up one position to #2, previously known as **A3:2017-Sensitive Data Exposure**, which was broad symptom rather than a root cause. The renewed name focuses on failures related to cryptography as it has been implicitly before. This category often leads to sensitive data exposure or system compromise.
- **[A03:2021-Injection](A03_2021-Injection.md)** slides down to the third position. 94% of the applications were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3.37%, and the 33 CWEs mapped into this category have the second most occurrences in applications with 274k occurrences. Cross-site Scripting is now part of this category in this edition.
- **[A04:2021-Insecure Design](A04_2021-Insecure_Design.md)** is a new category for 2021, with a focus on risks related to design flaws. If we genuinely want to "move left" as an industry, we need more threat modeling, secure design patterns and principles, and reference architectures. An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks.
- **[A05:2021-Security Misconfiguration](A05_2021-Security_Misconfiguration.md)** moves up from #6 in the previous edition; 90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.5%, and over 208k occurrences of CWEs mapped to this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up. The former category for **A4:2017-XML External Entities (XXE)** is now part of this risk category.
- **[A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)** was previously titled Using Components with Known Vulnerabilities and is #2 in the Top 10 community survey, but also had enough data to make the Top 10 via data analysis. This category moves up from #9 in 2017 and is a known issue that we struggle to test and assess risk. It is the only category not to have any Common Vulnerability and Exposures (CVEs) mapped to the included CWEs, so a default exploit and impact weights of 5.0 are factored into their scores.
- **[A07:2021-Identification and Authentication Failures](A07_2021-Identification_and_Authentication_Failures.md)** was previously Broken Authentication and is sliding down from the second position, and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10, but the increased availability of standardized frameworks seems to be helping.
- **[A08:2021-Software and Data Integrity Failures](A08_2021-Software_and_Data_Integrity_Failures.md)** is a new category for 2021, focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data mapped to the 10 CWEs in this category. **A8:2017-Insecure Deserialization** is now a part of this larger category.
- **[A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)** was previously **A10:2017-Insufficient Logging & Monitoring** and is added from the Top 10 community survey (#3), moving up from #10 previously. This category is expanded to include more types of failures, is challenging to test for, and isn't well represented in the CVE/CVSS data. However, failures in this category can directly impact visibility, incident alerting, and forensics.
- **[A10:2021-Server-Side Request Forgery](A10_2021-Server-Side_Request_Forgery_(SSRF).md)** is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it's not illustrated in the data at this time.

## Methodology

This installment of the Top 10 is more data-driven than ever but not blindly data-driven. We selected eight of the ten categories from contributed data and two categories from the Top 10 community survey at a high level. We do this for a fundamental reason, looking at the contributed data is looking into the past. AppSec researchers take time to find new vulnerabilities and new ways to test for them. It takes time to integrate these tests into tools and processes. By the time we can reliably test a weakness at scale, years have likely passed. To balance that view, we use an community survey to ask application security and development experts on the front lines what they see as essential weaknesses that the data may not show yet.

There are a few critical changes that we adopted to continue to mature the Top 10.

## How the categories are structured

A few categories have changed from the previous installment of the OWASP Top Ten. Here is a high-level summary of the category changes.

Previous data collection efforts were focused on a prescribed subset of approximately 30 CWEs with a field asking for additional findings. We learned that organizations would primarily focus on just those 30 CWEs and rarely add additional CWEs that they saw. In this iteration, we opened it up and just asked for data, with no restriction on CWEs. We asked for the number of applications tested for a given year (starting in 2017), and the number of applications with at least one instance of a CWE found in testing. This format allows us to track how prevalent each CWE is within the population of applications. We ignore frequency for our purposes; while it may be necessary for other situations, it only hides the actual prevalence in the application population. Whether an application has four instances of a CWE or 4,000 instances is not part of the calculation for the Top 10. We went from approximately 30 CWEs to almost 400 CWEs to analyze in the dataset. We plan to do additional data analysis as a supplement in the future. This significant increase in the number of CWEs necessitates changes to how the categories are structured.

We spent several months grouping and categorizing CWEs and could have continued for additional months. We had to stop at some point. There are both *root cause* and *symptom* types of CWEs, where *root cause* types are like "Cryptographic Failure" and "Misconfiguration" contrasted to *symptom* types like "Sensitive Data Exposure" and "Denial of Service." We decided to focus on the *root cause* whenever possible as it's more logical for providing identification and remediation guidance. Focusing on the *root cause* over the *symptom* isn't a new concept; the Top Ten has been a mix of *symptom* and *root cause*. CWEs are also a mix of *symptom* and *root cause*; we are simply being more deliberate about it and calling it out. There is an average of 19.6 CWEs per category in this installment, with the lower bounds at 1 CWE for **A10:2021-Server-Side Request Forgery (SSRF)** to 40 CWEs in **A04:2021-Insecure Design**. This updated category structure offers additional training benefits as companies can focus on CWEs that make sense for a language/framework.

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

The following organizations (along with some anonymous donors) kindly donated data for over 500,000 applications to make this the largest and most comprehensive application security data set. Without you, this would not be possible.

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

The OWASP Top 10 2021 team gratefully acknowledge the financial support of Secure Code Warrior.

[![Secure Code Warrior](assets/securecodewarrior.png)](https://securecodewarrior.com)
