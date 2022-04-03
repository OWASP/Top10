# OWASP Top 10 2021 介紹

欢迎來到最新版本的 OWASP Top 10！! OWASP Top 10 2021 是一个全新的名单，包含了你可以打印下來的新图示说明，若有需要的话，你可以从我们的网页上面下载。

在此我们想对所有贡献了他们时间和资料的人給予极大的感谢。没有你们，这一个新版本不会产生。**谢谢**。

## Top 10 for 2021 有什么新的变化？

这次在 OWASP Top 10 for 2021 有三个全新的分类，有四个分类有做名称和范围的修正，并有将一些类别做合并。

<img src="./assets/image1.png" style="width:6.5in;height:1.78889in" alt="Mapping of the relationship between the Top 10 2017 and the new Top 10 2021" />

**A01:2021-权限控制失效** 从第五名移上來; 94% 被测试的应用程式都有验证到某种类别权限控制失效的问题。在权限控制失效这个类别中被对应到的 34 个 CWEs 在验测资料中出现的次数都高于其他的弱点类别。

**A02:2021-加密机制失效** 提升一名到第二名，在之前为 _敏感资料外曝_，在此定义下比较类似于一个广泛的问题而非根本原因。在此重新定义并将问题核心定义在加密机制的失败，并因此造成敏感性资料外泄或是系統被破坏。

**A03:2021-注入式攻击** 下滑到第三名。94% 被测试的应用程式都有验测到某种类別注入式攻击的问题。在注入式攻击这个类別中被对应到的 33 个 CWEs 在验测资料中出现的次数为弱点问题的第二高。跨站脚本攻击现在在新版本属于这个类別。

**A04:2021-不安全设计** 这是 2021 年版本的新类別，并特別聚焦在设计相关的缺陷。如果我们真的希望让整个产业"向左移动"＊注一＊，那我们必须进一步的往威胁建模，安全设计模块的观念，和安全參考架构前进。

＊注一: Move Left 于英文原文中代表在软件开发及交付过程中，在早期找出及处理相关问题，同 Shift Left Testing。＊

**A05:2021-安全设定缺陷** 从上一版本的第六名移动上來。90% 被测试的应用程式都有验测到某种类別的安全设定缺陷。在更多的软件往更高度和有弹性的设定移动，我们并不意外这个类別的问题往上移动。在前版本中的 XML 外部实体注入攻击 （XML External Entities）现在属于这个类別。

**A06:2021-危险或过旧的组件** 在之前标题为 _使用有已知弱点的组件_。在本次版本中于业界问卷中排名第二，但也有足够的统计资料让它可以进入 Top 10。这个类別从 2017 版本的第九名爬升到第六，也是我们持续挣扎做测试和评估风险的类別。这也是唯一一个沒有任何 CVE 能被对应到 CWE 內的类別，所以预设的威胁及影响权重在这类別的分数上被预设为 5.0。

**A07:2021-认证及验证机制失效** 在之前标题为 _错误的认证机制_。在本次版本中由第二名下滑至此，并同时包含了将认证相关缺失的 CWE 包含在內。这个类別仍是 Top 10 不可缺少的一环，但同时也有发现现在标准化的架构有协助降低次风险发生机率。

**A08:2021-软件及资料完整性失效** 这是 2021 年版本全新的类別，并在软件更新，敏感及重要资料，和 CI/CD 管道中并沒有做完整性的确认为前提做假设并进行评估。在评估中影响权重最高分的 CVE/CVSS 资料都与这类別中的 10 个 CWE 对应到。2017 年版本中不安全的反序列化现在被合并至此类別。

**A09:2021-安全记录及监控失效** 在之前为*不完整的记录及监控*并纳入在业界问卷中在本次列名为第三名并从之前的第十名上移。这个类別将扩充去纳入更多相关的缺失，但这也是相当难去验证，并沒有相当多的 CVE/CVSS 资料可以佐证。但是在这个类別中的缺失会直接影响到整体安全的可视性，事件告警及取证。

**A10:2021-服务器端请求伪造** 这个类別是在业界问卷排名第一名，并在此版本內纳入。由资料显示此问题有较低被验测次数和范围，但有高于平均的威胁及影响权重比率。这个类別的出现也是因为业界专家重复申明这类別的问题相当重要，即使在本次资料中并沒有足够的资料去显示这个问题。

## 分析方法

本次 Top 10 的选择方式比以往更重视资料分析，但并不是完全以资料分析为主。我们从资料分析中挑选了八个风险类別，然后由业界问卷中挑选两个风险类別。我们从过往的分享资料中去了解，并有我们一个基本的理由。原因是所有的资安研究人员都不断的在找新的弱点并找出方法去验证弱点，但会需要时间才能将这些验测方法纳入到既有的工具和测试流程中。当我们能有效的大量测试这个弱点时，有可能已经过了多年的时间。为了要让两者之间有平衡，我们使用业界问卷请教在前线的资安研究专家们并了解他们觉得有哪些是他们觉得严重但尚未出现在测试资料中的漏洞及问题。

这是几个我们为了要让 OWASP Top 10 更加成熟的重要改变。

### 如何建构风险类別

有別于上一个版本，在这次的 OWASP Top 10 有一些风险类別的修改。我们在此以比较高的角度说明一下这次的类別修改。

在上一次的资料收集当中，我们将资料收集的重心放在预先定义好的约 30 个 CWEs 并纳入一个领域以求其他的发现。从这里我们看到绝大多数的组织都只会专注在这 30 个 CWEs 而不常加入其他他们可能发现的 CWEs。在这次的改版中，我们将所有的问题都以开放式的方法处理，并沒有限制在任何一个 CWEs。我们请教了从 2017 年开始所测试的网页应用程式数量，然后在这些程式中至少有一个 CWE 被发现的数量。这个格式让我们能够追踪每个 CWE 跟所有被验测及统计的应用程式的数量跟关系。我们也忽略了 CWE 出现的频率，虽然在某些状况下这也许是必须的，但这却隐藏了风险类別本身与应用程式数量整体的关系。所以一个应用程式有 4 个或是 4,000 个弱点并不是被计算在 Top 10 的基础。但同时我们也从原本的 30 多个 CWEs 增长到快 400 多个 CWEs 去进行分析。我们因此也计划未來做更多的资料分析，并在对此版本进行补充说明。而这些增加的 CWEs 也同时影响了这次风险类別的规划。

我们花了好几个月将 CWEs 进行分组跟分类，而且其实可以一直花更多时间去做这件事情。但我们必须在某一个时间点停住。在 CWEs 当中，同时有 _根本原因_ 以及 _症状_ 的问题，而像是 "加密机制失效" 和 "设定问题" 这类型的 _原因_ 与 "敏感资料外泄" 和 "阻断服务" 这类型的 _症状_ 是对立的。因此我们决定在可以的时候要更专注于底层的原因，因为这是可以有效指出问题的本体跟同时提供问题的解决大方向。专注在问题核心而不将重心放在症状并不是一个新的概念 ，Top Ten 有史以來一直是症状跟问题核心的綜合体，只是这次我们更刻意的将他突显出來。在这次的新版本中，每一个类別內的平均有 19.6 个 CWE，而最低的 _A10:2021-服务器端请求伪造_ 有一个 CWE 到 _A04:2021-不安全设计_ 有四十个 CWE。这个新的类別架构能提供企业更多的资安训练的好处，因为在新的架构下可以更专注在某个语系或平台上的 CWE。

### 选择类別时资料的使用方式

在 2017 年，我们用事件发生次数去判断可能发生的机率去选择类別，然后透过一群在业界拥有数十年经验的专家团对讨论并依照 _可发生性_，_可发现性（同可能性）_，和 _技术影响力_ 去做排名。在 2021 年，我们希望如果可以的话用资料证明可发生性和技术影响性。

我们下载了 OWASP Depndency Check 并取出了 CVSS 漏洞，并将相关的 CWE 用影响力分数分群。这花了一些时间和力气去研究因为所有的 CVEs 都有 CVSSv2 分数，但是在其中因为 CVSSv2 跟 CVSSv3 之间有一些缺失是必须被修正的。经过了一段时间后，所有的 CVEs 都会有对应的 CVSSv3 的分数。再者，分数的范围和计算的公式在 CVSSv2 和 CVSSv3 之间也做了更新。

在 CVSSv2 中，漏洞和影响力两者都可达到 10.0 分，但是公式本身会将两者调整为漏洞占 60%，然后影响力占 40%。在 CVSSv3 中，理论上的最高值将漏洞限制在 6.0 分而影响力在 4.0 分。当考率到权重比率时，影响力的分数会偏高，在 CVSSv3 中几乎平均会多出 1.5 分，而漏洞分数却会平均少 0.5 分。

从 OWASP Dependcy Check 翠取出的 NVD 资料当中有将近 12.5 万笔 CVE 资料有对应到 CWE，而有 241 笔独特的 CWEs 有对应到 CVE。6.2 万笔 CWE 有对应到 CVSSv3 分数，所以大约是整体资料中一半的部分。

而在 Top Ten，我们计算漏洞和影响力的平均分数的方式如下。我们将所有有 CVSS 分数的 CVE 依照 CWE 分组，然后依照有 CVSSv3 的漏洞和影响力在所有资料中的百分比作权重，在加上资料中有 CVSSv2 的资料去做平均。我们将这些平均后的 CWEs 对应到资料中，然后将他的漏洞和引想力分数使用在另一半的风险公式中。

## 为什么就不纯粹做统计分析？

这些资料的結果最主要是被限制在能使用自动工具测试出來的結果。可是当你跟一位有经验的应用程式安全专家聊的时候，他们会跟你说绝大多数他们找到的问题都不在这些资料里面。原因是一个测试要被自动化的时候，需要花时间去开发这些弱点测试的方法论，当你需要将这个测试自动化并能对大量的应用程式去验证时，又会花上更多的时间。当我们回头看去年或以前有可能沒出现的一些问题的趋势，我们发现其实都沒有在这些资料当中。

因此，由于资料不完全的关系，我们只有从资料中选出 8 个类別，而并不是 10 个。剩下的两个类別是从业界问卷中所选出的。这会允许在前线的參与者去选出他们认为的高风险，而不是纯粹依据资料去判断（甚至可能资料永远都不会有出现的踪跡）。

## 为什么用事故率而不是用发生次数

There are three primary sources of data. We identify them as
Human-assisted Tooling (HaT), Tool-assisted Human (TaH), and raw
Tooling.

Tooling and HaT are high-frequency finding generators. Tools will look
for specific vulnerabilities and tirelessly attempt to find every
instance of that vulnerability and will generate high finding counts for
some vulnerability types. Look at Cross-Site Scripting, which is
typically one of two flavors: it's either a more minor, isolated mistake
or a systemic issue. When it's a systemic issue, the finding counts can
be in the thousands for an application. This high frequency drowns out
most other vulnerabilities found in reports or data.

TaH, on the other hand, will find a broader range of vulnerability types
but at a much lower frequency due to time constraints. When humans test
an application and see something like Cross-Site Scripting, they will
typically find three or four instances and stop. They can determine a
systemic finding and write it up with a recommendation to fix on an
application-wide scale. There is no need (or time) to find every
instance.

Suppose we take these two distinct data sets and try to merge them on
frequency. In that case, the Tooling and HaT data will drown the more
accurate (but broad) TaH data and is a good part of why something like
Cross-Site Scripting has been so highly ranked in many lists when the
impact is generally low to moderate. It's because of the sheer volume of
findings. (Cross-Site Scripting is also reasonably easy to test for, so
there are many more tests for it as well).

In 2017, we introduced using incidence rate instead to take a fresh look
at the data and cleanly merge Tooling and HaT data with TaH data. The
incidence rate asks what percentage of the application population had at
least one instance of a vulnerability type. We don't care if it was
one-off or systemic. That's irrelevant for our purposes; we just need to
know how many applications had at least one instance, which helps
provide a clearer view of the testing is findings across multiple
testing types without drowning the data in high-frequency results.

## What is your data collection and analysis process?

We formalized the OWASP Top 10 data collection process at the Open
Security Summit in 2017. OWASP Top 10 leaders and the community spent
two days working out formalizing a transparent data collection process.
The 2021 edition is the second time we have used this methodology.

We publish a call for data through social media channels available to
us, both project and OWASP. On the [OWASP Project
page](https://owasp.org/www-project-top-ten/#div-data_2020), we list the
data elements and structure we are looking for and how to submit them.
In the [GitHub
project](https://github.com/OWASP/Top10/tree/master/2020/Data), we have
example files that serve as templates. We work with organizations as
needed to help figure out the structure and mapping to CWEs.

We get data from organizations that are testing vendors by trade, bug
bounty vendors, and organizations that contribute internal testing data.
Once we have the data, we load it together and run a fundamental
analysis of what CWEs map to risk categories. There is overlap between
some CWEs, and others are very closely related (ex. Cryptographic
vulnerabilities). Any decisions related to the raw data submitted are
documented and published to be open and transparent with how we
normalized the data.

We look at the eight categories with the highest incidence rates for
inclusion in the Top 10. We also look at the industry survey results to
see which ones may already be present in the data. The top two votes
that aren't already present in the data will be selected for the other
two places in the Top 10. Once all ten were selected, we applied
generalized factors for exploitability and impact; to help rank the Top
10 in order.

## Data Factors

There are data factors that are listed for each of the Top 10
Categories, here is what they mean:

- _CWEs Mapped_: The number of CWEs mapped to a category by the Top 10
  team.

- _Incidence Rate_: Incidence rate is the percentage of applications
  vulnerable to that CWE from the population tested by that org for
  that year.

- (Testing) _Coverage_: The percentage of applications tested by all
  organizations for a given CWE.

- _Weighted Exploit_: The Exploit sub-score from CVSSv2 and CVSSv3
  scores assigned to CVEs mapped to CWEs, normalized, and placed on a
  10pt scale.

- _Weighted Impact_: The Impact sub-score from CVSSv2 and CVSSv3
  scores assigned to CVEs mapped to CWEs, normalized, and placed on a
  10pt scale.

- _Total Occurrences_: Total number of applications found to have the
  CWEs mapped to a category.

- _Total CVEs_: Total number of CVEs in the NVD DB that were mapped to
  the CWEs mapped to a category.

## Category Relationships from 2017

There has been a lot of talk about the overlap between the Top Ten
risks. By the definition of each (list of CWEs included), there really
isn't any overlap. However, conceptually, there can be overlap or
interactions based on the higher-level naming. Venn diagrams are many
times used to show overlap like this.

<img src="./assets/image2.png" style="width:4.31736in;height:3.71339in" alt="Diagram Description automatically generated" />

The Venn diagram above represents the interactions between the Top Ten
2017 risk categories. While doing so, a couple of essential points
became obvious:

1.  One could argue that Cross-Site Scripting ultimately belongs within
    Injection as it's essentially Content Injection. Looking at the 2021
    data, it became even more evident that XSS needed to move into
    Injection.

2.  The overlap is only in one direction. We will often classify a
    vulnerability by the end manifestation or "symptom," not the
    (potentially deep) root cause. For instance, "Sensitive Data
    Exposure" may have been the result of a "Security Misconfiguration";
    however, you won't see it in the other direction. As a result,
    arrows are drawn in the interaction zones to indicate which
    direction it occurs.

3.  Sometimes these diagrams are drawn with everything in _A06:2021
    Using Components with Known Vulnerabilities_. While some of these
    risk categories may be the root cause of third-party
    vulnerabilities, they are generally managed differently and with
    different responsibilities. The other types are typically
    representing first-party risks.

# Thank you to our data contributors

The following organizations (along with some anonymous donors) kindly
donated data for over 500,000 applications to make this the largest and
most comprehensive application security data set. Without you, this
would not be possible.

|                   |                  |               |                |
| :---------------: | :--------------: | :-----------: | :------------: |
|    AppSec Labs    |      GitLab      |  Micro Focus  |     Sqreen     |
|     Cobalt.io     |    HackerOne     | PenTest-Tools |    Veracode    |
| Contrast Security | HCL Technologies |    Probely    | WhiteHat (NTT) |

## Thank you to our sponsors

The OWASP Top 10 2021 team gratefully acknowledge the financial support of Secure Code Warrior and Just Eat.

[![Secure Code Warrior](assets/securecodewarrior.png){ width="256" }](https://securecodewarrior.com)

[![Just Eats](assets/JustEat.png){ width="256" }](https://www.just-eat.co.uk/)
