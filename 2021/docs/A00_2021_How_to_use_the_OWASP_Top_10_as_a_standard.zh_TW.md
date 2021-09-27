# 如何將 OWASP Top 10 2021 做為標準使用

OWASP Top 10 最主要是一個提升意識及資安認知形態的文件。但是，從 2003 年開始，這並沒有讓任何的企業或組織停止使用它當作預設的應用安全標準。如果你想要用使用 OWASP Top 10 當作程式設計或是驗證測試的一個標準，要先知道這只是一個最低限度的指標並且也只是一個開始。

使用 OWASP Top 10 作為標準的困難之一是我們記錄了應用安全風險，而不一定是容易測試的問題。例如，A04:2021-Insecure Design 超出了大多數能夠測被試及被驗證的範圍。 另一個例子是要測試有效的就地、被使用中的測試記錄和監控機制只能透過面談和要求抽樣有效的資安事件鑑識案例。 一個靜態原始碼分析工具可以找出日誌記錄的缺失，但可能無法確定業務邏輯或存取控制是否在日誌記錄中記錄了有關重要安全漏洞的日誌。 滲透測試人員可能只能確定他們在測試環境中測試時有確實的執行了資安事件鑑識，在實際的實體環境中卻有可能沒有做到相同的標準。

以下是我們建議在什麼時候可以使用 OWASP Top 10:

| 使用案例               | OWASP Top 10 2021 | OWASP 應用安全驗證標準 (ASVS) |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| 認知性               | 是               |                                                  |
| 教育訓練                | 基礎       | 完整                                    |
| 設計及架構 | 偶爾      | 可以                                              |
| 程式標準         | 最低限度      | 可以                                              |
| 安全程式驗證      | 最低限度      | 可以                                              |
| 同行評審清單   | 最低限度      | 可以                                              |
| 單元測試            | 偶而可以      | 可以                                              |
| 整合測試     | 偶而可以      | 可以                                              |
| 滲透測試     | 最低限度      | 可以                                              |
| 支援工具            | 最低限度      | 可以                                              |
| 安全供應鏈     | 偶而可以      | 可以                                              |

We would encourage anyone wanting to adopt an application security
standard to use the OWASP Application Security Verification Standard
(ASVS), as it’s designed to be verifiable and tested, and can be used in
all parts of a secure development lifecycle.

The ASVS is the only acceptable choice for tool vendors. Tools cannot
comprehensively detect, test, or protect against the OWASP Top 10 due to
the nature of several of the OWASP Top 10 risks, with reference to
A04:2021-Insecure Design. OWASP discourages any claims of full coverage
of the OWASP Top 10, because it’s simply untrue.
