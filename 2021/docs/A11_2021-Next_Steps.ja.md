# A11:2021 – Next Steps

OWASPトップ10は、建て付け上、最も重要な10のリスクに限定されています。OWASPトップ10に掲載するかどうか、長時間の検討を要した「ぎりぎり境界線」のリスクで、最終的には掲載されなかったものがあります。
データをさまざまな方法で解釈したのですが、それでも他のリスクの方がより大きな影響があったからです。アプリケーションセキュリティプログラムを成熟させるべく取り組んでいる企業や、適用範囲を広げたいと考えているセキュリティコンサルタント会社あるいは製品ツールベンダーは、以下の4つの問題については、識別したり修正したりする努力を傾ける価値があります。

## ソースコードの品質にかかわる問題

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 60.85%        | 23.42%        |                       |                      | 101736             | 7564        |

-   **Description.** コード品質の問題には、既知のセキュリティ上の欠陥やパターン、変数の多目的再利用、デバッグ出力での機密情報の露出、一つ違いのエラー、TOCTOU（time of check/time of use）レースコンディション(競合状態)、符号なしまたは符号ありの変換エラー、free後の領域の使用などがあります。このセクションの特徴は、通常、厳しいコンパイラフラグ、静的コード解析ツール、Linter IDEプラグインなどで特定できることです。  モダンな開発現代の言語は、設計上、たとえばRustのメモリ所有権と借用の概念、Rustのスレッド設計、Goの厳格な型付けと境界チェックのように、これらの問題の多くを排除しています。

-   **How to prevent**. 利用しているエディタや言語の静的コード解析オプションを有効にして使用する。静的コード解析ツールの使用を検討する。RustやGoなど、バグクラスを排除した言語やフレームワークの使用や移行が可能かどうかを検討する。

-   **Example attack scenarios**. 攻撃者は、複数のスレッド間で静的に共有された変数を使用するレースコンディションを悪用して、機密情報を取得または更新する可能性があります。

-   **References**. TBA

## サービス拒否攻撃(DoS)

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 79.58%        | 33.26%        |                       |                      | 66985              | 973         |

-   **Description**. 十分なリソースがあれば、サービス拒否は常に可能です。しかし、設計やコーディングの手法は、サービス拒否攻撃の被害の大きさに影響します。例えば、リンクひとつあれば誰でも大容量のファイルにアクセスしたり、あらゆるページで計算量の多いトランザクションを発生させることができます。こういうケースでは、このサービス拒否の挙動は、少ない労力でも成立します。

-   **How to prevent**. コードのパフォーマンステストを、CPU、I/O、メモリ使用量について実施し、再設計、最適化、またはコストの高い操作についてキャッシュを行う。巨大なファイルやオブジェクトに対してはアクセス制御し、許可された個人のみがアクセスするよう制御したり、エッジキャッシングネットワークによるサービスを検討する。

-   **Example attack scenarios**. 攻撃者は、ある操作が完了するのに5～10秒かかると判断したとします。4つのスレッドを同時に実行するとサーバーが応答しなくなるように見えると、攻撃者は1000個のスレッドを使用し、システム全体をオフラインにします。

-   **References**. TBA

## Memory Management Errors

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 56.06%        | 31.74%        |                       |                      | 26576              | 16184       |

-   **Description**. Webアプリケーションは、Java、.NET、node.js（JavaScriptまたはTypeScript）などのメモリ管理のできる言語で書かれることが多いです。しかし、これらの言語は、バッファやヒープのオーバーフロー、free後メモリーの利用、整数オーバーフローなど、メモリ管理の問題を抱えるシステム言語で書かれています。ウェブアプリケーション言語が名目上「メモリセーフ」だとしても、実際の基盤はそうではないことがあります。そのような証拠を示すサンドボックス環境からの脱出は、枚挙にいとまがありません。

-   **How to prevent**. 最近のAPIの多くは、RustやGoなどのメモリセーフな言語で書かれています。Rustの場合、メモリセーフは言語の重要な機能です。既存のコードに対しては、厳密なコンパイラフラグ、強力な型付け、静的コード解析、ファズテストなどを使用するなら、メモリリーク、メモリ、配列のオーバーランなどを特定することができるでしょう。

-   **Example attack scenarios**. Buffer and heap overflows have been a
    mainstay of

-   **References**. TBA

## Security Control Failures

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 2            | 11.35%              | 9.64%               | 76.60%        | 45.23%        |                       |                      | 44911              | 329         |

-   **Description**.

-   **How to prevent**.

-   **Example attack scenarios**.

-   **References**. TBA

# A11:2021 – Next Steps

By design, the OWASP Top 10 is innately limited to the ten most
significant risks. Every OWASP Top 10 has “on the cusp” risks considered
at length for inclusion, but in the end, they didn’t make it. No matter
how we tried to interpret or twist the data, the other risks were more
prevalent and impactful.

Organizations working towards a mature appsec program or security
consultancies or tool vendors wishing to expand coverage for their
offerings, the following four issues are well worth the effort to
identify and remediate.

## Code Quality issues

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 60.85%        | 23.42%        |                       |                      | 101736             | 7564        |

-   **Description.** Code quality issues include known security defects
    or patterns, reusing variables for multiple purposes, exposure of
    sensitive information in debugging output, off-by-one errors, time
    of check/time of use (TOCTOU) race conditions, unsigned or signed
    conversion errors, use after free, and more. The hallmark of this
    section is that they can usually be identified with stringent
    compiler flags, static code analysis tools, and linter IDE plugins.
    Modern languages by design eliminated many of these issues, such as
    Rust’s memory ownership and borrowing concept, Rust’s threading
    design, and Go’s strict typing and bounds checking.

-   **How to prevent**. Enable and use your editor and language’s static
    code analysis options. Consider using a static code analysis tool.
    Consider if it might be possible to use or migrate to a language or
    framework that eliminates bug classes, such as Rust or Go.

-   **Example attack scenarios**. An attacker might obtain or update
    sensitive information by exploiting a race condition using a
    statically shared variable across multiple threads.

-   **References**. TBA

## Denial of Service

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 79.58%        | 33.26%        |                       |                      | 66985              | 973         |

-   **Description**. Denial of service is always possible given
    sufficient resources. However, design and coding practices have a
    significant bearing on the magnitude of the denial of service.
    Suppose anyone with the link can access a large file, or a
    computationally expensive transaction occurs on every page. In that
    case, denial of service requires less effort to conduct.

-   **How to prevent**. Performance test code for CPU, I/O, and memory
    usage, re-architect, optimize, or cache expensive operations.
    Consider access controls for larger objects to ensure that only
    authorized individuals can access huge files or objects or serve
    them by an edge caching network.

-   **Example attack scenarios**. An attacker might determine that an
    operation takes 5-10 seconds to complete. When running four
    concurrent threads, the server seems to stop responding. The
    attacker uses 1000 threads and takes the entire system offline.

-   **References**. TBA

## Memory Management Errors

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 56.06%        | 31.74%        |                       |                      | 26576              | 16184       |

-   **Description**. Web applications tend to be written in managed
    memory languages, such as Java, .NET, or node.js (JavaScript or
    TypeScript). However, these languages are written in systems
    languages that have memory management issues, such as buffer or heap
    overflows, use after free, integer overflows, and more. There have
    been many sandbox escapes over the years that prove that just
    because the web application language is nominally memory “safe,” the
    foundations are not.

-   **How to prevent**. Many modern APIs are now written in memory-safe
    languages such as Rust or Go. In the case of Rust, memory safety is
    a crucial feature of the language. For existing code, the use of
    strict compiler flags, strong typing, static code analysis, and fuzz
    testing can be beneficial in identifying memory leaks, memory, and
    array overruns, and more.

-   **Example attack scenarios**. Buffer and heap overflows have been a
    mainstay of

-   **References**. TBA

## Security Control Failures

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Max Coverage  | Avg Coverage  | Avg Weighted Exploit  | Avg Weighted Impact  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 2            | 11.35%              | 9.64%               | 76.60%        | 45.23%        |                       |                      | 44911              | 329         |

-   **Description**.

-   **How to prevent**.

-   **Example attack scenarios**.

-   **References**. TBA
