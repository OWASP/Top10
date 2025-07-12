# A11:2021 – Next Steps

OWASPトップ10は、建て付け上、最も重要な10のリスクに限定されています。OWASPトップ10に掲載するかどうか、長時間の検討を要した「ぎりぎり境界線」のリスクで、最終的には掲載されなかったものがあります。
データをさまざまな方法で解釈したのですが、それでも他のリスクの方がより大きな影響があったからです。アプリケーションセキュリティプログラムを成熟させるべく取り組んでいる企業や、適用範囲を広げたいと考えているセキュリティコンサルタント会社あるいは製品ツールベンダーは、以下の4つの問題については、識別したり修正したりする努力を傾ける価値があります。

## ソースコードの品質にかかわる問題

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

-   **概要** コード品質の問題には、既知のセキュリティ上の欠陥やパターン、変数の多目的再利用、デバッグ出力での機密情報の露出、一つ違いのエラー、TOCTOU（time of check/time of use）レースコンディション(競合状態)、符号なしまたは符号ありの変換エラー、free後の領域の使用などがあります。このセクションの特徴は、通常、厳しいコンパイラフラグ、静的コード解析ツール、Linter IDEプラグインなどで特定できることです。  モダンな開発現代の言語は、設計上、たとえばRustのメモリ所有権と借用の概念、Rustのスレッド設計、Goの厳格な型付けと境界チェックのように、これらの問題の多くを排除しています。

-   **防御手段** 利用しているエディタや言語の静的コード解析オプションを有効にして使用する。静的コード解析ツールの使用を検討する。RustやGoなど、バグクラスを排除した言語やフレームワークの使用や移行が可能かどうかを検討する。

-   **攻撃シナリオ例** 攻撃者は、複数のスレッド間で静的に共有された変数を使用するレースコンディションを悪用して、機密情報を取得または更新する可能性があります。

-   **参考文献**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)

## サービス拒否攻撃(DoS)

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **概要** 十分なリソースがあれば、サービス拒否は常に可能です。しかし、設計やコーディングの手法は、サービス拒否攻撃の被害の大きさに影響します。例えば、リンクひとつあれば誰でも大容量のファイルにアクセスしたり、あらゆるページで計算量の多いトランザクションを発生させることができます。こういうケースでは、このサービス拒否の挙動は、少ない労力でも成立します。

-   **どのように防ぐか** コードのパフォーマンステストを、CPU、I/O、メモリ使用量について実施し、再設計、最適化、またはコストの高い操作についてキャッシュを行う。巨大なファイルやオブジェクトに対してはアクセス制御し、許可された個人のみがアクセスするよう制御したり、エッジキャッシングネットワークによるサービスを検討する。

-   **攻撃シナリオ例** 攻撃者は、ある操作が完了するのに5～10秒かかると判断したとします。4つのスレッドを同時に実行するとサーバーが応答しなくなるように見えると、攻撃者は1000個のスレッドを使用し、システム全体をオフラインにします。

-   **参考文献**
    - [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## メモリ管理エラー

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **概要** Webアプリケーションは、Java、.NET、node.js（JavaScriptまたはTypeScript）などのメモリ管理のできる言語で書かれることが多いです。しかし、これらの言語は、バッファやヒープのオーバーフロー、free後メモリーの利用、整数オーバーフローなど、メモリ管理の問題を抱えるシステム言語で書かれています。ウェブアプリケーション言語が名目上「メモリセーフ」だとしても、実際の基盤はそうではないことがあります。そのような証拠を示すサンドボックス環境からの脱出は、枚挙にいとまがありません。

-   **防御手** 最近のAPIの多くは、RustやGoなどのメモリセーフな言語で書かれています。Rustの場合、メモリセーフは言語の重要な機能です。既存のコードに対しては、厳密なコンパイラフラグ、強力な型付け、静的コード解析、ファズテストなどを使用するなら、メモリリーク、メモリ、配列のオーバーランなどを特定することができるでしょう。

-   **攻撃シナリオ例** バッファオーバーフローやヒープオーバーフローは、長年にわたり攻撃者の主要な方法となってきました。攻撃者はデータをプログラムに送り、プログラムはそれをスタックバッファ(サイズが足りていないにもかかわらず)に格納しようとします。その結果として、コールスタック上の情報(関数のリターンポインタを含む)が上書きされます。攻撃者の送ったデータにより、関数のリターンポインタが上書きされ、関数がリターンポインタを返したとき、攻撃者のデータに含まれる悪意のあるコードへ制御が移されます。

-   **参考文献**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)

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

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Avg Weighted Exploit  | Avg Weighted Impact  | Max Coverage  | Avg Coverage  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

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

-   **References**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)

## Denial of Service

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Avg Weighted Exploit  | Avg Weighted Impact  | Max Coverage  | Avg Coverage  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

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

-   **References**
    - [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Memory Management Errors

| CWEs Mapped  | Max Incidence Rate  | Avg Incidence Rate  | Avg Weighted Exploit  | Avg Weighted Impact  | Max Coverage  | Avg Coverage  | Total Occurrences  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

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
    mainstay of attackers over the years. The attacker sends data to a program, which it stores in an undersized stack buffer. The result is that information on the call stack is overwritten, including the function’s return pointer. The data sets the value of the return pointer so that when the function returns, it transfers control to malicious code contained in the attacker’s data.

-   **References**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
