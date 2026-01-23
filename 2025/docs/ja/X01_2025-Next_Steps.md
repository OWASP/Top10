# 次の一手 (Next Steps)

設計上、OWASP Top 10 は本質的に最も重大な 10 のリスクに限定されています。すべての OWASP Top 10 において、掲載を巡って長期間検討された「僅差の (On the cusp)」リスクが存在しますが、最終的には他のリスクの方がより一般的で影響力が大きいと判断され、選外となりました。

以下の 2 つの問題は、成熟したアプリケーションセキュリティプログラムを目指す組織、セキュリティコンサルタント、あるいは提供機能の網羅率を高めたいツールベンダーにとって、特定と是正に取り組む価値が十分にあるものです。


## X01:2025 アプリケーション・レジリエンスの欠如 (Lack of Application Resilience)

### 背景 (Background.)

これは 2021 年版の「サービス拒否 (Denial of Service)」を改称したものです。根本原因ではなく症状を説明していたため、名称が変更されました。本カテゴリは、レジリエンス (Resilience)（回復力）の問題に関連する弱点を表す CWE (共通弱点一覧) に焦点を当てています。本カテゴリのスコアリングは、「A10:2025 例外的な状況への不適切な対応」と非常に僅差でした。関連する CWE には、制御されていないリソースの消費 (CWE-400)、高度に圧縮されたデータの不適切な処理（データ増幅） (CWE-409)、制御されていない再帰 (CWE-674)、および到達不能な終了条件を持つループ（無限ループ） (CWE-835) が含まれます。


### スコアテーブル (Score table.)


<table>
  <tr>
   <td>紐付けられた CWE 数
   </td>
   <td>最大出現率
   </td>
   <td>平均出現率
   </td>
   <td>最大網羅率
   </td>
   <td>平均網羅率
   </td>
   <td>平均加重悪用スコア
   </td>
   <td>平均加重影響スコア
   </td>
   <td>出現総数
   </td>
   <td>CVE 総数
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>20.05%
   </td>
   <td>4.55%
   </td>
   <td>86.01%
   </td>
   <td>41.47%
   </td>
   <td>7.92
   </td>
   <td>3.49
   </td>
   <td>865,066
   </td>
   <td>4,423
   </td>
  </tr>
</table>


### 説明 (Description.)

本カテゴリは、負荷、障害、および例外的なケースに対してアプリケーションが応答する際のシステム的な弱点を表しており、それによって障害からの回復が不可能になります。アプリケーションが予期せぬ状況、リソースの制約、およびその他の有害な事象を適切に処理、耐え忍び、または回復できない場合、多くは可用性の問題を引き起こしますが、データの破損、機密データの露出、連鎖的な失敗、およびセキュリティ制御のバイパスを招くこともあります。

さらに、[X02:2025 メモリ管理の失敗](#x022025-memory-management-failures) も、アプリケーションやシステム全体の失敗に繋がる可能性があります。


### 防止方法 (How to prevent.)

この種の脆弱性を防ぐには、システムの失敗と回復を前提とした設計 (Design for failure and recovery) を行う必要があります。

* 制限、リソース制限 (Quotas)、およびフェイルオーバー機能を実装してください。特にリソースを最も消費する操作に注意を払ってください。
* リソース集約的なページを特定し、事前に対策を立ててください。攻撃面 (Attack surface) を削減し、特に未知または信頼できないユーザーに対して、大量のリソース（CPU、メモリ等）を必要とする不要な「ガジェット (Gadgets)」や機能を露出させないでください。
* 許可リスト (Allow-lists) とサイズ制限を用いた厳格な入力検証を実施し、徹底的にテストしてください。
* レスポンスのサイズを制限し、生のレスポンスをクライアントに返さないでください（サーバー側で処理してください）。
* デフォルトで「安全/閉鎖 (Safe/closed)」の状態にし、デフォルトで拒否 (Deny by default) し、エラーが発生した場合はロールバックしてください。
* リクエストスレッド内でのブロッキング同期呼び出しを避けてください（非同期/ノンブロッキングの利用、タイムアウト、同時実行制限の設定等を行ってください）。
* エラー処理機能を慎重にテストしてください。
* サーキットブレーカー (Circuit breakers)、バルクヘッド (Bulkheads)、リトライロジック、および緩やかな機能低下 (Graceful degradation) などのレジリエンスパターンを実装してください。
* パフォーマンスおよび負荷テストを実施してください。リスク許容度がある場合はカオスエンジニアリング (Chaos engineering) も検討してください。
* 合理的で許容可能な範囲で、冗長性を考慮した実装とアーキテクチャを採用してください。
* 監視 (Monitoring)、可観測性 (Observability)、およびアラート (Alerting) を実装してください。
* RFC 2267 に準拠して、無効な送信元アドレスをフィルタリングしてください。
* フィンガープリント、IP、または挙動による動的な解析を用いて、既知のボットネットをブロックしてください。
* プルーフ・オブ・ワーク (Proof-of-Work)：通常のユーザーには大きな影響を与えず、大量のリクエストを送信しようとするボットにのみ負荷を強いるような、リソースを消費する操作を「攻撃者側」で開始させてください。システムの全般的な負荷が上昇した際、特に信頼性の低い、あるいはボットと思われるシステムに対して、プルーフ・オブ・ワークをより困難にしてください。
* 無活動時間に基づくアイドルタイムアウトおよび最終タイムアウトを設定し、サーバー側のセッション時間を制限してください。
* セッションに紐付く情報ストレージの量を制限してください。


### 攻撃シナリオの例 (Example attack scenarios.)

**シナリオ #1：** 攻撃者が意図的にアプリケーションリソースを消費させてシステム内の障害を誘発し、サービス拒否 (DoS) を引き起こす。これには、メモリの枯渇、ディスク容量の占有、CPU の飽和、または際限のない接続による枯渇(endless connections)などが含まれます。

**シナリオ #2：** 入力へのファジング (Fuzzing) により、アプリケーションのビジネスロジックを破壊するような特定のレスポンスを引き起こす。

**シナリオ #3：** 攻撃者がアプリケーションの依存関係に注目し、API やその他の外部サービスを停止させる。アプリケーションはそれらのサービスなしでは継続できなくなります。


### 関連資料 (References.)

* [OWASP Cheat Sheet: サービス拒否 (Denial of Service)](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core ベストプラクティス (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [マイクロサービスにおけるレジリエンス：バルクヘッド vs サーキットブレーカー (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [バルクヘッドパターン (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST サイバーセキュリティフレームワーク (CSF)](https://www.nist.gov/cyberframework)
* [ブロッキング呼び出しの回避：Java で非同期化する (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)


### 紐付けられた CWE 一覧 (List of Mapped CWEs)
* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-400 Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
* [CWE-409 Improper Handling of Highly Compressed Data (Data Amplification)](https://cwe.mitre.org/data/definitions/409.html)
* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-674 Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-835 Loop with Unreachable Exit Condition ('Infinite Loop')](https://cwe.mitre.org/data/definitions/835.html)


## X02:2025 メモリ管理の失敗 (Memory Management Failures)

### 背景 (Background.)

Java、C#、JavaScript/TypeScript (node.js)、Go、および「安全な」Rust といった言語は、メモリ安全 (Memory safe) です。メモリ管理の問題は、C や C++ のような非メモリ安全言語で発生する傾向があります。本カテゴリは、関連する CVE が 3 番目に多いにもかかわらず、コミュニティ調査では最も低いスコアであり、データ上でも低いスコアとなりました。これは、従来のデスクトップアプリケーションよりもウェブアプリケーションが主流となっているためと考えられます。メモリ管理の脆弱性は、しばしば最高の CVSS スコアを記録します。


### スコアテーブル (Score table.)


<table>
  <tr>
   <td>紐付けられた CWE 数
   </td>
   <td>最大出現率
   </td>
   <td>平均出現率
   </td>
   <td>最大網羅率
   </td>
   <td>平均網羅率
   </td>
   <td>平均加重悪用スコア
   </td>
   <td>平均加重影響スコア
   </td>
   <td>出現総数
   </td>
   <td>CVE 総数
   </td>
  </tr>
  <tr>
   <td>24
   </td>
   <td>2.96%
   </td>
   <td>1.13%
   </td>
   <td>55.62%
   </td>
   <td>28.45%
   </td>
   <td>6.75
   </td>
   <td>4.82
   </td>
   <td>220,414
   </td>
   <td>30,978
   </td>
  </tr>
</table>


### 説明 (Description.)

アプリケーションが自身でメモリを管理しなければならない場合、ミスを犯すのは非常に容易です。メモリ安全言語の使用は増えていますが、世界中で依然として多くのレガシーシステムが稼働しており、非メモリ安全言語の使用を必要とする新しい低レベルシステムや、メインフレーム、IoT デバイス、ファームウェア、および自身でのメモリ管理を強いられる可能性のあるその他のシステムと対話するウェブアプリケーションも存在します。代表的な CWE は、入力サイズの確認なしでのバッファコピー（クラシックなバッファオーバーフロー） (CWE-120) および スタックベースのバッファオーバーフロー (CWE-121) です。

メモリ管理の失敗は、以下の場合に発生する可能性があります。

* 変数に十分なメモリを割り当てていない
* 入力を検証しておらず、ヒープ、スタック、またはバッファのオーバーフローを引き起こしている
* 変数の型が保持できるサイズよりも大きなデータ値を保存している
* 未割り当てのメモリやアドレス空間を使用しようとしている
* オフバイワン (Off-by-one) エラー（0 ではなく 1 から数え始める等）を作成している
* 解放 (Free) された後のオブジェクトにアクセスしようとしている
* 未初期化の変数を使用している
* メモリリークを起こしている、あるいはアプリケーションが失敗するまでエラーによって利用可能なすべてのメモリを使い果たしている

メモリ管理の失敗は、アプリケーションやシステム全体の失敗に繋がる可能性があります（[X01:2025 アプリケーション・レジリエンスの欠如](#x012025-lack-of-application-resilience) も参照してください）。


### 防止方法 (How to prevent.)

メモリ管理の失敗を防ぐ最善の方法は、メモリ安全言語を使用することです。例としては、Rust、Java、Go、C#、Python、Swift、Kotlin、JavaScript などが挙げられます。新しいアプリケーションを作成する際は、メモリ安全言語への切り替えに伴う学習曲線がそれだけの価値があることを、組織に対して強く説得してください。フルリファクタリングを行う場合は、可能かつ実現可能な範囲で、メモリ安全言語での書き換えを推進してください。

メモリ安全言語を使用できない場合は、以下を実施してください。

* メモリ管理エラーの悪用を困難にする以下のサーバー機能を有効にしてください：アドレス空間配置のランダム化 (ASLR: Address Space Layout Randomization)、データ実行防止 (DEP: Data Execution Protection)、および構造化例外ハンドラー上書き保護 (SEHOP: Structured Exception Handling Overwrite Protection)。
* アプリケーションのメモリリークを監視してください。
* システムへのすべての入力を非常に慎重に検証し、期待を満たさないすべての入力を拒否してください。
* 使用している言語を学習し、安全でない関数とより安全な関数のリストを作成し、チーム全体で共有してください。可能であれば、安全なコーディングガイドラインや標準に追加してください。例えば C 言語では、`strcpy()` よりも `strncpy()` を、`strcat()` よりも `strncat()` を優先してください。
* 言語やフレームワークがメモリ安全ライブラリを提供している場合は、それを使用してください。例：Safestringlib や SafeStr。
* 可能な限り、生の配列やポインタではなく、管理されたバッファや文字列を使用してください。
* メモリの問題や選択した言語に焦点を当てた安全なコーディングトレーニングを受けてください。トレーナーに対して、メモリ管理の失敗を懸念していることを伝えてください。
* コードレビューや静的解析を実施してください。
* StackShield、StackGuard、Libsafe などのメモリ管理を支援するコンパイラツールを使用してください。
* システムへのすべての入力に対してファジング (Fuzzing) を実施してください。
* ペネトレーションテストを実施する場合は、メモリ管理の失敗を懸念しており、テスト中に特別な注意を払ってほしいことをテスターに伝えてください。
* コンパイラのエラー**および**警告をすべて修正してください。プログラムがコンパイルできるからといって、警告を無視しないでください。
* 基盤となるインフラストラクチャに対して、定期的なパッチ適用、スキャン、および要塞化 (Hardening) を実施してください。
* 基盤となるインフラストラクチャにおいて、潜在的なメモリ脆弱性やその他の失敗がないか、特に注意して監視してください。
* [カナリア (Canaries)](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) を使用して、アドレススタックをオーバーフロー攻撃から保護することを検討してください。


### 攻撃シナリオの例 (Example attack scenarios.)

**シナリオ #1：** バッファオーバーフローは最も有名なメモリ脆弱性であり、攻撃者がフィールドに受け入れ可能な量以上の情報を送信し、基盤となる変数に用意されたバッファを溢れさせる状況です。攻撃が成功すると、溢れた文字がスタックポインタを上書きし、攻撃者がプログラムに悪意のある命令を挿入できるようになります。

**シナリオ #2：** Use-After-Free (UAF) は、ブラウザのバグバウンティ提出において半ば一般的なほど頻繁に発生します。DOM 要素を操作する JavaScript を処理するウェブブラウザを想像してください。攻撃者は、オブジェクト（DOM 要素等）を作成してその参照を取得する JavaScript ペイロードを作成します。巧妙な操作を通じて、ブラウザにそのオブジェクトのメモリを解放させつつ、そのオブジェクトへのダングリングポインタを保持させます。ブラウザがメモリの解放に気づく前に、攻撃者は**同じ**メモリ空間を占有する新しいオブジェクトを割り当てます。ブラウザが元のポインタを使用しようとすると、それは攻撃者が制御するデータを指すようになります。このポインタが仮想関数テーブル用であった場合、攻撃者はコードの実行を自身のペイロードにリダイレクトさせることができます。

**シナリオ #3：** ユーザー入力を受け取り、適切に検証や無害化 (Sanitization) を行わず、そのままロギング関数に渡すネットワークサービス。ユーザーからの入力が、フォーマットを指定せずに `syslog("%s", user_input)` ではなく `syslog(user_input)` としてロギング関数に渡されます。攻撃者は `%x` などの書式指定子を含む悪意のあるペイロードを送信してスタックメモリを読み取ったり（機密データの露出）、`%n` を用いてメモリ番地に書き込んだりします。複数の書式指定子を連鎖させることで、スタックの構成を把握し、重要なアドレスを特定して上書きすることができます。これは 書式文字列の脆弱性 (Format string vulnerability)（制御されていない書式文字列）です。

注：モダンなブラウザは、このような攻撃から守るために、ブラウザサンドボックス (Browser sandboxing)、ASLR、DEP/NX、RELRO、PIE などの多くの階層の防御を備えています。ブラウザに対するメモリ管理の失敗を突いた攻撃は、実行するのが容易な攻撃ではありません。


### 関連資料 (References.)

* [OWASP community pages: メモリリーク (Memory leak),](https://owasp.org/www-community/vulnerabilities/Memory_leak) [メモリの二重解放 (Doubly freeing memory),](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [および バッファオーバーフロー (Buffer Overflow)](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: ファジングリソースのリスト](https://github.com/secfigo/Awesome-Fuzzing)
* [Project Zero ブログ](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC ブログ](https://www.microsoft.com/en-us/msrc/blog)


### 紐付けられた CWE 一覧 (List of Mapped CWEs)
* [CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-125 Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-415 Double Free](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-787 Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)


## X03:2025 AI 生成コードへの不適切な信頼 (Inappropriate Trust in AI Generated Code) (「バイブ・コーディング (Vibe Coding)」)

### 背景 (Background.)

現在、全世界が AI について語り、利用しており、これにはソフトウェア開発者も含まれます。現時点では AI 生成コードに関連する CVE や CWE は存在しませんが、AI が生成したコードは人間が書いたコードよりも脆弱性を含むことが多いことが、広く知られ、文書化されています。


### 説明 (Description.)

ソフトウェア開発の実践において、AI の支援を受けてコードを書くだけでなく、人間の監視をほぼ経ずにコードが書かれコミットされる（しばしば「バイブ・コーディング (Vibe coding)」と呼ばれます）よう変化しているのを私たちは目にしています。ブログやウェブサイトからコードスニペットを深く考えずにコピーするのが決して良いアイデアではなかったのと同様に、このケースでは問題がさらに悪化しています。優れた安全なコードスニペットはかつても今も稀であり、システムの制約により AI によって統計的に無視される可能性があります。


### 防止方法 (How to prevent.)

AI を使用する際、コードを書くすべての人々に以下を考慮することを強く求めます。

* AI によって書かれたコードやオンラインフォーラムからコピーしたコードであっても、自身が提出するすべてのコードを読み、完全に理解している必要があります。コミットするすべてのコードに対して責任を負うのはあなた自身です。
* AI の支援を受けたコードを、脆弱性がないか徹底的にレビューしてください。理想的には自身の目で、またその目的のために作られたセキュリティツール（静的解析など）も使用してください。[OWASP Cheat Sheet: 安全なコードレビュー](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html) で説明されているような古典的なコードレビュー手法の活用を検討してください。
* 理想的には、自身でコードを書き、AI に改善を提案させ、AI のコードをチェックし、結果に満足するまで AI に修正を行わせることです。
* 自身で収集・精査した安全なコードサンプルや文書（組織の安全なコーディングガイドライン、標準、またはポリシー等）を備えた検索拡張生成 (RAG: Retrieval Augmented Generation) サーバーの使用を検討し、RAG サーバーにポリシーや標準を遵守させてください。
* 選択した AI で使用するために、プライバシーやセキュリティのガードレールを実装したツールの購入を検討してください。
* プライベート AI の購入を検討してください。理想的には、組織のデータ、クエリ、コード、またはその他の機密情報で AI が学習されないような契約合意（プライバシー合意を含む）を結んでください。
* IDE と AI の間にモデル・コンテキスト・プロトコル (MCP: Model Context Protocol) サーバーを導入し、選択したセキュリティツールの使用を強制するように設定することを検討してください。
* 開発者（およびすべての従業員）に対し、組織内で AI をどのように使用すべきか、あるいは使用すべきでないかを周知するためのポリシーとプロセスを SDLC の一部として実装してください。
* IT セキュリティのベストプラクティスを考慮した、高品質で効果的なプロンプトのリストを作成してください。理想的には、内部の安全なコーディングガイドラインも考慮に入れるべきです。開発者はこれらのプロンプトを自身のプログラムの開始点として利用できます。
* AI は、システム開発ライフサイクルの各フェーズの一部となる可能性が高いですが、効果的かつ安全に利用する方法の両方を考慮してください。賢明に利用してください。
* 実際のところ、複雑な機能、ビジネス上重要なプログラム、または長期間使用されるプログラムに対して、バイブ・コーディングを用いることは**推奨されません**。
* シャドー AI (Shadow AI) の利用に対する技術的なチェックと保護策を実装してください。
* ポリシーに加え、安全な AI の利用方法やソフトウェア開発における AI 利用のベストプラクティスについて、開発者をトレーニングしてください。


### 関連資料 (References.)

* [OWASP Cheat Sheet: 安全なコードレビュー (Secure Code Review)](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


### 紐付けられた CWE 一覧 (List of Mapped CWEs)
-なし-

