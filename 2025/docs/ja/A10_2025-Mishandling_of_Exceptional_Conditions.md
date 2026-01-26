# A10:2025 例外的な状況への不適切な対応 (Mishandling of Exceptional Conditions) ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## 背景 (Background.)

「例外的な状況への不適切な対応」は、2025年版の新カテゴリです。本カテゴリは 24 の CWE (共通弱点一覧) で構成されており、不適切なエラー処理、論理エラー、安全でない失敗処理(フェイルオープン) (Failing open)、およびシステムが遭遇しうる異常な状況に起因するその他の関連シナリオに焦点を当てています。このカテゴリには、以前は「コード品質の低さ (Poor code quality)」に関連付けられていたいくつかの CWE が含まれています。それは私たちにとってあまりに一般的すぎました。私たちの意見では、このより具体的なカテゴリの方が、より良い指針を提供できると考えています。

本カテゴリに含まれる注目すべき CWE には、機密情報を含むエラーメッセージの生成 (CWE-209)、必須パラメータの処理失敗 (CWE-234)、不十分な特権の不適切な処理 (CWE-274)、NULLポインタ参照 (CWE-476)、および安全でない失敗処理 (CWE-636) が含まれます。


## スコアテーブル (Score table.)


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
   <td>20.67%
   </td>
   <td>2.95%
   </td>
   <td>100.00%
   </td>
   <td>37.95%
   </td>
   <td>7.11
   </td>
   <td>3.81
   </td>
   <td>769,581
   </td>
   <td>3,416
   </td>
  </tr>
</table>



## 説明 (Description.)

ソフトウェアにおける例外的な状況の不適切な取り扱いは、プログラムが異常かつ予測不能な事態を防止、検知、および応答することに失敗したときに発生し、クラッシュや予期しない挙動、そして時には脆弱性を引き起こします。これには、以下の 3 つの失敗のいずれか、または複数が関与しています。すなわち、アプリケーションが異常な状況の発生を「防止」できないこと、発生している状況を「識別」できないこと、あるいは、その状況に対して後から「応答」が不適切、あるいは全く行われないことです。

例外的な状況は、入力検証の不足、不十分、または不完全さや、発生した関数ではなく上位階層で行われる遅すぎるエラー処理、あるいはメモリ、特権、ネットワークの問題といった予期せぬ環境状態、一貫性のない例外処理、あるいは例外が全く処理されずシステムが未知かつ予測不能な状態に陥ることによって引き起こされます。アプリケーションが「次の命令をどうすべきか」確信を持てなくなったときはいつでも、例外的な状況の処理に失敗しています。見つけにくいエラーや例外は、長期にわたってアプリケーション全体のセキュリティを脅かす可能性があります。

例外的な状況の処理を誤ると、ロジックの不具合、オーバーフロー、競合状態 (Race conditions)、不正な取引、あるいはメモリ、状態、リソース、タイミング、認証、および認可に関する問題など、多くの異なるセキュリティ脆弱性が発生する可能性があります。これらのタイプの脆弱性は、システムまたはそのデータの機密性、可用性、および完全性に悪影響を及ぼす可能性があります。攻撃者は、アプリケーションの欠陥のあるエラー処理を操作して、この脆弱性を突いてきます。


## 防止方法 (How to prevent.)

例外的な状況を適切に処理するには、そのような状況を計画しておく必要があります（最悪の事態を想定 (Expect the worst) する）。すべてのシステムエラーを、それが発生した場所で直接「キャッチ (Catch)」し、それを処理しなければなりません（つまり、問題を解決し、その問題から確実に回復するために意味のある何かを行うことを意味します）。処理の一環として、エラーをスローすること（ユーザーに理解可能な方法で通知する）、イベントをログに記録すること、および正当であると判断した場合にはアラートを発行することを含めるべきです。また、何かを見落とした場合に備えて、グローバルな例外ハンドラーを設置しておくべきです。理想的には、継続的な攻撃を示す繰り返されるエラーやパターンを監視し、何らかの応答、防御、またはブロックを発行できる、監視 (Monitoring) または可観測性 (Observability) のツールや機能を備えることです。これは、私たちのエラー処理の弱点に焦点を当てたスクリプトやボットをブロックし、それらに応答するのに役立ちます。

例外的な状況をキャッチして処理することで、プログラムの基盤となるインフラストラクチャが予測不能な状況に対処したまま放置されないようにします。いかなる種類のトランザクションであっても、その途中でエラーが発生した場合は、トランザクションのすべての部分をロールバックしてやり直すことが非常に重要です（フェイルクローズ (Fail closed) とも呼ばれます）。途中でトランザクションを回復しようとすると、回復不可能な間違いを犯してしまうことがよくあります。

可能な限り、レート制限 (Rate limiting)、リソース制限 (Resource quotas)、スロットリング (Throttling)、およびその他の制限を追加して、そもそも例外的な状況が発生するのを防いでください。情報技術において無制限なものは何一つあってはなりません。それはアプリケーションのレジリエンス (Resilience)（回復力）の欠如、サービス拒否、ブルートフォース攻撃の成功、および莫大なクラウド利用料に繋がるからです。
特定のレートを超える同一の繰り返されるエラーについては、それらがいつ、どの程度の頻度で発生したかを示す統計としてのみ出力することを検討してください。この情報は、自動化されたロギングや監視を妨げないように、元のメッセージに追加されるべきです（[A09:2025 セキュリティログとアラートの不備](A09_2025-Security_Logging_and_Alerting_Failures.md) 参照）。

これに加えて、厳格な入力検証（受け入れなければならない潜在的に危険な文字については無害化 (Sanitization) またはエスケープを行う）、および「集約された (Centralized)」エラー処理、ロギング、監視、アラート、ならびにグローバル例外ハンドラーを含めるべきです。一つのアプリケーションに例外的な状況を処理するための複数の関数を持たせるべきではなく、一箇所で、毎回同じ方法で実行されるべきです。また、このセクションのすべてのアドバイスについてプロジェクトのセキュリティ要件を作成し、プロジェクトの設計フェーズで脅威モデリング (Threat modeling) や安全な設計レビューを実施し、コードレビューや静的解析を実施し、最終的なシステムに対してストレス、パフォーマンス、およびペネトレーションテストを実行すべきです。

可能であれば、組織全体で例外的な状況を同じ方法で処理すべきです。そうすることで、この重要なセキュリティ制御におけるエラーのコードレビューや監査が容易になります。


## 攻撃シナリオの例 (Example attack scenarios.)

**シナリオ #1：例外的な状況の誤処理によるリソースの枯渇 (サービス拒否)** アプリケーションがファイルのアップロード時に例外をキャッチするものの、その後にリソースを適切に解放しない場合に発生する可能性があります。新しい例外が発生するたびにリソースがロックされるか利用不可のままになり、最終的にすべてのリソースが使い果たされます。

**シナリオ #2：不適切な処理またはデータベースエラーによる機密データの露出** ユーザーにシステムの完全なエラーを明らかにしてしまうケースです。攻撃者は、機密性の高いシステム情報を利用してより優れた SQL インジェクション攻撃を作成するために、意図的にエラーを発生させ続けます。ユーザーへのエラーメッセージに含まれる機密データは偵察 (Reconnaissance) 活動に利用されます。

**シナリオ #3：金融取引における状態の破損** 攻撃者がネットワークの中断を介して多段階のトランザクションを妨害することによって引き起こされる可能性があります。トランザクションの順序が「ユーザーアカウントの引き落とし、宛先アカウントへの入金、トランザクションのログ記録」であったと仮定します。途中でエラーが発生したときにシステムがトランザクション全体を適切にロールバック（フェイルクローズ）しない場合、攻撃者はユーザーのアカウントを枯渇させたり、あるいは攻撃者が宛先に何度も送金できてしまう競合状態が発生したりする可能性があります。


## 関連資料 (References.)

OWASP MASVS‑RESILIENCE

* [OWASP Cheat Sheet: ロギング](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
* [OWASP Cheat Sheet: エラー処理](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
* [OWASP Application Security Verification Standard (ASVS): V16.5 エラー処理](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)
* [OWASP Testing Guide: 4.8.1 エラー処理のテスト](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [例外に関するベストプラクティス (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)
* [クリーンコードと例外処理の技術 (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)
* [一般的なエラー処理規則 (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)
* [例外的な状況の現実世界における不適切な取り扱いの例](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/)


## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215 Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234 Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248 Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252 Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274 Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369 Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390 Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391 Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394 Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396 Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397 Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460 Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476 NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478 Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484 Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550 Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636 Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703 Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754 Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755 Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

