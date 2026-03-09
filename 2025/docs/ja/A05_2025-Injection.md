# A05:2025 インジェクション (Injection) ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## 背景 (Background)

インジェクションは前回の第3位から第5位へと順位を下げましたが、これは「暗号化の失敗」や「安全でない設計」との相対的な順位を維持した結果、こうなりました。本カテゴリは最も頻繁にテストされている領域の一つであり、調査対象となったすべてのアプリケーションが何らかの形でインジェクションの検査を受けています。紐付けられた 37 の CWE に関する CVE 数は全カテゴリの中で最多です。本カテゴリには、出現頻度は高いが影響度は相対的に低いクロスサイトスクリプティング (XSS、30,000 件以上の CVE) から、頻度は低いが深刻な影響をもたらす SQL インジェクション (14,000 件以上の CVE) まで、幅広い問題が含まれます。なお、XSS に関連する膨大な数の CVE が、カテゴリ全体の平均加重影響スコアを押し下げる要因となっています。

## スコアテーブル (Score Table)

<table>
  <tr>
   <td>紐付けられた CWE 数</td>
   <td>最大出現率</td>
   <td>平均出現率</td>
   <td>最大網羅率</td>
   <td>平均網羅率</td>
   <td>平均加重悪用スコア</td>
   <td>平均加重影響スコア</td>
   <td>出現総数</td>
   <td>CVE 総数</td>
  </tr>
  <tr>
   <td>37</td>
   <td>13.77%</td>
   <td>3.08%</td>
   <td>100.00%</td>
   <td>42.93%</td>
   <td>7.15</td>
   <td>4.32</td>
   <td>1,404,249</td>
   <td>62,445</td>
  </tr>
</table>

## 説明 (Description)

インジェクションの脆弱性は、信頼できないユーザー入力がブラウザやデータベース、コマンドラインなどのインタープリタ (Interpreter) に送信され、その一部が意図せずコマンドとして実行されてしまうアプリケーションの欠陥です。

以下の項目に当てはまる場合、アプリケーションは脆弱である可能性があります。

* ユーザーから提供されたデータが、アプリケーションによって検証、フィルタリング、または無害化 (Sanitize) されていない。
* 文脈に応じたエスケープ処理を行わずに、動的クエリや非パラメータ化された呼び出しをインタープリタで直接使用している。
* 無害化されていないデータが ORM (オブジェクト関係マッピング) の検索パラメータに使用され、本来アクセスできない機密レコードが抽出されてしまう。
* 悪意ある可能性のあるデータが、動的クエリやコマンド、ストアドプロシージャの中で直接利用、あるいは結合されている。

代表的なものには SQL、NoSQL、OS コマンド、ORM、LDAP、および式言語 (EL) や OGNL (Object Graph Navigation Library) へのインジェクションがあります。インタープリタの種類にかかわらず、その根本的な概念は同一です。検出にはソースコードレビューが最も効果的ですが、すべての入力（パラメータ、ヘッダー、URL、Cookie、JSON、XML 等）に対する自動テストやファジング (Fuzzing) も有効です。また、CI/CD パイプラインに SAST (静的解析)、DAST (動的解析)、IAST (インタラクティブ解析) を組み込むことで、本番環境へのデプロイ前に不備を特定できます。

なお、LLM (大規模言語モデル) において一般的になりつつある関連の脆弱性については、[OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)、特に [LLM01:2025 プロンプトインジェクション (Prompt Injection)](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) で詳しく解説されています。

## 防止方法 (How to Prevent)

インジェクションを防ぐ最善の方法は、「データ」を「コマンド」や「クエリ」から分離し続けることです。

* **安全な API の利用：** インタープリタの使用自体を避ける、パラメータ化されたインターフェースを利用する、あるいは ORM ツールへ移行することが推奨されます。
    * **注意：** パラメータ化していても、PL/SQL や T-SQL 内でクエリとデータを結合して `EXECUTE IMMEDIATE` 等を実行すると、SQL インジェクションが発生する恐れがあります。

データとコマンドを分離できない場合は、以下の手法で脅威を軽減してください。

* **サーバー側での入力検証：** ポジティブな入力検証（許可リスト方式）を実施してください。ただし、多くのアプリでは特殊文字の入力を許容する必要があるため、これだけでは不十分です。
* **特殊文字のエスケープ：** 残存する動的クエリについては、各インタープリタ専用の構文を用いて特殊文字をエスケープしてください。
    * **注意：** テーブル名やカラム名などの SQL 構造そのものはエスケープできません。ユーザーから提供された構造名をクエリに使用するのは極めて危険です。

**警告：** 文字列のパースやエスケープによる対策はミスが起きやすく、システムのわずかな変更で無効化される恐れがあるため、堅牢な手法とは言えません。

## 攻撃シナリオの例 (Example Attack Scenarios)

**シナリオ #1：不適切な SQL 呼び出し**
アプリケーションが、検証されていないデータを結合して SQL を構築している。
```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";

```

攻撃者がブラウザの `id` パラメータを `' OR '1'='1` に書き換えると、クエリの意味が変わり、全口座のレコードが返されてしまいます。

```
http://example.com/app/accountView?id=' OR '1'='1
```

**シナリオ #2：フレームワークへの盲信**
Hibernate Query Language (HQL) を使用していても、以下のように入力を結合すると脆弱になります。

```java
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");

```

攻撃者が `' OR custID IS NOT NULL OR custID='` を入力すると、フィルターを回避して全アカウントへの不正アクセスが可能になります。

**シナリオ #3：OS コマンドへの直接注入**
アプリケーションがユーザー入力を直接 OS コマンドへ渡している。

```java
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);

```

攻撃者が `example.com; cat /etc/passwd` と入力することで、サーバー上で任意のコマンドが実行されます。

## 関連資料 (References)

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing)

## 紐付けられた CWE 一覧 (List of Mapped CWEs)

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
* [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)
* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)
* [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)
* [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)
* [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)
* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
* [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)
* [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
* [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
* [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)
* [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)
* [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)
* [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)
* [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)
* [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)
* [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)
* [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)
* [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)
* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
* [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
* [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)
* [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)
* [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)
* [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)
* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)
* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)
* [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)
* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)


