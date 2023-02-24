# A03:2021 – インジェクション    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## 因子

| 対応する CWE 数 | 最大発生率 | 平均発生率 |  加重平均（攻撃の難易度） | 加重平均（攻撃による影響） | 最大網羅率 | 平均網羅率 | 総発生数 | CVE 合計件数 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 7.25                 | 7.15                | 94.04%       | 47.90%       | 274,228           | 32,078     |

## 概要

インジェクションは3位に下がっています。
94%のアプリケーションで、何らかのインジェクションに関する問題が確認されており、最大発生率は19%、平均発生率は3%、そして発生件数は27万4千件でした。
注目すべき共通脆弱性識別子 (CWEs) は、*CWE-79:クロスサイト・スクリプティング*、 *CWE-89:SQLインジェクション*、そして*CWE-73:ファイル名やパス名の外部制御*です。

## 説明

次のような状況では、アプリケーションはこの攻撃に対して脆弱です:

-   ユーザが提供したデータが、アプリケーションによって検証、フィルタリング、またはサニタイズされない。

-   コンテキストに応じたエスケープが行われず、動的クエリまたはパラメータ化されていない呼出しがインタープリタに直接使用される。

-   オブジェクト・リレーショナル・マッピング（ORM）の検索パラメータに悪意を持ったデータが使用され、重要なレコードを追加で抽出してしまう。

-   悪意を持ったデータを直接または連結して使う。動的クエリ、コマンドまたはストアド・プロシージャにおいてSQLやコマンドがそのような構造と悪意を持ったデータを含む。

より一般的なインジェクションとしては、SQL、NoSQL、OS コマンド、オブジェクト・リレーショナル・マッピング（ORM）、LDAP、およびEL式（Expression Language）またはOGNL式（Object Graph Navigation Library）のインジェクションがあります。
コンセプトはすべてのインタープリタで同じです。
ソースコードをレビューすれば、インジェクションに対してアプリケーションが脆弱であるか最も効果的に検出できます。
すべてのパラメータ、ヘッダー、URL、Cookie、JSON、SOAP、およびXMLデータ入力の完全な自動テストが推奨されます。
また、組織は静的 (SAST)、動的 (DAST)、そしてインタラクティブ (IAST) アプリケーションセキュリティテストツールをCI/CDパイプラインに導入できます。
これにより、新たに作られてしまったインジェクション欠陥を稼働環境に展開する前に検出できます。

## 防止方法

インジェクションを防止するためにはコマンドとクエリからデータを常に分けておくことが必要です:

-   推奨される選択肢は安全なAPIを使用すること。インタープリタの使用を完全に避ける、パラメータ化されたインターフェースを利用する、または、オブジェクト・リレーショナル・マッピング・ツール（ORM）を使用するように移行すること。<br/>
    **注意:** パラメータ化されていたとしても、ストアドプロシージャでは、PL/SQLまたはT-SQLによってクエリとデータを連結したり、EXECUTE IMMEDIATEやexec()を利用して悪意のあるデータを実行することによって、SQLインジェクションを発生させることができる。

-   ポジティブな、言い換えると「ホワイトリスト」によるサーバーサイドの入力検証を用いる。特殊文字を必要とする多くのアプリケーション、たとえばモバイルアプリケーション用のテキスト領域やAPIなどにおいては完全な防御方法とはならない。

-   上記の対応が困難な動的クエリでは、そのインタープリタ固有のエスケープ構文を使用して特殊文字をエスケープする。</br>
    **注意:** テーブル名やカラム名などのSQLストラクチャに対してはエスケープができない。そのため、ユーザ指定のストラクチャ名は危険である。これはレポート作成ソフトウェアに存在する一般的な問題である。

-   クエリ内でLIMIT句やその他のSQL制御を使用することで、SQLインジェクション攻撃が発生した場合のレコードの大量漏洩を防ぐ。

## 攻撃シナリオの例

**シナリオ #1**: あるアプリケーションは信頼できないデータを用いることで以下のような脆弱なSQL呼び出しを作ってしまいます。
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

**シナリオ #2**: 同様に、アプリケーションがフレームワークを盲信すると、脆弱性のあるクエリになりえます (例えば、Hibernateクエリ言語(HQL)):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

これら両方のケースにおいて、攻撃者はブラウザでパラメータ'id'の値を' UNION SELECT SLEEP(10);--に変更します。例えば:

```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

これで、両方のクエリの意味が変えられ、accountsテーブルにあるレコードが全て返されることになります。さらなる攻撃により、データの改ざんや削除、ストアドプロシージャの呼び出しが可能です。

## 参考資料

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## 対応する CWE のリスト

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)

# A03:2021 – Injection    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 7.25                 | 7.15                | 94.04%       | 47.90%       | 274,228           | 32,078     |

## Overview

Injection slides down to the third position. 94% of the applications
were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3%, and 274k occurances. Notable Common Weakness Enumerations (CWEs) included are
*CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, and *CWE-73:
External Control of File Name or Path*.

## Description

An application is vulnerable to attack when:

-   User-supplied data is not validated, filtered, or sanitized by the
    application.

-   Dynamic queries or non-parameterized calls without context-aware
    escaping are used directly in the interpreter.

-   Hostile data is used within object-relational mapping (ORM) search
    parameters to extract additional, sensitive records.

-   Hostile data is directly used or concatenated. The SQL or command
    contains the structure and malicious data in dynamic queries,
    commands, or stored procedures.

Some of the more common injections are SQL, NoSQL, OS command, Object
Relational Mapping (ORM), LDAP, and Expression Language (EL) or Object
Graph Navigation Library (OGNL) injection. The concept is identical
among all interpreters. Source code review is the best method of
detecting if applications are vulnerable to injections. Automated
testing of all parameters, headers, URL, cookies, JSON, SOAP, and XML
data inputs is strongly encouraged. Organizations can include
static (SAST), dynamic (DAST), and interactive (IAST) application security testing tools into the CI/CD
pipeline to identify introduced injection flaws before production
deployment.

## How to Prevent

Preventing injection requires keeping data separate from commands and queries:

-   The preferred option is to use a safe API, which avoids using the
    interpreter entirely, provides a parameterized interface, or
    migrates to Object Relational Mapping Tools (ORMs).<br/>
    **Note:** Even when parameterized, stored procedures can still introduce
    SQL injection if PL/SQL or T-SQL concatenates queries and data or
    executes hostile data with EXECUTE IMMEDIATE or exec().

-   Use positive server-side input validation. This is
    not a complete defense as many applications require special
    characters, such as text areas or APIs for mobile applications.

-   For any residual dynamic queries, escape special characters using
    the specific escape syntax for that interpreter.<br/>
    **Note:** SQL structures such as table names, column names, and so on
    cannot be escaped, and thus user-supplied structure names are
    dangerous. This is a common issue in report-writing software.

-   Use LIMIT and other SQL controls within queries to prevent mass
    disclosure of records in case of SQL injection.

## Example Attack Scenarios

**Scenario #1:** An application uses untrusted data in the construction
of the following vulnerable SQL call:
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Scenario #2:** Similarly, an application’s blind trust in frameworks
may result in queries that are still vulnerable, (e.g., Hibernate Query
Language (HQL)):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

In both cases, the attacker modifies the ‘id’ parameter value in their
browser to send: ' UNION SLEEP(10);--. For example:
```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

This changes the meaning of both queries to return all the records from
the accounts table. More dangerous attacks could modify or delete data
or even invoke stored procedures.

## References

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## List of Mapped CWEs

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
