# A03:2021 – 注入式攻擊

## 對照因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權弱點 | 平均加權影響 | 出現次數 | 所有有關 CVEs 數量|
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 94.04%       | 47.90%       | 7.25                 | 7.15                | 274,228           | 32,078     |

## 概述

植入式攻擊下滑到了第三名。94% 被測試的應用程式都有驗測到某種類型的注入式攻擊問題。值得注意的 CWEs 包括了 CWE-79：跨網站攻擊、CWE-89：SQL 注入式攻擊以及 CWE-73：在外部控制檔案名稱或路徑。 

## 描述 

應用程式在以下情況容易遭受攻擊：

-   應用程式未驗證、過濾或清理使用者提供的資料。

-   在直譯器中未使用上下文感知轉義的動態查詢或無參數呼叫。

-   在物件關係對映 (ORM) 的搜尋參數中，使用惡意的資料來提取額外的敏感紀錄。

-   在動態查詢、命令或儲存的程序，SQL、指令或儲存的程序中，直接使用或連結了惡意資料。

一些常見的注入式攻擊是 SQL、NoSQL、OS 指令、物件關係對映 (ORM)、LDAP以及表達式語言 (EL) 或對象導航圖語言 (OGNL) 注入。這個概念在所有的直譯器都是相同的。假若應用程式存在注入式攻擊的弱點，源碼檢測是最好的方式。強烈建議對所有輸入的參數、標頭、URL、cookies、JSON、SOAP 以及 XML 的資料進行自動化測試。組織可以將靜態源碼測試 (SAST) 以及動態應用程式檢測 (DAST) 工具，包含到持續整合與持續部署 (CI/CD)管道中，以達成在上線部署前能識別注入攻擊的缺陷。

## 如何預防

-   需要將命令與查詢資料分開，以防止注入式攻擊。

-   首要的選項是使用安全的應用程式界面 (API)，完全避免使用直譯器，以提供參數化的界面或整合到物件關係對映 (ORMs) 工具中。

-   注意：即使已經參數化了，在儲存的程序中仍然可以引入 SQL 注入攻擊，如果透過 PL/SQL 或 T-SQL 連接查詢與資料，並使用 EXECUTE IMMEDIATE 或 exec() 執行惡意資料。

-   使用正面或白名單在伺服器端驗證輸入的資料。這並不是一個完整的防禦機制，因許多應用程序需要使用特殊的字符，例如：應用程式的文本區域或應用程式界面 (API)應用於行動裝置上的應用程式。

-   對於任何剩餘的動態查詢，在轉譯中使用特殊符號進行查詢將對查詢語法帶來不同的涵義。

-   注意：在 SQL 結構中，例如：資料表名稱、欄位名稱是無法被轉譯的，因此使用者提供資料結構的名稱是危險的，這是一個在編寫軟體時常見的問題。

-   在查詢中使用 LIMIT 以及其它的 SQL 控制器，可以防止當遭受 SQL 注入式攻擊時被大量洩露紀錄。

## 攻擊情境範例

**情境 #1:** 應用程式使用了不被信任的資料在脆弱的 SQL 呼叫中：

String query = "SELECT \* FROM accounts WHERE custID='" +
request.getParameter("id") + "'";

**情境 #2:** 類似地，應用程式對框架的盲目信任，可能導致仍然在漏洞的查詢，(例如：Hibernate 查詢語言 (HQL))： 

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" +
> request.getParameter("id") + "'");

在這兩個情境中，攻擊者在他們的瀏覽器修改了 "id" 參數值，送出 ‘ or ‘1’=’1，例如：

http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--

這兩個查詢的含義將產生改變，而回應所有帳戶資料表中的紀錄，更危險的攻擊將可能修改或刪除資料，以及影響資料的儲存過程。

## 參考

-   [OWASP Proactive Controls: Secure Database
    Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and
    Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL
    Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in
    Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query
    Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications –
    OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template
    injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## 對應的 CWE 列表

CWE-20 Improper Input Validation

CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')

CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)

CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')

CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')

CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')

CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)

CWE-83 Improper Neutralization of Script in Attributes in a Web Page

CWE-87 Improper Neutralization of Alternate XSS Syntax

CWE-88 Improper Neutralization of Argument Delimiters in a Command
('Argument Injection')

CWE-89 Improper Neutralization of Special Elements used in an SQL
Command ('SQL Injection')

CWE-90 Improper Neutralization of Special Elements used in an LDAP Query
('LDAP Injection')

CWE-91 XML Injection (aka Blind XPath Injection)

CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')

CWE-94 Improper Control of Generation of Code ('Code Injection')

CWE-95 Improper Neutralization of Directives in Dynamically Evaluated
Code ('Eval Injection')

CWE-96 Improper Neutralization of Directives in Statically Saved Code
('Static Code Injection')

CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a
Web Page

CWE-98 Improper Control of Filename for Include/Require Statement in PHP
Program ('PHP Remote File Inclusion')

CWE-99 Improper Control of Resource Identifiers ('Resource Injection')

CWE-100 Deprecated: Was catch-all for input validation issues

CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP
Response Splitting')

CWE-116 Improper Encoding or Escaping of Output

CWE-138 Improper Neutralization of Special Elements

CWE-184 Incomplete List of Disallowed Inputs

CWE-470 Use of Externally-Controlled Input to Select Classes or Code
('Unsafe Reflection')

CWE-471 Modification of Assumed-Immutable Data (MAID)

CWE-564 SQL Injection: Hibernate

CWE-610 Externally Controlled Reference to a Resource in Another Sphere

CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath
Injection')

CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax

CWE-652 Improper Neutralization of Data within XQuery Expressions
('XQuery Injection')

CWE-917 Improper Neutralization of Special Elements used in an
Expression Language Statement ('Expression Language Injection')
