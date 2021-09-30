# A06:2021 – 易受攻擊和已淘汰的組件(Vulnerable and Outdated Components)

## 弱點因素(Factors)

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |



## 弱點簡介

此弱點在產業調查中排名第二，但也有足夠的統計資料讓它可以進入前十。 
易受攻擊的組件是一個已知問題，我們極難做測試和評估的風險的類，而且該弱點是在 CWEs 中唯一沒有任何 CVE 對應的類別，
著名的 CWEs 包含：
*CWE-1104：Use of Unmaintained Third-Party Components* 以及兩個 2013 年度、2017 年度 TOP 10 CWEs。


## 弱點描述

您可能容易受到攻擊：

-   如果您並不知道您使用的所有組件的版本（含用戶端和伺服器端）。 這包括您直接使用的組件以及嵌入的相依套件。

-   If the software is vulnerable, unsupported, or out of date. This
    includes the OS, web/application server, database management system
    (DBMS), applications, APIs and all components, runtime environments,
    and libraries.

-   如果軟體容易受到攻擊、已不支援或已淘汰。
    包括作業系統、網頁/應用程式伺服器、資料庫管理系統 (DBMS)、應用程式、API 以及所有組件、執行環境和程式庫(libraries)。

-   If you do not scan for vulnerabilities regularly and subscribe to
    security bulletins related to the components you use.

-   如果您並沒有定期：執行弱點掃瞄以及訂閱與您使用組件相關的資安通報。

-   If you do not fix or upgrade the underlying platform, frameworks,
    and dependencies in a risk-based, timely fashion. This commonly
    happens in environments when patching is a monthly or quarterly task
    under change control, leaving organizations open to days or months
    of unnecessary exposure to fixed vulnerabilities.

-   如果您不及時修補或更新底層平台、框架和存在風險的相依套件。
    這通常發生在變更管理預計下個月或每季度更新時，已修復漏洞更新未上版的空窗期，會使組織面臨數天或數月不必要地暴露於的風險。

-   If software developers do not test the compatibility of updated,
    upgraded, or patched libraries.
-   如果軟體開發人員未測試更新、升級或修補的程式庫的相容性。

-   If you do not secure the components’ configurations (see
    A05:2021-Security Misconfiguration).
-   如果你未安全設定組件的設置檔案。（請參閱 A05:2021-安全設定缺陷 Security Misconfiguration）。

## 如何預防(How to Prevent)

There should be a patch management process in place to:
應該設置修補程式(patch)的上版流程：

-   Remove unused dependencies, unnecessary features, components, files,
    and documentation.
-   刪除未使用的相依套件、不必要的功能、組件、檔案及文件。


-   Continuously inventory the versions of both client-side and
    server-side components (e.g., frameworks, libraries) and their
	@@ -58,71 +80,108 @@ There should be a patch management process in place to:
    vulnerabilities in the components. Use software composition analysis
    tools to automate the process. Subscribe to email alerts for
    security vulnerabilities related to components you use.
-   持續使用版控工具來盤點客戶端和伺服器端組件（例如框架、程式庫）及相依組件的版本，如版控工具、OWASP Dependency Check、retire.js 等。
    持續監控 CVE 和 NVD 等等來源來確認是組件是否存在的漏洞。使用軟體組合分析工具來自動化該流程。 
    訂閱您使用的組件相關的安全漏洞的資安通報。

-   Only obtain components from official sources over secure links.
    Prefer signed packages to reduce the chance of including a modified,
    malicious component (See A08:2021-Software and Data Integrity
    Failures).
-   僅透過官方提供的安全連結來取得組件。
-   優先選擇已簽署的更新包，以降低更新包被加入惡意組件的可能。（請參閱 A08:2021-軟體及資料完整性失效）。

-   Monitor for libraries and components that are unmaintained or do not
    create security patches for older versions. If patching is not
    possible, consider deploying a virtual patch to monitor, detect, or
    protect against the discovered issue.
-   監控程式庫及組件是否未維護或為舊版程式未更新安全修複程式。
    如果無法更新版本，請考慮部署虛擬修復程式來監控、檢測或防禦已發現的特定弱點。

Every organization must ensure an ongoing plan for monitoring, triaging,
and applying updates or configuration changes for the lifetime of the
application or portfolio.

每個組織都必須確保在應用程式或開發專案(portfolio)的生命週期內制訂持續監控、鑒別分類(triaging)及 申請更新 或是 更改配置的計劃。


## 攻擊情境範例(Example Attack Scenarios)

**Scenario #1:** Components typically run with the same privileges as
the application itself, so flaws in any component can result in serious
impact. Such flaws can be accidental (e.g., coding error) or intentional
(e.g., a backdoor in a component). Some example exploitable component
vulnerabilities discovered are:

**情境 #1：** 組件通常以與應用程式本身相同的權限運行，因此任何組件中的缺陷都可能導致嚴重的影響。
此類缺陷可能是偶然的（例如，編碼錯誤）或有意的（例如，組件中的後門）。
常見易受攻擊組件的範例：

-   CVE-2017-5638, a Struts 2 remote code execution vulnerability that
    enables the execution of arbitrary code on the server, has been
    blamed for significant breaches.
-   CVE-2017-5638：一個 Struts 2 遠端程式碼執行漏洞，可以在伺服器上執行任意代碼，已被歸咎於重大漏洞。

-   While the internet of things (IoT) is frequently difficult or
    impossible to patch, the importance of patching them can be great
    (e.g., biomedical devices).
-   雖然物聯網 (IoT) 通常很難或不可能修補，但它們可能有很高的重要性。（例如，生物醫學設備）。

There are automated tools to help attackers find unpatched or
misconfigured systems. For example, the Shodan IoT search engine can
help you find devices that still suffer from Heartbleed vulnerability
patched in April 2014.
有一些自動化工具可以幫助攻擊者找到未打補丁或配置錯誤的系統。 例如，Shodan IoT 搜索引擎可以幫助您找到存在 2014 年 4 月未修補 Heartbleed 漏洞的設備。


## 參考文獻(References)

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search
-   
-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## 對應的 CWEs 清單(List of Mapped CWEs)

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components