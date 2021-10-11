# A06:2021 – 易受攻擊和已淘汰的組件(Vulnerable and Outdated Components)

## 弱點因素(Factors)

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |



## 弱點簡介

此弱點在產業調查中排名第二，但有足夠的資料讓它進入前十。
易受攻擊的組件是我們努力測試和評估風險的已知問題，該弱點是在 CWEs 中唯一沒有任何 CVE 對應的類別，因此使用預設的 5.0 漏洞利用/影響權重。
知名的 CWEs包括： 
*CWE-1104：使用未維護的第三方組件 以及兩個 2013 年度、2017 年度 前 10 名的 CWEs。

## 弱點描述

您可能容易受到攻擊：

-   如果您不知道您使用的所有組件的版本（用戶端和伺服器端）。 這包括您直接使用的組件以及嵌入的相依套件(nested dependencies)。

-   如果軟體容易受到攻擊、已不支援或已淘汰。 
    包括作業系統、網頁/應用程式伺服器、資料庫管理系統 (DBMS)、應用程式、 API 以及所有組件、執行環境和程式庫(libraries)。

-   如果您沒有定期執行弱點掃瞄並訂閱與您使用組件相關的資安通報。

-   如果您未憑藉基於風險的方式及時修補或升級底層平台、框架和相依套件。 
    這通常發生在修補工作是變更控制下的每月或每季度任務的環境中，會使組織數天甚至數月不必要地暴露於可修補的漏洞風險。
    
-   如果軟體開發人員未測試更新、升級或修補後程式庫的相容性。

-   如果你未保護組件的設定檔案。（請參閱 A05:2021 - 安全設定缺陷 Security Misconfiguration）。

## 如何預防(How to Prevent)
應該設置修補程式管理流程來：

-   刪除未使用的相依套件、不必要的功能、組件、檔案及文件。


-   持續使用版控工具來盤點客戶端和伺服器端組件（例如框架、程式庫）及相依組件的版本，如版控工具、OWASP Dependency Check、retire.js 等。
    持續監控 CVE 和 NVD 等等來源來確認是組件是否存在的漏洞。使用軟體組合分析工具來自動化該流程。 
    訂閱您使用的組件相關的安全漏洞的資安通報。
    
-   持續盤點客戶端和伺服器端組件（例如框架、程式庫）及相依組件的版本，如版控工具、OWASP Dependency Check、retire.js 等。
    持續監控 CVE 和 NVD 等等來源來確認是組件是否存在的漏洞。
    使用軟體組合分析工具來自動化該流程。 
    訂閱您使用的組件相關的安全漏洞的資安通報。
    使用諸如版控工具、OWASP Dependency Check、retire.js 等工具持續盤點客戶端和服務器端組件（例如框架、程式庫）及其相依組件的版本。
    
-   僅透過官方提供的安全連結來取得組件。
    優先選擇已簽署的更新包，以降低更新包被加入惡意組件的可能。（請參閱 A08:2021-軟體及資料完整性失效）。

-   監控未維護或未為舊版本創建安全修補程式的程式庫和組件。
    如果無法修補程式，請考慮部署虛擬修補程式來監控、檢測或防禦已發現的特定弱點。

每個組織都必須確保在應用程式或開發專案(portfolio)的生命週期內制訂持續監控、鑒別分類(triaging) 及 申請更新 或是 更改配置的計劃。


## 攻擊情境範例(Example Attack Scenarios)

**情境 #1：** 組件通常以與應用程式本身相同的權限運行，因此任何組件中的缺陷都可能導致嚴重的影響。 
此類缺陷可能是偶然的（例如，編碼錯誤）或有意的（例如，組件中的後門）。 
一些已知易受攻擊組件的範例為：

-   CVE-2017-5638：一個 Struts 2 遠端程式碼執行漏洞，可以在伺服器上執行任意代碼，已被歸咎於重大漏洞。

-   雖然物聯網 (IoT) 設備通常很難或無法修補，但修補它們可能有很高的重要性。（例如，生物醫學設備）。

有一些自動化工具可以幫助攻擊者找到未修補或配置錯誤的系統。 例如，Shodan IoT 搜索引擎可以幫助您找到存在 2014 年 4 月未修補 Heartbleed 漏洞的設備。


## 參考文獻(References)

-   OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling

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
