# A08:2021 – Software and Data Integrity Failures

## Factors
# 弱點因素

| 對應的 CWEs數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 相關 CVEs 總量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 75.04%       | 45.35%       | 6.94                 | 7.94                | 47,972            | 1,152      |

## Overview
## 弱點簡介

A new category for 2021 focuses on making assumptions related to
software updates, critical data, and CI/CD pipelines without verifying
integrity. One of the highest weighted impacts from CVE/CVSS data.
Notable CWEs include *CWE-502: Deserialization of Untrusted Data*,
*CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, and
*CWE-494: Download of Code Without Integrity Check*.

這是2021年的新類型，著重在軟體更新，關鍵資料及持續性整合/部署(CI/CD)流程未經完整性驗證之假設。同時在CVE/CVSS資料加權後之最高影響之一。值得注意的CWE包含CWE-502：不受信任資料之反序列化，CWE-829：包含來自不受信任控制領域之功能及CWE-494：下載未經完整性驗證之程式碼。

## Description 
## 弱點描述

Software and data integrity failures relate to code and infrastructure
that does not protect against integrity violations. For example, where
objects or data are encoded or serialized into a structure that an
attacker can see and modify is vulnerable to insecure deserialization.
Another form of this is where an application relies upon plugins,
libraries, or modules from untrusted sources, repositories, and content
delivery networks (CDNs). An insecure CI/CD pipeline can introduce the
potential for unauthorized access, malicious code, or system compromise.
Lastly, many applications now include auto-update functionality, where
updates are downloaded without sufficient integrity verification and
applied to the previously trusted application. Attackers could
potentially upload their own updates to be distributed and run on all
installations.

程式碼或基礎架構未能保護軟體及資料之完整性受到破壞。舉例來說，物件或資料經編碼或序列化到一個對攻擊者可讀寫之結構中將導致不安全的反序列化。另一種形式則是應用程式依賴來自於不受信任來源，典藏庫及內容遞送網路之外掛，函式庫或模組。不安全的持續性整合/部署(CI/CD)流程則會造成潛在的未經授權存取，惡意程式碼或系統破壞。最後，現在許多應用程式擁有自動更新功能，但自動更新功能在缺乏充足完整性驗證功能時就下載並安裝更新到處於安全狀態下的應用程式。攻擊者能上傳自製更新檔案，更新檔案將傳播到所有已安裝之應用程式並在這些應用程式上執行。

## How to Prevent
## 弱點描述

-   Ensure that unsigned or unencrypted serialized data is not sent to
    untrusted clients without some form of integrity check or digital
    signature to detect tampering or replay of the serialized data
    
- 確保不受信任之客戶端不會收到未簽署或加密之序列化資料並利用完整性檢查或數位簽章來偵測竄改或重放攻擊。

-   Verify the software or data is from the expected source via signing
    or similar mechanisms
    
- 利用數位簽章或類似機制確保軟體或資料來自預期之提供者

-   Ensure libraries and dependencies, such as npm or Maven, are
    consuming trusted repositories
    
- 確保函式庫及從屬套件，例如npm或Maven，是從受信任的典藏庫取得。

-   Ensure that a software supply chain security tool, such as OWASP
    Dependency Check or OWASP CycloneDX, is used to verify that
    components do not contain known vulnerabilities
    
- 使用軟體供應鏈安全工具(例如OWASP Dependency Check 或 OWASP CycloneDX)確保元件沒有已知弱點。

-   Ensure that your CI/CD pipeline has proper configuration and access
    control to ensure the integrity of the code flowing through the
    build and deploy processes.
    
- 適當地設定持續性整合/部署(CI/CD)流程的組態及存取控制以確保程式碼在組建及部署流程中的完整性。

## Example Attack Scenarios
## 攻擊情境範例

**Scenario #1 Insecure Deserialization:** A React application calls a
set of Spring Boot microservices. Being functional programmers, they
tried to ensure that their code is immutable. The solution they came up
with is serializing the user state and passing it back and forth with
each request. An attacker notices the "R00" Java object signature and
uses the Java Serial Killer tool to gain remote code execution on the
application server.

情境1 不安全的反序列化：一個反應式應用程式呼叫Spring Boot微服務。程式設計師們試圖確保他們的代碼是不可變的。他們的解決方案是在雙向所有請求訊息中包含序列化的用戶狀態。攻擊者注意到“R00”Java物件簽章並使用 Java Serial Killer 工具(用來執行Java反序列化攻擊)在應用程式伺服器遠端執行程式碼。

**Scenario #2 Update without signing:** Many home routers, set-top
boxes, device firmware, and others do not verify updates via signed
firmware. Unsigned firmware is a growing target for attackers and is
expected to only get worse. This is a major concern as many times there
is no mechanism to remediate other than to fix in a future version and
wait for previous versions to age out.

情境2 未簽署之更新：許多家用路由器、機上盒、裝置韌體等未以通過簽署之韌體驗證更新檔案。未簽署韌體是越來越多攻擊者的目標且情況只會變得更糟。這是一個主要問題，因為只能以新版本修復此機制並期待舊版本自然淘汰，沒有其他方法。

**Scenario #3 SolarWinds malicious update**: Nation-states have been
known to attack update mechanisms, with a recent notable attack being
the SolarWinds Orion attack. The company that develops the software had
secure build and update integrity processes. Still, these were able to
be subverted, and for several months, the firm distributed a highly
targeted malicious update to more than 18,000 organizations, of which
around 100 or so were affected. This is one of the most far-reaching and
most significant breaches of this nature in history.

情境3 SolarWinds 惡意更新：眾所周知，某些國家會攻擊更新機制，最近一次值得注意的是對SolarWinds Orion的攻擊。該軟體開發商擁有安全組建和更新完整性流程。儘管如此，這些流程仍被破壞並在幾個月時間中向 18,000 多個組織送出高度針對性的惡意更新，其中大約 100 個組織受到了影響。 這是歷史上此類性質最深遠、最重大的資安事件之一。

## References
## 參考文獻

-   \[OWASP Cheat Sheet: Deserialization\](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   \[OWASP Cheat Sheet: Software Supply Chain Security\]()

-   \[OWASP Cheat Sheet: Secure build and deployment\]()

-   \[SAFECode Software Integrity Controls\](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   \[A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack\](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   <https://www.manning.com/books/securing-devops>

## List of Mapped CWEs
## 對應的 CWEs 清單

CWE-345 Insufficient Verification of Data Authenticity

CWE-345 不足的資料真實性驗證

CWE-353 Missing Support for Integrity Check

CWE-353 缺乏對完整性確認之支援

CWE-426 Untrusted Search Path

CWE-426 不受信任的搜尋路徑

CWE-494 Download of Code Without Integrity Check

CWE-494 下載未經完整性驗證之程式碼

CWE-502 Deserialization of Untrusted Data

CWE-502 不受信任資料之反序列化

CWE-565 Reliance on Cookies without Validation and Integrity Checking

CWE-565 信任未經驗證及完整性確認的Cookies

CWE-784 Reliance on Cookies without Validation and Integrity Checking in
a Security Decision

CWE-784 在安全性決策中信任未經驗證及完整性確認的Cookies

CWE-829 Inclusion of Functionality from Untrusted Control Sphere

CWE-829 包含來自不受信任控制領域之功能

CWE-830 Inclusion of Web Functionality from an Untrusted Source

CWE-830 包含來自不受信任控制來源之網頁功能

CWE-915 Improperly Controlled Modification of Dynamically-Determined
Object Attributes

CWE-915 動態決定物件屬性於不當控制下之修改
