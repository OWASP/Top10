# A05:2021 – 安全設定缺陷

## 弱點因素(Factors)

| 可對照CWEs數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權引響 | 出現次數 | 所有相關 CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 89.58%       | 44.84%       | 8.12                 | 6.56                | 208,387           | 789        |

## 弱點簡介(Overview)

Moving up from #6 in the previous edition, 90% of applications were
tested for some form of misconfiguration. With more shifts into highly
configurable software, it's not surprising to see this category move up.
Notable CWEs included are *CWE-16 Configuration* and *CWE-611 Improper
Restriction of XML External Entity Reference*.

從先前版本的第六名排名，向上調升，90%的程式都被測試找出各類的設定缺陷。隨著越來越多的可設定式軟體數量增加，看到此類別的排名上升，並不是件意外的事。明顯相對應的CWEs包含了 *CWE16 設定* 以及 *CWE-611 不充足的XML外部實體引用限制*

## 弱點描述(Description)

The application might be vulnerable if the application is:
如果程式包含了以下幾個因素，則可能有易受攻擊的脆弱性。

-   Missing appropriate security hardening across any part of the
    application stack or improperly configured permissions on cloud
    services.

-   在程式各堆疊層面，缺少適切的安全強化，或是於雲端服務上有著不當的權限設定。

-   Unnecessary features are enabled or installed (e.g., unnecessary
    ports, services, pages, accounts, or privileges).

-   不必要的功能啟用或是安裝 (例如，不必要的端口，服務，頁面，帳號，或是特權)。

-   Default accounts and their passwords are still enabled and
    unchanged.

-   預設帳號與密碼還可使用，並且未更改。

-   Error handling reveals stack traces or other overly informative
    error messages to users.

-   因錯誤處理而暴露出的堆疊追蹤，或是向使用者，暴露出過多的錯誤警告資訊

-   For upgraded systems, the latest security features are disabled or
    not configured securely.

-   因為系統升級，導致最新的安全功能被關閉，或是造成不安全的設定

-   The security settings in the application servers, application
    frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases,
    etc., are not set to secure values.

-   在佈署程式的伺服器，程式框架(例如Struts, Spring, ASP net，各種函示庫，資料庫等。並未設定該有的安全參數。 

-   The server does not send security headers or directives, or they are
    not set to secure values.

-   伺服器並未傳送安全的標頭或是指令，或未被設定安全參數。

-   The software is out of date or vulnerable (see A06:2021-Vulnerable
    and Outdated Components).

-   軟體已經過時已淘汰，或者帶有脆弱性 (請參照 A06:2021-易受攻擊和已淘汰的組件 )


Without a concerted, repeatable application security configuration
process, systems are at a higher risk.
當沒有一個一致性，可重複的程式安全設定流程時，系統將會面對高風險。

## 如何預防(How to Prevent)

Secure installation processes should be implemented, including:
安全的安裝步驟流程，應該被實際佈署，包含以下

-   A repeatable hardening process makes it fast and easy to deploy
    another environment that is appropriately locked down. Development,
    QA, and production environments should all be configured
    identically, with different credentials used in each environment.
    This process should be automated to minimize the effort required to
    set up a new secure environment.

-   一個可重複的安全強化流程，必需可達到快速且簡單的佈署，而且能在分隔且封鎖的環境下執行。開發，品質管理，以及實際營運的環境，都須有一致相同的設定，並且使用不同的認證資訊。這種步驟需要盡可能的自動化，降低需要建立安全環境時，所需要的投入。

-   A minimal platform without any unnecessary features, components,
    documentation, and samples. Remove or do not install unused features
    and frameworks.

-   一個最精簡的平台，上面不會搭配任何不需要的功能，套件，檔案，以及範本。移除或不安裝任何，不須使用的功能或框架。

-   A task to review and update the configurations appropriate to all
    security notes, updates, and patches as part of the patch management
    process (see A06:2021-Vulnerable and Outdated Components). Review
    cloud storage permissions (e.g., S3 bucket permissions).

-   在變更管理下，需有特定的任務，依據安全告知，相關更新，來執行安全審視及更動(可參照 A06:2021-易受攻擊和已淘汰的組件)。審視雲端儲存的權限(例如 S3 bucket的權限)

-   A segmented application architecture provides effective and secure
    separation between components or tenants, with segmentation,
    containerization, or cloud security groups (ACLs).

-   一個可分割的程式架構，對於各元件，用戶，可透過分離，容器化，雲端安全群組設定(ACLs)，來達到分割的效果。提供有效且安全的分離。

-   Sending security directives to clients, e.g., Security Headers.

-   寄送安全指令給用戶端，例如 安全標頭。

-   An automated process to verify the effectiveness of the
    configurations and settings in all environments.

-   一個自動化的流程，可以確認環境中各類的安全設定。

## 攻擊情境範例(Example Attack Scenarios)

**Scenario #1:** The application server comes with sample applications
not removed from the production server. These sample applications have
known security flaws attackers use to compromise the server. Suppose one
of these applications is the admin console, and default accounts weren't
changed. In that case, the attacker logs in with default passwords and
takes over.

**情境 #1:** 營運用的程式伺服器，帶有預設的樣本程式，並未移除。這個樣本程式帶有已知的安全缺陷，可被攻擊者利用入侵伺服器。例如，預設的程式帶有管理者介面，並且有未變更的帳號，攻擊者可以透過預設的密碼登入，並取得控制權。

**Scenario #2:** Directory listing is not disabled on the server. An
attacker discovers they can simply list directories. The attacker finds
and downloads the compiled Java classes, which they decompile and
reverse engineer to view the code. The attacker then finds a severe
access control flaw in the application.

**情境 #2:** 資料夾列表指令並未在伺服器上關閉。攻擊者可以找出並且下載，已編譯過Java檔案，並且透過反編譯與逆向工程等手法，查看原始碼。再因此找出程式中，嚴重的存取控制缺陷。

**Scenario #3:** The application server's configuration allows detailed
error messages, e.g., stack traces, to be returned to users. This
potentially exposes sensitive information or underlying flaws such as
component versions that are known to be vulnerable.

**情境 #3:** 程式伺服器的設定，勻許輸出帶有詳細內容的錯誤訊息，例如堆疊追蹤，供用戶查看。這有可能導致敏感訊息的外洩，或間接透露出，使用中，並帶有脆弱性的元件版本。

**Scenario #4:** A cloud service provider has default sharing
permissions open to the Internet by other CSP users. This allows
sensitive data stored within cloud storage to be accessed.

**情境 #4:** 一個雲端伺服器，提供了預設權限分享，給其他在網際網路的CSP用戶。這將導致雲端儲存的敏感資料可以被存取。

## References

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP 測試指南: 設定管理](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   OWASP Testing Guide: Testing for Error Codes

-   OWASP 測試指南: 錯誤代碼測試

-   Application Security Verification Standard V19 Configuration

-   應用程式安全確認標準 v19 設定篇

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [NIST 泛用伺服器強化指南](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [CIS 安全設定指南/基準](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

-   [Amazon S3 儲存貯體偵測與探索](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## 對應的CWEs清單(List of Mapped CWEs)

CWE-2 Configuration

CWE-2 設定

CWE-11 ASP.NET Misconfiguration: Creating Debug Binary

CWE-11 ASP.NET 錯誤設定:創建除錯二進制檔 

CWE-13 ASP.NET Misconfiguration: Password in Configuration File

CWE-13 ASP.NET 錯誤設定: 設定檔中所存的密碼

CWE-15 External Control of System or Configuration Setting

CWE-15 系統的外部控制與設定

CWE-16 Configuration

CWE-16 設定

CWE-260 Password in Configuration File

CWE-260 設定檔中所存的密碼

CWE-315 Cleartext Storage of Sensitive Information in a Cookie

CWE-315 cookies中的明文存放敏感資料 

CWE-520 .NET Misconfiguration: Use of Impersonation

CWE-520 .NET 錯誤設定: 冒充使用

CWE-526 Exposure of Sensitive Information Through Environmental
Variables

CWE-526 環境物件所洩漏的敏感資訊

CWE-537 Java Runtime Error Message Containing Sensitive Information

CWE-537 Java運行環境下，錯誤訊息包含敏感資訊

CWE-541 Inclusion of Sensitive Information in an Include File

CWE-541 包容檔案中，包含敏感資訊

CWE-547 Use of Hard-coded, Security-relevant Constants

CWE-547 使用寫死的安全相關參數

CWE-611 Improper Restriction of XML External Entity Reference

CWE-611 不充足的XML外部實體引用限制

CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

CWE-614 HTTPS下，敏感Cookies沒有使用"安全"參數設定 

CWE-756 Missing Custom Error Page

CWE-756 遺漏客制的錯誤頁面

CWE-776 Improper Restriction of Recursive Entity References in DTDs
('XML Entity Expansion')

CWE-776 DTDs中，不充足的遞迴物件引用限制
(XML 物件擴張)

CWE-942 Permissive Cross-domain Policy with Untrusted Domains

CWE-942 跨網域白名單的過度權限

CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

CWE-1004 敏感Cookie沒有使用'HttpOnly'參數設定

CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration

CWE-1032 OWASP 2017 前十大 A6群組 - 安全錯誤設定

CWE-1174 ASP.NET Misconfiguration: Improper Model Validation

CWE-1174 ASP.NET 錯誤設定: 不充足的模組驗證