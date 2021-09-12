# A01:2021 – 權限控制失效


## 對照因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 |最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 94.55%       | 47.72%       | 6.92                 | 5.93                | 318,487           | 19,013     |

## 概述

Moving up from the fifth position, 94% of applications were tested for
some form of broken access control. Notable CWEs included are *CWE-200:
Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201:
Exposure of Sensitive Information Through Sent Data*, and *CWE-352:
Cross-Site Request Forgery*.

從第五名晋升，94% 的應用程式都對中斷的存取控制進行了某種形式的測試。著名
的 CWE 包括 *CWE-200：將敏感信息暴露給未經授權的演員*，*CWE-201：通過發送數據*
和 *CWE-352暴露敏感信息：跨站請求偽造*。

## Description, 描述 

Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data or
performing a business function outside the user's limits. Common access
control vulnerabilities include:

存取控制強化政策，使用戶不能在其預期權限之外採取行動。 故障通常會導致未經授權
的信息洩露、修改或破壞所有數據或執行超出用戶限制的業務功能。 常見的存取控制漏
洞包括：

-   Bypassing access control checks by modifying the URL, internal
    application state, or the HTML page, or simply using a custom API
    attack tool.
    通過修改 URL、內部應用程序狀態或 HTML 頁面，或僅使用自定義 API 攻擊工具來繞過存取控制檢查。

-   Allowing the primary key to be changed to another user's record,
    permitting viewing or editing someone else's account.
    容許主鍵被更改為其他用戶的記錄，允許查看或編輯其他人的帳戶。

-   Elevation of privilege. Acting as a user without being logged in or
    acting as an admin when logged in as a user.
    特權提升。 在未登入的情況下充當用戶或以用戶身份登入時充當管理員。

-   Metadata manipulation, such as replaying or tampering with a JSON
    Web Token (JWT) access control token, or a cookie or hidden field
    manipulated to elevate privileges or abusing JWT invalidation.
    中繼資料操作，例如重放或篡改 JSON Web 令牌 (JWT) 存取控制令牌，或 cookie
    或隱藏欄位被操縱以提升特權或濫用 JWT 失效。

-   CORS misconfiguration allows unauthorized API access.
    CORS 錯誤配置允許未經授權的 API 存取。

-   Force browsing to authenticated pages as an unauthenticated user or
    to privileged pages as a standard user. Accessing API with missing
    access controls for POST, PUT and DELETE.
    強制以未經身份驗證的用戶身份瀏覽經過身份驗證的頁面或以標準用戶身份存取特權頁面。 
    存取對 POST、PUT 和 DELETE 缺少存取控制的API。

## How to Prevent, 如何預防

Access control is only effective in trusted server-side code or
server-less API, where the attacker cannot modify the access control
check or metadata.
存取控制僅在受信任的服務器端代碼或無伺服器的API，攻擊者無法修改存取控制檢查或中繼資料。

-   Except for public resources, deny by default.
    除公開資源外，以拒絕為預設值。

-   Implement access control mechanisms once and re-use them throughout
    the application, including minimizing CORS usage.
    只實施一次存取控制機制，並在整個應用程式中重複使用它們，包括最大限度地減少 CORS 的使用。

-   Model access controls should enforce record ownership rather than
    accepting that the user can create, read, update, or delete any
    record.
    模型存取控制應該強化記錄所有權，而不是接受用戶可以創建、讀取、更新或刪除任何記錄。

-   Unique application business limit requirements should be enforced by
    domain models.
    獨特的應用程序業務限制要求應由領域模型強制執行。

-   Disable web server directory listing and ensure file metadata (e.g.,
    .git) and backup files are not present within web roots.
    停用 Web 服務器目錄列表，並確保文件中繼資料（例如，.git) 和備份文件不在 web 根目錄中。

-   Log access control failures, alert admins when appropriate (e.g.,
    repeated failures).
    記錄存取控制失敗，適時提醒管理員（例如，多次失敗）。

-   Rate limit API and controller access to minimize the harm from
    automated attack tooling.
    對 API 和控制器存取進行流量限制，將自動化攻擊工具所帶來的損害最小化。

-   JWT tokens should be invalidated on the server after logout.
    登出後，JWT 令牌在服務器應使其失效。

Developers and QA staff should include functional access control unit
and integration tests.
開發人員和 QA 人員應納入功能的存取控制之單元和整合測試。

## Example Attack Scenarios, 攻擊情境範例

**Scenario #1:** The application uses unverified data in a SQL call that
is accessing account information:

**情境 #1：** 應用程序在存取帳戶資訊的 SQL 呼叫中使用未經驗證的數據：

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

An attacker simply modifies the browser's 'acct' parameter to send
whatever account number they want. If not correctly verified, the
attacker can access any user's account.

攻擊者只需修改瀏覽器的“acct”參數即可發送他們想要的任何帳號。 如果沒有正確驗證，
攻擊者可以存取任何用戶的帳戶。

https://example.com/app/accountInfo?acct=notmyacct

**Scenario #2:** An attacker simply forces browses to target URLs. Admin
rights are required for access to the admin page.

**情境#2：** 攻擊者只是強迫瀏覽某些目標網址。 存取管理頁面需要管理員權限。

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

If an unauthenticated user can access either page, it's a flaw. If a
non-admin can access the admin page, this is a flaw.
如果未經身份驗證的用戶可以存取任一頁面，那就是一個缺陷。 如果一個非管理員可以存取管理頁面，這是一個缺陷。

## References

-   [OWASP Proactive Controls: Enforce Access Controls, OWASP主動控制：實施存取控制](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access Control, OWASP 應用安全驗證標準：V4 存取控制](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization Testing, OWASP 測試指南：授權測試](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control, OWASP 備忘單：存取控制]()

-   [PortSwigger: Exploiting CORS
    misconfiguration, PortSwigger：利用CORS的錯誤配置](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## List of Mapped CWEs, 對應的CWE列表

CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')
不當限制受限目錄的路徑名稱（路徑遍訪）

CWE-23 Relative Path Traversal
相對路徑遍訪

CWE-35 Path Traversal: '.../...//'
路徑遍訪: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')
檔案存取前不當的路徑解析 ('連結指向')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
將敏感信息曝露給未經授權的行為者

CWE-201 Exposure of Sensitive Information Through Sent Data
經由發送的資料曝露敏感資訊

CWE-219 Storage of File with Sensitive Data Under Web Root
在網站根目錄下存放敏感資料

CWE-264 Permissions, Privileges, and Access Controls (should no longer
be used)
權限、特權和存取控制（不應再使用）

CWE-275 Permission Issues
權限問題

CWE-276 Incorrect Default Permissions
不正確的預設權限

CWE-284 Improper Access Control
不當的存取控制

CWE-285 Improper Authorization
不當的授權

CWE-352 Cross-Site Request Forgery (CSRF)
跨站請求偽造 (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized
Actor
將私有的個人資訊曝露給未經授權的行為者

CWE-377 Insecure Temporary File
不安全的暫存檔案

CWE-402 Transmission of Private Resources into a New Sphere ('Resource
Leak')
私有資源輸入新領域（“資源洩漏”）

CWE-425 Direct Request ('Forced Browsing')
直接請求（“強制瀏覽”）

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')
意外代理或中介（“困惑的代理”）

CWE-497 Exposure of Sensitive System Information to an Unauthorized
Control Sphere
將敏感系統資訊曝露給未經授權的控制領域

CWE-538 Insertion of Sensitive Information into Externally-Accessible
File or Directory
將敏感信息插入外部可存取的檔案或目錄

CWE-540 Inclusion of Sensitive Information in Source Code
原始程式中包含敏感資訊

CWE-548 Exposure of Information Through Directory Listing
透過列示目錄而曝露資訊

CWE-552 Files or Directories Accessible to External Parties
外部各方可存取的檔案或目錄

CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key
通過用戶控制的 SQL 主鍵繞過授權

CWE-601 URL Redirection to Untrusted Site ('Open Redirect')
URL重新導向至不受信任的站台（“開放而不受限的重新導向”）

CWE-639 Authorization Bypass Through User-Controlled Key
通過用戶控制的金鑰繞過授權

CWE-651 Exposure of WSDL File Containing Sensitive Information
曝露包含敏感資訊的WSDL檔案

CWE-668 Exposure of Resource to Wrong Sphere
資源曝露於錯誤領域

CWE-706 Use of Incorrectly-Resolved Name or Reference
使用被不正確解析的名稱或參考

CWE-862 Missing Authorization
缺少授權

CWE-863 Incorrect Authorization
不正確的授權

CWE-913 Improper Control of Dynamically-Managed Code Resources
不當的動態管理的代碼資源控制

CWE-922 Insecure Storage of Sensitive Information
不安全儲存的敏感信息

CWE-1275 Sensitive Cookie with Improper SameSite Attribute
具有不當SameSite屬性設定的敏感Cookie
