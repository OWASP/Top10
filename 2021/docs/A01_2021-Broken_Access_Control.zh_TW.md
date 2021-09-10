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

從第五名晋升，94% 的應用程式都對中斷的訪問控制進行了某種形式的測試。著名
的 CWE 包括 *CWE-200：將敏感信息暴露給未經授權的演員*，*CWE-201：通過發送數據*
和 *CWE-352暴露敏感信息：跨站請求偽造*。

## Description 

Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data or
performing a business function outside the user's limits. Common access
control vulnerabilities include:

訪問控制強化政策，使用戶不能在其預期權限之外採取行動。 故障通常會導致未經授權
的信息洩露、修改或破壞所有數據或執行超出用戶限制的業務功能。 常見的訪問控制漏
洞包括：

-   Bypassing access control checks by modifying the URL, internal
    application state, or the HTML page, or simply using a custom API
    attack tool.
    通過修改 URL、內部應用程序狀態或 HTML 頁面，或僅使用自定義 API 攻擊工具來繞過訪問控制檢查。

-   Allowing the primary key to be changed to another user's record,
    permitting viewing or editing someone else's account.
    容許主鍵被更改為其他用戶的記錄，允許查看或編輯其他人的帳戶。

-   Elevation of privilege. Acting as a user without being logged in or
    acting as an admin when logged in as a user.
    特權提升。 在未登入的情況下充當用戶或以用戶身份登入時充當管理員。

-   Metadata manipulation, such as replaying or tampering with a JSON
    Web Token (JWT) access control token, or a cookie or hidden field
    manipulated to elevate privileges or abusing JWT invalidation.
    中繼資料操作，例如重放或篡改 JSON Web 令牌 (JWT) 訪問控制令牌，或 cookie
    或隱藏欄位被操縱以提升特權或濫用 JWT 失效。

-   CORS misconfiguration allows unauthorized API access.
    CORS 錯誤配置允許未經授權的 API 訪問。

-   Force browsing to authenticated pages as an unauthenticated user or
    to privileged pages as a standard user. Accessing API with missing
    access controls for POST, PUT and DELETE.
    強制以未經身份驗證的用戶身份瀏覽經過身份驗證的頁面或以標準用戶身份訪問特權頁面。 
    訪問對 POST、PUT 和 DELETE 缺少訪問控制的API。

## How to Prevent

Access control is only effective in trusted server-side code or
server-less API, where the attacker cannot modify the access control
check or metadata.
訪問控制僅在受信任的服務器端代碼或無伺服器的API，攻擊者無法修改訪問控制檢查或中繼資料。

-   Except for public resources, deny by default.
    除公開資源外，以拒絕為預設值。

-   Implement access control mechanisms once and re-use them throughout
    the application, including minimizing CORS usage.
    只實施一次訪問控制機制，並在整個應用程式中重複使用它們，包括最大限度地減少 CORS 的使用。

-   Model access controls should enforce record ownership rather than
    accepting that the user can create, read, update, or delete any
    record.
    模型訪問控制應該強化記錄所有權，而不是接受用戶可以創建、讀取、更新或刪除任何記錄。

-   Unique application business limit requirements should be enforced by
    domain models.
    獨特的應用程序業務限制要求應由領域模型強制執行。

-   Disable web server directory listing and ensure file metadata (e.g.,
    .git) and backup files are not present within web roots.
    停用 Web 服務器目錄列表，並確保文件中繼資料（例如，.git) 和備份文件不在 web 根目錄中。

-   Log access control failures, alert admins when appropriate (e.g.,
    repeated failures).
    記錄訪問控制失敗，適時提醒管理員（例如，多次失敗）。

-   Rate limit API and controller access to minimize the harm from
    automated attack tooling.
    對 API 和控制器訪問進行流量限制，將自動化攻擊工具所帶來的損害最小化。

-   JWT tokens should be invalidated on the server after logout.
    登出後，JWT 令牌在服務器應使其失效。

Developers and QA staff should include functional access control unit
and integration tests.
開發人員和 QA 人員應納入功能的訪問控制之單元和整合測試。

## Example Attack Scenarios

**Scenario #1:** The application uses unverified data in a SQL call that
is accessing account information:

**場景 #1：** 應用程序在訪問帳戶資訊的 SQL 呼叫中使用未經驗證的數據：

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

An attacker simply modifies the browser's 'acct' parameter to send
whatever account number they want. If not correctly verified, the
attacker can access any user's account.

攻擊者只需修改瀏覽器的“acct”參數即可發送他們想要的任何帳號。 如果沒有正確驗證，
攻擊者可以訪問任何用戶的帳戶。

https://example.com/app/accountInfo?acct=notmyacct

**Scenario #2:** An attacker simply forces browses to target URLs. Admin
rights are required for access to the admin page.

**場景#2：** 攻擊者只是強迫瀏覽某些目標網址。 訪問管理頁面需要管理員權限。

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

If an unauthenticated user can access either page, it's a flaw. If a
non-admin can access the admin page, this is a flaw.
如果未經身份驗證的用戶可以訪問任一頁面，那就是一個缺陷。 如果一個非管理員可以訪問管理頁面，這是一個缺陷。

## References

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control]()

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## List of Mapped CWEs

CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')

CWE-23 Relative Path Traversal

CWE-35 Path Traversal: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

CWE-201 Exposure of Sensitive Information Through Sent Data

CWE-219 Storage of File with Sensitive Data Under Web Root

CWE-264 Permissions, Privileges, and Access Controls (should no longer
be used)

CWE-275 Permission Issues

CWE-276 Incorrect Default Permissions

CWE-284 Improper Access Control

CWE-285 Improper Authorization

CWE-352 Cross-Site Request Forgery (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized
Actor

CWE-377 Insecure Temporary File

CWE-402 Transmission of Private Resources into a New Sphere ('Resource
Leak')

CWE-425 Direct Request ('Forced Browsing')

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

CWE-497 Exposure of Sensitive System Information to an Unauthorized
Control Sphere

CWE-538 Insertion of Sensitive Information into Externally-Accessible
File or Directory

CWE-540 Inclusion of Sensitive Information in Source Code

CWE-548 Exposure of Information Through Directory Listing

CWE-552 Files or Directories Accessible to External Parties

CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key

CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

CWE-639 Authorization Bypass Through User-Controlled Key

CWE-651 Exposure of WSDL File Containing Sensitive Information

CWE-668 Exposure of Resource to Wrong Sphere

CWE-706 Use of Incorrectly-Resolved Name or Reference

CWE-862 Missing Authorization

CWE-863 Incorrect Authorization

CWE-913 Improper Control of Dynamically-Managed Code Resources

CWE-922 Insecure Storage of Sensitive Information

CWE-1275 Sensitive Cookie with Improper SameSite Attribute
