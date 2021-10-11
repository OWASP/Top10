# A01:2021 – 權限控制失效


## 對照因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 |最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 94.55%       | 47.72%       | 6.92                 | 5.93                | 318,487           | 19,013     |

## 概述

從第五名晋升至第一名，94% 被測試的應用程式，都有被驗測到某種類別權限控制失效的問題。著名的CWE包括 *CWE-200：Exposure of Sensitive Information to an Unauthorized Actor*，*CWE-201：Exposure of Sensitive Information Through Sent Data* 和 *CWE-352 Cross-Site Request Forgery。

## 描述 

存取控制強化政策，使用戶不能採取在預期權限之外的行動。控制失效通常會導致未經授權的資訊洩露、修改或損壞所有資料，或執行超出用戶權限的業務功能。常見的存取控制弱點包括：

-   通過修改URL、內部應用程式狀態或HTML頁面，或僅使用自定義API攻擊工具來繞過存取控制檢查。

-   容許主鍵被更改為其他用戶的記錄，允許查看或編輯其他人的帳戶。

-   特權提升。未登入即成為用戶，或以用戶身份登入即成為管理員。

-   中繼資料操作，例如重放或篡改JSON網站令牌(JWT)之存取控制令牌，或被操縱以提升特權或濫用JWT失效的cookie或隱藏欄位。

-   CORS錯誤配置允許未經授權的API存取。

-   以未經身份驗證的用戶身份強制瀏覽已驗證的頁面或以標準用戶身份存取特權頁面。存取缺少存取控制的API以進行POST、PUT 和 DELETE操作。

## 如何預防

存取控制僅在受信任的伺服器端代碼或無伺服器的API有效，攻擊者無法修改這裏的存取控制檢查或中繼資料。

-   除公開的資源外，默認為拒絕存取。

-   一次性地建置存取控制機制，之後在整個應用程式中重複使用它們，包括最大限度地減少使用CORS。

-   模型的存取控制措施應該強化記錄所有權，而不是讓用戶可以創建、讀取、更新或刪除任何記錄。

-   獨特的應用程式業務限制要求應由領域模型予以強化。

-   停用Web伺服器目錄列表，並確保檔案中繼資料（例如，.git)和備份檔案不在web根目錄中。

-   記錄存取控制失效，並在適當的時間警示管理員（例如，重覆性失效）。

-   對API和控制器存取進行流量限制，以最小化自動攻擊工具所帶來的損害。

-   JWT令牌於登出後，在伺服器端應使其失效。

開發人員和QA品保人員應納入與功能有關之存取控制的單元和整合測試。

## 攻擊情境範例

**情境 #1：** 應用程式在存取帳戶資訊的SQL呼叫中使用未經驗證的資料：

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

攻擊者只需修改瀏覽器的“acct”參數即可發送他們想要的任何帳號。如果沒有正確驗證，攻擊者可以存取任何用戶的帳戶。

https://example.com/app/accountInfo?acct=notmyacct

**情境#2：** 攻擊者僅強迫瀏覽某些目標網址。存取管理頁面需要管理員權限。

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

如果未經身份驗證的用戶可以存取任一頁面，那就是一個缺陷。 如果一個非管理員可以存取管理頁面，這也是一個缺陷。

## 參考

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## 對應的CWE列表


[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
