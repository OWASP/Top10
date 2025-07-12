# A04:2021 – 不安全設計

## 弱點因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 | 最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 77.25%       | 42.51%       | 6.46                 | 6.78                | 262,407           | 2,691      |

## 弱點簡介

2021年中的一個全新類別，著重於在設計與架構中的風險。來呼籲更多使用到威脅建模、安全設計模式與參考架構。
著名的 CWE 包括下列 *CWE-209: 產生的錯誤信息的中包含敏感訊息*、*CWE-256: 未受保護的憑證儲存方式*、*CWE-501: 違反信任邊界* 與 *CWE-522: 不足夠的憑證保護*。


## 弱點描述 

不安全設計是一個廣泛的類別呈現許多不同的弱點，代表為"缺乏或無效的控制設計"。 缺乏不安全設計是指没有控制措施。舉例來說，想像一段程式碼應該加密敏感資料但是沒有對應的實作方法。無效的不安全設計是可以實現威脅的地方，但不足的領域（商業）邏輯驗證會阻止該動作。以下個例子說，想像領域邏輯是用來處理基於收入等級的疫情減稅但是並未確認所有的輸入都是有正確的簽名，因此提供超過原本可以獲得而且更顯著的減稅利益。

安全設計一個文化與方法持續不斷的來評估威脅並保證程式碼有被穩健的設計與測試來預防已知的攻擊方法。安全設計需要安全的開發生命週期、某種形式上的安全設計模式或是已完成的元件庫或工具以及威脅建模。

## 如何預防

-   建立與使用安全開發生命週期並且協同應用程式安全的專業人士來評估與設計安全與隱私相關的控制措施。

-   建立與使用安全設計模式的函式庫或是已完成可使用的元件。    

-   使用威脅建模在關鍵的認證、存取控制、商業邏輯與關鍵缺陷上。

-   撰寫單元測試與整合測試來驗證所有的關鍵流程對威脅建模都有抵抗。

## 攻擊情境範例

**情境 #1** 憑證恢復的流程或許會包含“問題與答案”，該方式是被NIST 800-63b、OWASP ASVS與WASP Top 10中禁止。“問題與答案”無法被作為信任身份的證據因為不止一個人可能會知道答案，因此這個方法會被禁止的原因。因此此類的程式碼應該被移除或是用更安全的設計來替代。

**情境 #2:** 電影院在要求押金前允許團體預訂折扣並且最多有15 名觀眾。攻擊者可以威脅模型此流程並測試他們在一次請求中是否可以預訂 600 個座位和的所有電影院，導致電影院巨大的收入損失。

**情境  #3:** 連鎖零售的電子商務網站沒有保護機制來對抗黃牛的機器人購買高端的顯示卡再轉售到拍賣網站。對於零售商與顯示卡製造商產生了可怕的宣傳效應並且導致與那些無法購買到顯卡的愛好者間產生了不愉快。巧妙的防機器人設計與領域邏輯規則，例如短暫幾秒的購買時間或許可以辨識出不可信賴的購買並且拒絕該交易。

## 參考文獻

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   NIST – Guidelines on Minimum Standards for Developer Verification of
    > Software  
    > https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software

## 對應的 CWEs 清單

CWE-73 External Control of File Name or Path

CWE-183 Permissive List of Allowed Inputs

CWE-209 Generation of Error Message Containing Sensitive Information

CWE-213 Exposure of Sensitive Information Due to Incompatible Policies

CWE-235 Improper Handling of Extra Parameters

CWE-256 Unprotected Storage of Credentials

CWE-257 Storing Passwords in a Recoverable Format

CWE-266 Incorrect Privilege Assignment

CWE-269 Improper Privilege Management

CWE-280 Improper Handling of Insufficient Permissions or Privileges

CWE-311 Missing Encryption of Sensitive Data

CWE-312 Cleartext Storage of Sensitive Information

CWE-313 Cleartext Storage in a File or on Disk

CWE-316 Cleartext Storage of Sensitive Information in Memory

CWE-419 Unprotected Primary Channel

CWE-430 Deployment of Wrong Handler

CWE-434 Unrestricted Upload of File with Dangerous Type

CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request
Smuggling')

CWE-451 User Interface (UI) Misrepresentation of Critical Information

CWE-472 External Control of Assumed-Immutable Web Parameter

CWE-501 Trust Boundary Violation

CWE-522 Insufficiently Protected Credentials

CWE-525 Use of Web Browser Cache Containing Sensitive Information

CWE-539 Use of Persistent Cookies Containing Sensitive Information

CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session

CWE-598 Use of GET Request Method With Sensitive Query Strings

CWE-602 Client-Side Enforcement of Server-Side Security

CWE-642 External Control of Critical State Data

CWE-646 Reliance on File Name or Extension of Externally-Supplied File

CWE-650 Trusting HTTP Permission Methods on the Server Side

CWE-653 Insufficient Compartmentalization

CWE-656 Reliance on Security Through Obscurity

CWE-657 Violation of Secure Design Principles

CWE-799 Improper Control of Interaction Frequency

CWE-807 Reliance on Untrusted Inputs in a Security Decision

CWE-840 Business Logic Errors

CWE-841 Improper Enforcement of Behavioral Workflow

CWE-927 Use of Implicit Intent for Sensitive Communication

CWE-1021 Improper Restriction of Rendered UI Layers or Frames

CWE-1173 Improper Use of Validation Framework
