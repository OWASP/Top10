# A07:2021 – 認證及驗證機制失效

## 弱點因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 |最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 79.51%       | 45.72%       | 7.40                 | 6.50                | 132,195           | 3,897      |

## 弱點簡介

之前被稱之為"無效的身份認證"，此類別從第二名下滑，現在包含了與身份識別失效相關的CWEs，如知名的"CWE-297: 與不匹配的服務端進行不適當的憑證確認", "CWE-287: 不適當的認證", "CWE-384: 會話(session)固定攻擊"

## 弱點描述 

確認用戶的身分、認證、會話(session)管理對於防止與認證相關的攻擊至關重要，如果應用程式存在以下情況，則可能有認證的漏洞:

-   允許像是攻擊者已經擁有有效用戶名稱和密碼列表的撞庫自動化攻擊。

-   允許暴力或其他自動化攻擊。

-   允許預設、脆弱、常見的密碼，像是"Password1"或"admin/admin"。

-   使用脆弱或無效的認證資訊回復或忘記密碼的流程，如不安全的"知識相關問答"。

-   將密碼使用明碼、加密或較脆弱雜湊法的方式儲存(參考A3: 2017-敏感性資料洩漏)。

-   不具有或是無效的多因素認證。

-   於URL中洩漏會話(session) ID(如 URL重寫)。

-   成功登入後沒有輪換會話(session) ID。

-   沒有正確的註銷會話(session) ID。 用戶的會話(session)或認證tokens(主要是單一登入(SSO)token) 沒有在登出時或一段時間沒活動時被適當的註銷。

## 如何預防

-   在可能的情況下，實作多因素認證來防止自動化撞庫攻擊、暴力破解、以及遭竊認證資訊被重複利用的攻擊。

-   不要交付或部署任何預設的認證資訊，特別是管理者。

-   實作脆弱密碼的檢查，如測試新設定或變更的密碼是否存在於前10,000個最差密碼清單。

-   將密碼長度、複雜度、和輪換政策與"NIST 800-63b第5.1.1節-被記憶的秘密或其他現代基於證據的密碼政策"保持一致。

-   對所有結果使用相同的訊息回應，確保註冊、認證資訊回復、以及API路徑能夠抵禦帳號列舉攻擊。

-   限制或增加失敗登入嘗試的延遲。記錄所有失敗並於偵測到撞庫、暴力破解或其他攻擊時發出告警。

-   使用伺服器端、安全的內建會話(session)管理器，在登入後產生新的高亂數隨機程度(entropy)的隨機會話(session)ID。會話(session)ID不應出現在URL中，必須被安全的儲存，並且在登出後、閒置、超時後被註銷。

## 攻擊情境範例

**情境 #1:** 使用已知列表密碼的撞庫攻擊是一種常見的攻擊方式，假設應用程式沒有實施自動化威脅或撞庫攻擊的保護，在這種情況下，應用程式會被利用為密碼預報的工具來判斷認證資訊是否有效。

**情境 #2:** 大多數的認證攻擊是因為持續的使用密碼作為唯一因素，最佳實務、密碼輪換、以及複雜度的要求會鼓勵用戶使用和重複使用脆弱的密碼。建議組織按照NIST 800-63停止這些做法並使用多因素認證。

**情境 #3:** 應用程式的會話超時沒有被設定正確。一個用戶使用公用電腦來存取應用程式時，用戶沒有選擇"登出"而是簡單的關閉瀏覽器分頁就離開，此時一個攻擊者在一小時後使用同一個瀏覽器，前一個用戶仍然處於通過認證的狀態。

## 參考文獻

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   OWASP Testing Guide: Identity, Authentication

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Credential Stuffing

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Session Management

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## 對應的 CWEs 清單

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)
