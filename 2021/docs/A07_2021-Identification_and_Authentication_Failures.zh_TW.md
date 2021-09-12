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

-   使用明碼、被加密的或使用較脆弱雜湊法的密碼(參考A3: 2017-敏感性資料洩漏)。
    (TODO) https://github.com/OWASP/Top10/issues/553

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

CWE-255 認證資訊管理的錯誤

CWE-259 密碼寫死

CWE-287 不適當的認證

CWE-288 使用備用的路徑或管道繞過認證

CWE-290 以欺騙來繞過認證

CWE-294 以攔截重送來繞過認證

CWE-295 不適當的憑證確認

CWE-297 與不匹配的服務端進行不適當的憑證確認

CWE-300 通道可被非端點存取

CWE-302 驗證被假設不變的資料繞過

CWE-304 於認證中缺少關鍵的步驟

CWE-306 關鍵的功能中缺少認證

CWE-307 過度認證的嘗試沒有被適當的限制

CWE-346 原始資料確認上的錯誤

CWE-384 會話(Session)固定

CWE-521 脆弱密碼的要求

CWE-613 不適當的會話超時

CWE-620 沒有被驗證的密碼變更

CWE-640 忘記密碼的脆弱密碼回復機制

CWE-798 認證資訊寫死

CWE-940 不當的通訊通道來源驗證

CWE-1216 鎖定機制相關的錯誤
