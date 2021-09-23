# A02:2021 – 加密機制失效

## 弱點因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 |最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              | 79.33%       | 34.85%       | 7.29                 | 6.81                | 233,788           | 3,075      |

## 弱點簡介
上升一個名次來到第二名，之前稱之為"敏感性資料洩漏"，正更像是一種廣泛的症狀而非根因，聚焦於密碼學相關的失效(或缺乏加密)，這往往會導致敏感資料的洩漏。著名的CWE包含"CWE259: 密碼寫死", "CWE-327: 被破解或是有風險的加密演算法", 以及"CWE-331: 不足的亂數隨機程度(entropy)"。

## 弱點描述 
首先確定靜態資料及資料傳輸的防護需求，舉例來說，密碼、信用卡卡號、健康紀錄、個資、以及需要額外保護的營業祕密...等等主要被隱私法所保護的資料，如歐盟GDPR或PCIDSS等等金融業相關的資料保護法或標準。對於這些資料需考量:

-   上開資料是否以明碼傳輸? 像是HTTP, SMTP, FTP等等協定，使用於對外網際網路的流量是危險的。必須驗證所有的內部流量，如在負載平衡器、網站伺服器、或後端系統之間 。

-   是否有任何老舊或脆弱的加密演算法被預設使用或存在於較舊的程式碼?

-   是否有任何預設的加密金鑰被使用、脆弱的加密金鑰被重複使用，是否有適當的金鑰管理或金鑰輪換?

-   加密是否非強制? 舉例: 使用者代理(瀏覽器)是否有遺失安全相關的指令或標頭?

-   使用者代理(如: app, 郵件客戶端)是否有驗證伺服器的憑證是有效的?

請參考 ASVS 加密(V7), 資料保護(V9), 及SSL/TLS(V10)。

## 如何預防

至少執行以下措施，並參考相關資料:

-   對應用程式處理、儲存、傳輸的資料進行分類，根據隱私法、法令法規、或商業需求辨識哪些為敏感性資料。

-   依照分類執行對應的控制措施。

-   非必要不儲存敏感性資料，盡快捨棄或使用符合PCIDSS的資料記號化(tokenization)甚至截斷(truncation)。 沒有被保存的數據是不會被竊取的。

-   確保將所有靜態的敏感性資料加密。

-   確認使用最新版且標準的強演算法、協定及金鑰; 使用適當的金鑰管理。

-   使用安全的協定加密傳輸中的資料，像是有完全前向保密(PFS)、伺服器加密優先順序(cipher prioritization by the server)及安全參數的TLS。 使用像是HTTP強制安全傳輸技術(HSTS)的指令強化加密。

-   針對包含敏感資料的回應停用快取。

-   使用具有雜湊迭代次數因素(work factor/delay factor)，如Argon2, scrypt, bcrypt或PBKDF2的強自適應性加鹽雜湊法來儲存密碼。

-   獨立驗證設定的有效性。

## 攻擊情境範例

**情境 #1**: 有一個應用程式使用自動化資料庫加密來加密資料庫中的信用卡卡號，但是資料被存取時是被自動解密的，進而允許透過SQL注入缺陷來存取信用卡卡號明文。

**情境 #2**: 有一個站台沒有對所有頁面強制使用TLS或支援脆弱的加密，攻擊者監控網路流量(如在不安全的無線網路), 將連線從HTTPS降級成HTTP，並攔截請求竊取使用者的會話(session) cookies，之後攻擊者重送竊取到的會話(session) cookies並劫持用戶(認證過的)的會話，進而存取或修改使用者的隱私資料。 除了上述以外，攻擊者也能修改傳輸的資料，如匯款收款人。

**情境 #3**: 密碼資料庫使用未被加鹽或簡單的雜湊來儲存每個人的密碼，一個檔案上傳的缺陷可以讓攻擊者存取密碼資料庫，所有未被加鹽的雜湊可以被預先計算好的彩虹表公開。即使雜湊有被加鹽，由簡單或快速的雜湊法算出的雜湊仍能被GPU破解。

## 參考文獻

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Password and Cryptographic Storage

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   OWASP Testing Guide: Testing for weak cryptography


## 對應的CWEs清單

CWE-261 密碼的脆弱編碼

CWE-296 不當遵循憑證信任鏈

CWE-310 密碼學議題

CWE-319 敏感性資訊明碼傳輸

CWE-321 寫死加密金鑰

CWE-322 沒有經過實體認證的金鑰交換

CWE-323 加密時使用重複的隨機數(nonce)金鑰對

CWE-324 使用過期的金鑰

CWE-325 缺少所需的加密步驟

CWE-326 加密長度不足

CWE-327 使用被破解或是有風險的加密演算法

CWE-328 可逆的單向雜湊

CWE-329 在密碼分組鏈接(CBC)模式下沒有使用隨機初始向量(IV)

CWE-330 使用不充分的隨機亂數

CWE-331 不足的亂數隨機程度(entropy)

CWE-335 於虛擬亂數產生器(PRNG)不當使用種子(seeds)

CWE-336 於虛擬亂數產生器(PRNG)使用同一組種子(seeds)

CWE-337 於虛擬亂數產生器(PRNG)使用可預測的種子(seeds)

CWE-338 使用脆弱演算法的虛擬亂數產生器(PRNG)

CWE-340 產生可預測的數字或是標識符

CWE-347 不適當的密碼簽章驗證

CWE-523 未受保護的驗證資訊傳輸

CWE-720 OWASP Top Ten 2007 Category A9 - 不安全的傳輸

CWE-757 通訊時使用較不安全的演算法(降級的演算法)

CWE-759 使用單向雜湊時沒有加鹽

CWE-760 使用單向雜湊時加了可預測的鹽

CWE-780 使用RSA演算法時沒有使用OAEP

CWE-818 不足的傳輸層保護

CWE-916 使用運算量不足的密碼雜湊
