# A02:2021 – 加密機制失效

## 弱點因素

| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 |最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              | 79.33%       | 34.85%       | 7.29                 | 6.81                | 233,788           | 3,075      |

## 弱點簡介
上升一個名次來到第二名，之前版本稱為"敏感性資料洩漏"，更像是一種廣泛的症狀而非根因，本版本聚焦於密碼學相關的失效(或缺乏加密)，並因此常常導致敏感資料的洩漏。著名的CWE包含"CWE259: Use of Hard-coded Password", "CWE-327: Broken or Risky Crypto Algorithm", 以及"CWE-331: Insufficient Entropy"。

## 弱點描述 
首先確定靜態資料及資料傳輸的防護需求，舉例來說，密碼、信用卡卡號、健康紀錄、個資、以及需要額外保護的營業祕密...等等主要被隱私法所保護的資料，如歐盟GDPR或PCIDSS等等金融業相關的資料保護法或標準。對於這些資料需考量:

-   上開資料是否以明碼傳輸? 像是HTTP, SMTP, FTP等等協定，使用於對外網際網路的流量是危險的。必須驗證所有的內部流量，如在負載平衡器、網站伺服器、或後端系統之間 。

-   是否有任何老舊或脆弱的加密演算法被預設使用或存在於較舊的程式碼?

-   是否有任何預設的加密金鑰被使用、脆弱的加密金鑰被重複使用，是否有適當的金鑰管理或金鑰輪換?

-   加密是否非強制? 舉例: 使用者代理(瀏覽器)是否有遺失安全相關的指令或標題?

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

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
