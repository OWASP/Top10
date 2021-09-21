# A10:2021 – Server-Side Request Forgery (SSRF)

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 67.72%       | 67.72%       | 8.28                 | 6.72                | 9,503             | 385        |


| 可對照 CWEs 數量 | 最大發生率 | 平均發生率 |最大覆蓋範圍 | 平均覆蓋範圍 | 平均加權漏洞 | 平均加權影響 | 出現次數 | 所有相關 CVEs 數量 |
| 1  | 2.72%  | 2.72%  | 67.72%  | 67.72%  | 8.28 | 6.72  | 9,503  | 385   |



## Overview (概覽)

This category is added from the industry survey (#1). The data shows a
relatively low incidence rate with above average testing coverage and
above-average Exploit and Impact potential ratings. As new entries are
likely to be a single or small cluster of CWEs for attention and
awareness, the hope is that they are subject to focus and can be rolled
into a larger category in a future edition.
這個類別是從產業調查結果加入至此的(#1)。資料顯示在測試覆蓋率高於平均水準以及利用(Exploit)和衝擊(Impact)潛力評等高於平均水準的情況下，此類別發生機率相對較低。因為新報到的類別有可能是在CWEs當中受到單一或小群關注的類別而已，因此我們希望此項目可以引來更多人關注，進而在未來版本變成一個較大的類別。



## Description (說明)

SSRF flaws occur whenever a web application is fetching a remote
resource without validating the user-supplied URL. It allows an attacker
to coerce the application to send a crafted request to an unexpected
destination, even when protected by a firewall, VPN, or another type of
network ACL.
(當網頁應用程式正在取得遠端資源，卻未驗證由使用者提供的網址，此時就會發生偽造伺服端請求。即便有防火牆、VPN或其他網路ACL保護的情況下，攻擊者仍得以強迫網頁應用程式發送一個經過捏造的請求給一個非預期的目的端。)

As modern web applications provide end-users with convenient features,
fetching a URL becomes a common scenario. As a result, the incidence of
SSRF is increasing. Also, the severity of SSRF is becoming higher due to
cloud services and the complexity of architectures.
(現今的網頁應用程式提供終端使用者便利的特色，取得網址已經是常見的了。因此，偽造伺服端請求的發生率是在增加當中的。而且，因為雲端服務和雲端結構的複雜性，偽造伺服端請求的嚴重性將會愈來愈嚴峻。)

## How to Prevent (如何預防)

Developers can prevent SSRF by implementing some or all the following
defense in depth controls:
(開發者可以預防偽造伺服端請求，透過實施下列一部分或全部的縱身防禦控制措施：)

## **From Network layer** (從網路層著手)

-   Segment remote resource access functionality in separate networks to
    reduce the impact of SSRF (將遠端資源存取功能切割成不同子網路以降低偽造伺服端請求之衝擊)

-   Enforce “deny by default” firewall policies or network access
    control rules to block all but essential intranet traffic (於防火牆政策或於網路存取控制規則實施"預設全拒絕(deny by default)" ，以封鎖全部來自外部之網路流量)

## **From Application layer:** (從應用層)

-   Sanitize and validate all client-supplied input data (過濾並驗證來自於用戶端提供之全部輸入)

-   Enforce the URL schema, port, and destination with a positive allow
    list (以正面表列方式列出URL、port、目的地清單)

-   Do not send raw responses to clients (不傳送原始回應給用戶端)

-   Disable HTTP redirections (停用HTTP重新導向)

-   Be aware of the URL consistency to avoid attacks such as DNS
    rebinding and “time of check, time of use” (TOCTOU) race conditions (留意網址之一致性，以避免例如DNS rebinding攻擊、TOCTOU攻擊)

Do not mitigate SSRF via the use of a deny list or regular expression.
Attackers have payload lists, tools, and skills to bypass deny lists. (別透過拒絕清單或正規表示式來減緩偽造伺服端請求。攻擊者有 payload 清單、工具和技巧可以繞過這些拒絕清單。)

## Example Attack Scenarios (攻擊情境範例)

Attackers can use SSRF to attack systems protected behind web
application firewalls, firewalls, or network ACLs, using scenarios such
as:
(攻擊者可以利用偽造伺服端請求來攻擊在WAF、防火牆、或網路ACL後面的系統，可能採取之情境如下：)

**Scenario #1:** Port scan internal servers. If the network architecture
is unsegmented, attackers can map out internal networks and determine if
ports are open or closed on internal servers from connection results or
elapsed time to connect or reject SSRF payload connections.
(情境一：對內部伺服器 port scan。如果網路架構未被切割，攻擊者可以透過連線結果或連線所經過的時間或拒絕SSRF payload連線的狀態，加以對應出內部網路並且判斷該等 port在內部伺服器是否開啟或關閉狀態)


**Scenario #2:** Sensitive data exposure. Attackers can access local
files such as <file:///etc/passwd> or internal services to gain
sensitive information.
(情境二：機敏資料洩漏。攻擊者可以存取本地端檔案(例如 <file:///etc/passwd>) 或內部服務已取得機敏資料。)

**Scenario #3:** Access metadata storage of cloud services. Most cloud
providers have metadata storage such as <http://169.254.169.254/>. An
attacker can read the metadata to gain sensitive information.
(情境三：存取雲服務之 metadata storage。大部分雲端提供者都有 metadata storage，例如<http://169.254.169.254/>。攻擊者可以讀取metadata以取得機敏資訊。)

**Scenario #4:** Compromise internal services – The attacker can abuse
internal services to conduct further attacks such as Remote Code
Execution (RCE) or Denial of Service (DoS).
(情境四：滲透內部服務 - 攻擊者可以濫用內部服務去執行更進一步的攻擊，例如RCE或Dos。

## References

-   [OWASP - Server-Side Request Forgery Prevention Cheat
    Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery
    (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery
    (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF
    bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming
    Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## List of Mapped CWEs

CWE-918 Server-Side Request Forgery (SSRF)
