# A10:2021 – Server-Side Request Forgery (SSRF)

## 因素

| 可对照 CWEs 数量 | 最大发生率 | 平均发生率 |最大覆盖范围 | 平均覆盖范围 | 平均加权漏洞 | 平均加权影响 | 出现次数 | 所有相关 CVEs 数量 |
| :-------------: | :------: | :------: | :--------: | :--------: | :---------: | :--------: | :-----: | :--------------: |
| 1 | 2.72% | 2.72% | 67.72% | 67.72% | 8.28 | 6.72 | 9,503 | 385 |

## 概览

这个类别是从产业调查结果加入至此的(#1)。资料显示在测试覆盖率高于平均水准以及利用(Exploit)和冲击(Impact)潜力评等高于平均水准的情况下，此类别发生机率相对较低。因为新报到的类别有可能是在 CWEs 当中受到单一或小群关注的类别而已，因此我们希望此项目可以引来更多人关注，进而在未来版本变成一个较大的类别。

## 描述

当网页应用程式正在取得远端资源，却未验证由使用者提供的网址，此时就会发生伪造服务端请求。即便有防火墙、VPN 或其他网路 ACL 保护的情况下，攻击者仍得以强迫网页应用程式发送一个经过捏造的请求给一个非预期的目的端。

现今的网页应用程式提供终端使用者便利的特色，取得网址已经是常见的了。因此，伪造服务端请求的发生率是在增加当中的。而且，因为云端服务和云端结构的复杂性，伪造服务端请求的严重性将会愈来愈严峻。

## 如何预防

开发者可以预防伪造服务端请求，透过实施下列一部分或全部的纵身防御控制措施：

## **From Network layer** (从网路层着手)

- 将远端资源存取功能切割成不同子网路以降低伪造服务端请求之冲击

- 于防火墙政策或于网路存取控制规则实施"预设全拒绝(deny by default)" ，以封锁全部来自外部之网路流量

## **From Application layer:** (从应用层)

- 过滤并验证来自于用户端提供之全部输入

- 以正面表列方式列出 URL、port、目的地清单

- 不传送原始回应给用户端

- 停用 HTTP 重新导向

- 留意网址之一致性，以避免例如 DNS rebinding 攻击、TOCTOU 攻击

别透过拒绝清单或正规表示式来减缓伪造服务端请求。攻击者有 payload 清单、工具和技巧可以绕过这些拒绝清单

## Example Attack Scenarios (攻击情境范例)

攻击者可以利用伪造服务端请求来攻击在 WAF、防火墙、或网路 ACL 后面的系统，可能采取之情境如下：

**情境一**：对内部服务器 port scan。如果网路架构未被切割，攻击者可以透过连线结果或连线所经过的时间或拒绝 SSRF payload 连线的状态，加以对应出内部网路并且判断该等 port 在内部服务器是否开启或关闭状态

**情境二**：机敏资料泄漏。攻击者可以存取本地端档案(例如 <file:///etc/passwd>) 或内部服务已取得机敏资料。

**情境三**：存取云服务之 metadata storage。大部分云端提供者都有 metadata storage，例如<http://169.254.169.254/>。攻击者可以读取 metadata 以取得机敏资讯。

**情境四**：渗透内部服务 - 攻击者可以滥用内部服务去执行更进一步的攻击，例如 RCE 或 Dos

## References

- [OWASP - Server-Side Request Forgery Prevention Cheat
  Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

- [PortSwigger - Server-side request forgery
  (SSRF)](https://portswigger.net/web-security/ssrf)

- [Acunetix - What is Server-Side Request Forgery
  (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

- [SSRF
  bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

- [A New Era of SSRF - Exploiting URL Parser in Trending Programming
  Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## List of Mapped CWEs

CWE-918 Server-Side Request Forgery (SSRF)
