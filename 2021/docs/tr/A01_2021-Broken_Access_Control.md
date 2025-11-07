# A01:2021 – Broken Access Control (Kırık Erişim Kontrolü)    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| Eşlenen CWE'ler | Maks. Görülme Oranı | Ort. Görülme Oranı | Ort. Ağırlıklı Exploit | Ort. Ağırlıklı Etki | Maks. Kapsama | Ort. Kapsama | Toplam Görülme | Toplam CVE |
| :-------------: | :-----------------: | :----------------: | :--------------------: | :-----------------: | :-----------: | :----------: | :------------: | :--------: |
|        34       |        55.97%       |        3.81%       |          6.92          |         5.93        |     94.55%    |    47.72%    |     318,487    |   19,013   |

## Genel Bakış

Beşinci sıradan yükselerek, uygulamaların %94’ü bir tür broken access control açısından test edildi; ortalama görülme oranı %3.81 olup, katkı veri setinde 318 bini aşkın vakayla en çok görülen kategoridir. Dikkat çeken Common Weakness Enumeration (CWE) örnekleri arasında *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201: Insertion of Sensitive Information Into Sent Data* ve *CWE-352: Cross-Site Request Forgery* bulunur.

## Açıklama

Erişim kontrolü, kullanıcıların amaçlanan yetkilerinin dışına çıkamaması için politikayı uygular. Hatalar genellikle yetkisiz bilgi ifşasına, verilerin değiştirilmesine veya yok edilmesine ya da kullanıcının sınırları dışında bir işlevin icra edilmesine yol açar. Yaygın erişim kontrolü açıkları şunlardır:

* Asgari ayrıcalık (least privilege) veya varsayılan olarak reddet (deny by default) ilkesinin ihlali; belirli yetenekler, roller veya kullanıcılar için verilmesi gereken erişimin herkese açık olması.
* URL’yi (parameter tampering/force browsing), uygulamanın iç durumunu veya HTML sayfasını değiştirerek ya da API request’lerini değiştiren bir attack tool kullanarak erişim kontrol kontrollerinin atlatılması.
* Benzersiz tanımlayıcıyı vererek başkasının hesabını görüntüleme veya düzenleme (insecure direct object references).
* POST, PUT ve DELETE için access control eksikliği bulunan API’lere erişim.
* Yetki yükseltme (privilege escalation). Login olmadan bir kullanıcı gibi davranmak veya user olarak login iken admin gibi davranmak.
* Metadata manipülasyonu; örn. bir JSON Web Token (JWT) access control token’ını, cookie’yi veya hidden field’ı yeniden oynatarak/tahrif ederek yetki yükseltme ya da JWT invalidation’ını suistimal etme.
* CORS misconfiguration nedeniyle yetkisiz/güvenilmeyen origin’lerden API erişimine izin verilmesi.
* Auth olmadan authenticated sayfalara ya da standard user iken privileged sayfalara force browsing.

## Nasıl Önlenir

Erişim kontrolü yalnızca güvenilen server-side code veya server-less API içinde etkilidir; saldırganın access control kontrolünü veya metadata’yı değiştiremeyeceği yerlerde.

* Public kaynaklar hariç, varsayılan olarak reddet (deny by default).
* Access control mekanizmalarını bir kez uygulayıp tüm uygulamada yeniden kullanın; Cross-Origin Resource Sharing (CORS) kullanımını en aza indirin.
* Model access control’leri, herhangi bir kaydı create/read/update/delete etmesine izin vermek yerine kayıt sahipliğini (record ownership) zorlamalıdır.
* Benzersiz application business limit gereksinimleri domain model’lerince zorlanmalıdır.
* Web server directory listing’i devre dışı bırakın ve dosya metadata’sının (örn. .git) ve yedek dosyaların web root içinde bulunmadığından emin olun.
* Access control hatalarını log’layın, uygun olduğunda (örn. tekrar eden hatalarda) admin’leri uyarın.
* Otomatize attack tooling’in zararını en aza indirmek için API ve controller erişimini rate limit edin.
* Stateful session identifier’ları logout sonrası server tarafında geçersiz kılın. Stateless JWT token’ları kısa ömürlü yapın ki saldırgan için fırsat penceresi minimal olsun. Daha uzun ömürlü JWT’lerde erişimi revoke etmek için OAuth standartlarını takip etmek kuvvetle tavsiye edilir.

Geliştiriciler ve QA ekipleri fonksiyonel access control unit ve integration testlerini dahil etmelidir.

## Örnek Saldırı Senaryoları

**Senaryo #1:** Uygulama, account bilgilerine erişen bir SQL çağrısında doğrulanmamış veriyi kullanıyor:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

Saldırgan, browser’daki 'acct' parametresini istediği hesap numarasını gönderecek şekilde değiştirir. Doğru şekilde doğrulanmamışsa saldırgan herhangi bir kullanıcının hesabına erişebilir.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Senaryo #2:** Saldırgan hedef URL’lere basitçe force browse yapar. Admin sayfasına erişim için admin hakları gerekir.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```

Auth olmayan bir kullanıcı bu sayfalardan herhangi birine erişebiliyorsa bu bir hatadır. Non-admin bir kullanıcı admin sayfasına erişebiliyorsa bu da bir hatadır.

## Referanslar

* [OWASP Proactive Controls: Enforce Access
  Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

* [OWASP Application Security Verification Standard: V4 Access
  Control](https://owasp.org/www-project-application-security-verification-standard)

* [OWASP Testing Guide: Authorization
  Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

* [PortSwigger: Exploiting CORS
  misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## Eşlenen CWE’lerin Listesi

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

