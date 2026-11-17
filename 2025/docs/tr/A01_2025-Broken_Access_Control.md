#  A01:2025 Bozuk Erişim Kontrolü ![simge](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}



## Arka Plan. 

Top Ten'de 1. sıradaki yerini koruyan bu kategoride, test edilen uygulamaların %100'ünde bir tür bozuk erişim kontrolü tespit edildi. Öne çıkan CWE'ler arasında *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201: Exposure of Sensitive Information Through Sent Data*, *CWE-918 Server-Side Request Forgery (SSRF)* ve *CWE-352: Cross-Site Request Forgery (CSRF)* yer alıyor. Bu kategori, katkı sağlanan verilerde en yüksek görülme sayısına, ilişkili CVE sayısında ise ikinci sıraya sahiptir.


## Puan Tablosu.


<table>
  <tr>
   <td>Eşlenen CWE'ler 
   </td>
   <td>Maks. Görülme Oranı
   </td>
   <td>Ort. Görülme Oranı
   </td>
   <td>Maks. Kapsam
   </td>
   <td>Ort. Kapsam
   </td>
   <td>Ort. Ağırlıklı İstismar
   </td>
   <td>Ort. Ağırlıklı Etki
   </td>
   <td>Toplam Görülme
   </td>
   <td>Toplam CVE
   </td>
  </tr>
  <tr>
   <td>40
   </td>
   <td>20.15%
   </td>
   <td>3.74%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.04
   </td>
   <td>3.84
   </td>
   <td>1,839,701
   </td>
   <td>32,654
   </td>
  </tr>
</table>



## Açıklama. 

Erişim kontrolü, kullanıcıların kendilerine tanınan izinlerin dışında işlem yapamamasını sağlayacak şekilde politikayı uygular. Erişim kontrolündeki hatalar genellikle yetkisiz bilgi ifşasına, tüm verilerin değiştirilmesine veya yok edilmesine ya da kullanıcının yetki sınırları dışında bir iş işlevinin gerçekleştirilmesine yol açar. Yaygın erişim kontrolü güvenlik açıkları şunlardır:



* Genellikle varsayılan olarak reddetme (deny by default) şeklinde de bilinen en az yetki ilkesinin ihlali: Erişimin yalnızca belirli yetenekler, roller veya kullanıcılar için verilmesi gerekirken herkese açık olması.
* URL'yi (parametre manipülasyonu veya zorla gezinme/force browsing), uygulamanın iç durumunu ya da HTML sayfasını değiştirerek veya API isteklerini değiştiren bir saldırı aracı kullanarak erişim kontrolü denetimlerinin atlatılması.
* Benzersiz tanımlayıcısı verilerek başka birinin hesabının görüntülenmesine veya düzenlenmesine izin verilmesi (güvensiz doğrudan nesne referansları / insecure direct object references)
* POST, PUT ve DELETE için erişim kontrolleri eksik olan, erişilebilir bir API.
* Yetki yükseltme: Oturum açmadan bir kullanıcı gibi hareket etmek veya oturum açmış kullanıcıdan beklenenin ötesinde yetkiler (ör. yönetici erişimi) elde etmek.
* Üst veri manipülasyonu: Örneğin bir JSON Web Token (JWT) erişim kontrolü token'ının yeniden oynatılması (replay) veya kurcalanması, yetki yükseltmek için bir çerezin ya da gizli alanın manipüle edilmesi veya JWT geçersiz kılma mekanizmasının kötüye kullanılması.
* Hatalı CORS yapılandırmasının yetkisiz veya güvenilmeyen kaynaklardan (origin) API erişimine izin vermesi.
* Kimliği doğrulanmamış bir kullanıcı olarak kimlik doğrulaması gerektiren sayfalara ya da standart bir kullanıcı olarak ayrıcalıklı sayfalara zorla gezinme (URL tahmin etme).


## Nasıl Önlenir. 

Erişim kontrolü yalnızca, saldırganın erişim kontrolü denetimini veya üst verileri değiştiremeyeceği güvenilir sunucu tarafı kodunda ya da sunucusuz (serverless) API'lerde uygulandığında etkilidir.



* Herkese açık kaynaklar dışında erişimi varsayılan olarak reddedin.
* Erişim kontrolü mekanizmalarını bir kez uygulayın ve uygulama genelinde yeniden kullanın; Cross-Origin Resource Sharing (CORS) kullanımını en aza indirmek de buna dahildir.
* Model erişim kontrolleri, kullanıcıların herhangi bir kaydı oluşturmasına, okumasına, güncellemesine veya silmesine izin vermek yerine kayıt sahipliğini zorunlu kılmalıdır.
* Uygulamaya özgü iş kuralı sınırlarına ilişkin gereksinimler, alan (domain) modelleri tarafından uygulanmalıdır.
* Web sunucusunda dizin listelemeyi devre dışı bırakın ve dosya üst verilerinin (ör. .git) ve yedek dosyaların web kök dizinlerinde bulunmadığından emin olun.
* Erişim kontrolü hatalarını günlüğe kaydedin ve uygun durumlarda (ör. tekrarlanan hatalarda) yöneticileri uyarın.
* Otomatik saldırı araçlarının vereceği zararı en aza indirmek için API ve controller erişimine hız sınırları uygulayın.
* Durum bilgili (stateful) oturum tanımlayıcıları, oturum kapatıldıktan sonra sunucuda geçersiz kılınmalıdır. Durum bilgisiz (stateless) JWT token'ları, saldırganın fırsat penceresini en aza indirmek için kısa ömürlü olmalıdır. Daha uzun ömürlü JWT'ler için yenileme token'ları (refresh token) kullanmayı ve erişimi iptal etmek için OAuth standartlarını izlemeyi değerlendirin.
* Basit ve bildirimsel (declarative) erişim kontrolleri sağlayan, kendini kanıtlamış araç takımları veya kalıplar kullanın.

Geliştiriciler ve kalite güvence (QA) ekipleri, birim ve entegrasyon testlerine işlevsel erişim kontrolü testlerini dahil etmelidir.


## Örnek Saldırı Senaryoları. 

**Senaryo #1:** Uygulama, hesap bilgilerine erişen bir SQL çağrısında doğrulanmamış veri kullanıyor:


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```


Saldırgan, tarayıcıdaki 'acct' parametresini değiştirerek istediği herhangi bir hesap numarasını kolayca gönderebilir. Parametre doğru şekilde doğrulanmazsa saldırgan herhangi bir kullanıcının hesabına erişebilir.


```
https://example.com/app/accountInfo?acct=notmyacct
```


**Senaryo #2:** Saldırgan, tarayıcıyı doğrudan hedef URL'lere gitmeye zorlar. Yönetici sayfasına erişim için yönetici hakları gereklidir.


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


Kimliği doğrulanmamış bir kullanıcı bu sayfalardan herhangi birine erişebiliyorsa bu bir kusurdur. Yönetici olmayan bir kullanıcı yönetici sayfasına erişebiliyorsa bu da bir kusurdur.

**Senaryo #3:** Bir uygulama tüm erişim kontrolünü ön yüzde (front-end) uyguluyor. Saldırgan, tarayıcıda çalışan JavaScript kodu nedeniyle `https://example.com/app/admin_getappInfo` adresine ulaşamasa da şu komutu:


```
$ curl https://example.com/app/admin_getappInfo
```


komut satırından kolayca çalıştırabilir.


## Kaynaklar.

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## Eşlenen CWE'lerin Listesi

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)

* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)

* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)

* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)

* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)

* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)

* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)

* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)

* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
