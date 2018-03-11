# A5:2017 Yetersiz Erişim Kontrolü

| Tehdit Etkenleri/Saldırı vektörleri | Güvenlik zafiyeti  | Etkiler |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 2 | Yaygınlık 2 : Tespit Edilebilirlik 2 | Teknik 3 : İş |
| Erişim kontrolü istismarı saldırganların temel bir yeteneğidir. [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) ve [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) araçları erişim kontrolünün olmadığını tespit edebilir ancak olduğu durumlarda fonksiyonel olup olmadığını doğrulayamamaktadır. Erişim kontrolü manuel yöntemlerle veya belirli çerçevelerde erişim kontrollerinin bulunmayışı için otomatizasyon aracılığıyla tespit edilebilmektedir. | Erişim kontrolü açıklıkları otomatize tespitin eksikliği ve uygulama geliştiricileri tarafından etkin bir fonksiyonel test yapılmamasından dolayı yaygındır. Erişim kontrolü tespiti genellikle otomatize statik veya dinamik test ile yapılamamaktadır. HTTP metotları (GET, PUT vb.), kontrolör, doğrudan nesne başvuruları vb. dahil eksik veya yetersiz erişim kontrollerini tespit etmenin en iyi yolu manuel testlerdir. | Teknik etki saldırganların kullanıcılar veya yöneticiler gibi davranması veya kullanıcıların yetki gerektiren fonksiyonları kullanması veya kayıt oluşturulması, kayıtlara erişilmesi, kayıtların güncellenmesi veya silinmesidir. |

## Uygulamam Açıklık İçeriyor Mu?

Erişim kontrolü kullanıcıların kendi istenen izinleri dışında bir şey yapamayacağı şekilde bir politika uygulamaktadır. Uyumsuzluklar genellikle yetkisiz bilgi ifşasına, tüm verinin değiştirilmesine veya silinmesine veya kullanıcının sınırları dışında bir iş fonksiyonunun gerçekleştirilmesine yol açmaktadır. Yaygın erişim kontrolü açıklıkları şunları içermektedir:

* URL'i, iç uygulama durumunu veya HTML sayfasını değiştirerek veya basitçe özel bir API saldırı aracı kullanarak erişim kontrollerinin atlatılması.
* Birincill anahtarın başka bir kullanıcının kaydına göre değiştirilmesine izin vermek ve bu şekilde başkalarının hesaplarının görülmesine ve değiştirilmesine izin vermek.
* Yetki yükseltmesi. Giriş yapmadan bir kullanıcı gibi davranmak veya bir kullanıcı olarak girip bir yönetici gibi davranmak.
* Bir JSON Web Token (JWT) erişim anahtarının veya bir çerezin değiştirmek veya tekrar oynatmak gibi meta veri değiştirmek veya yetki yükseltmek için gizli alanları değiştirmek veya JWT geçersiz kılma sürecini suistimal etmek.
* CORS yanlış yapılandırması yetkisiz API erişimlerine izin vermektedir.
* Kimlik doğrulaması yapılmamış bir kullanıcı olarak kimlik doğrulama gerektiren sayfalara veya standart bir kullanıcı olarak yetki gerektiren sayfalara erişim. POST, PUT ve DELETE için eksik erişim kontrolleri ile API erişimi.

## Nasıl Önlenir

Erişim kontrolü sadece, saldırganın erişim kontrollerine veya meta verilere erişemeyeceği güvenilir sunucu taraflı kodda veya sunucusuz API'lerde zorunlu tutulduysa etkili olmaktadır.

* Herkese açık kaynaklar haricinde, varsayılan olarak reddedilmelidir.
* CORS kullanımını azaltmak dahil, erişim kontrolü mekanizmaları bir sefer oluşturulmalı ve uygulama boyunca tekrar kullanılmalıdır.
* Model erişim kontrolleri, kullanıcının herhangi bir kayıt oluşturabileceğini, herhangi bir kaydı okuyabileceğini, güncelleyebileceğini veya silebileceğini kabul etmek yerine, kayıt mülkiyetini gerektirmelidir. 
* Özgün uygulama iş limiti gereksinimleri etki alanı modelleri ile uygulanmalıdır.
* Sunucu dizin listelemesi devre dışı bırakılmalı ve web kök dizininde dosya meta verileri (örn. .git) ve yedekleme dosyaları bulunmamalıdır.
* Erişim kontrolü ihlalleri loglanmalı ve uygun görüldüğünde (örn. tekrar eden ihlaller) yöneticiler uyarılmalıdır.
* Otomatize saldırı araçlarından gelebilecek zararları en aza indirmek için API ve kontrolör erişimi sınırlandırılmalıdır.
* Çıkış yapıldıktan sonra JWT anahtarları sunucuda geçersiz kılınmalıdır.
* Geliştiricler ve QA çalışanları fonksiyonel erişin kontrolü birim ve entegrasyon testleri yapmalıdır.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Uygulama, hesap bilgilerine erişin bir SQL çağrısı içerisinde doğrulanmamış bir veri kullanmaktadır:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

Saldırgan tarayıcısında basitçe 'acct' parametresini değiştirerek istedği hesap numarasını yollayabilmektedir. Düzgün bir şekilde doğrulanmadığında, saldırgan herhangi bir kullanıcı hesabına erişebilmektedir.

`http://example.com/app/accountInfo?acct=notmyacct`

**Senaryo #2**: Saldırgan kaba kuvvet ile hedef URL'leri gezmektedir. Yönetici sayfasına erişim için yönetici hakları gerekmektedir.

```
  http://example.com/app/getappInfo
  http://example.com/app/admin_getappInfo
```

Eğer kimliği doğrulanmamış bir kullanıcı iki sayfadan herhangi birine erişebiliyorsa, açıklık bulunmaktadır. Eğer yönetici olmayan bir kullanıcı yönetici sayfasına erişebiliyorsa, bu bir açıklıktır.

## Kaynaklar

### OWASP

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Authorization Testing](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Dış Kaynaklar

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
