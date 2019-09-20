# A4:2017 XML Dış Varlıkları (XXE)

| Tehdit Etkenleri/Saldırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 2 | Yaygınlık 2 : Tespit Edilebilirlik 3 | Teknik 3 : İş |
| Saldırganlar, eğer XML dosyası yükleyebiliyorsa veya bir XML dokümanı içerisine zararlı bir içerik ekleyebiliyorsa, zafiyet içeren kodları, bağımlılıkları veya entegrasyonları istismar edecek şekilde XML işleyicilerini istismar edebilmektedir. | Varsayılan olarak, pek çok eski XML işleyicisi, XML işleme sırasında dereferans edilecek ve çalıştırılacak bir dış varlığa ait URL bilgisinin belirtilmesine izin vermektedir. [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) araçları bağımlılıkları ve yapılandırma ayarlarını inceleyerek bu açıklığı tespit edebilmektedir. [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) araçları, bu açıklığı tespit ve istismar etmek için ilave manuel adımlar gerektirmektedir. 2017 itibariyle genellikle test edilmediği için, manuel olarak test edecek kişiler XXE testlerinin nasıl yapılacağı konusunda eğitilmelidirler. | Bu açıklıklar veri ele geçirmek, sunucu üzerinden uzaktan istekte bulunmak, servis dışı bırakma saldırıları ve diğer saldırıları yürütmek için kullanılabilmektedir. |

## Uygulamam Açıklığı İçeriyor Mu?

Uygulamalar ve özellikle XML tabanlı web servisleri veya girdi alacak şekilde yapılan entegrasyonlar aşağıdaki durumlarda saldırıya açık olabilir:

* Uygulama özellikle güvenilmeyen kaynaklardan doğrudan XML girdisi kabul ediyorsa veya XML yüklemelerine izin veriyorsa veya daha sonra bir XML işleyicisi tarafından yorumlanacak şekilde güvenilmeyen veriyi XML dokümanına ekliyorsa.
* Uygulamadaki herhangi bir XML işleyicisi veya SOAP tabanlı web servisleri [doküman tip tanımlarına (DTD)](https://en.wikipedia.org/wiki/Document_type_definition) izin veriyorsa. DTD özelliğini devre dışı bırakma yöntemi işleyiciye göre değiştiği için, [OWASP Kopya Kağıdı: XXE Korunması](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet) gibi bir referansa başvurulması iyi bir uygulama örneğidir.
* Uygulama birleşik güvenlik veya tek oturum açma (SSO) amaçları doğrultusunda kimlik işleme için SAML kullanıyorsa. SAML kimlik iddiaları için XML kullanmakta ve bu da zafiyet içerebilmektedir.
* Uygulama SOAP 1.2 sürümünden önceki sürümleri kullanıyorsa ve XML varlıkları SOAP çerçevesine iletiliyorsa XXE saldırılarına karşı açık olabilmektedir.
* XXE saldırılarına karşı açık olmak uygulamanın Billion Laughs saldırısı gibi servis dışı bırakma saldırılarına da açık olduğu anlamına gelebilmektedir.

## Nasıl Önlenir

XXE tespiti ve önlemesi için geliştirici eğitimi çok önemlidir. Buna ek olarak, XXE saldırılarının önlenmesi için aşağıdakiler gerekmektedir:

* Mümkün oldukça, karmaşıklığı daha az olan JSON gibi veri formatları kullanılmalı ve hassas verinin serileştirilmesinden kaçınılmalıdır.
* Uygulama veya üzerinde çalıştığı işletim sistemi tarafından kullanılan tüm XML işleyicileri ve kütüphaneler güncellenmeli ve yamaları yüklenmelidir. Bağımlılık kontrol araçları kullanılmalıdır. SOAP 1.2 veya üzeri sürümlere güncellenmelidir.
* [OWASP Kopya Kağıdı: XXE Korunması](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet) dokümanında da belirtildiği üzere, uygulamadaki tüm XML ayrıştırıcılarında XML dış varlıkları ve DTD işleme özelliği devre dışı bırakılmalıdır.
* XML dokümanları, başlıklar veya nodlar içerisindeki zararlı girdiyi önlemek için, sunucu tarafında pozitif ("beyaz liste") girdi doğrulaması, filtreleme veya sterilizasyon uygulanmalıdır.
* XML veya XSL dosya yükleme özelliğinin, gelen XML girdisini XSD doğrulaması veya benzer bir doğrulama ile kontrol ettiğinden emin olunmalıdır.
* Pek çok entegrasyon içeren büyük ve karmaşık uygulamalar için manuel kod analizi en iyi alternatif olsa da, SAST araçları kaynak kod içerisindeki XXE açıklıklarının tespitinde yardımcı olmaktadır.

Eğer bu kontroller uygulanabilir değilse, XXE saldırılarını tespit etmek, izlemek ve engellemek için sanal yama kullanımı, API güvenlik geçitleri veya Web Uygulamaları Güvenlik Duvarları (WAF) kullanımı düşünülmelidir.

## Örnek Saldırı Senaryoları

Gömülü cihazlara saldırılar dahil, pek çok sayıda açık XXE sorunları tespit edilmiştir. Derin bir şekilde iç içe geçmiş bağımlılıklar dahil pek çok beklenmedik yerde XXE açıklığı bulunmaktadır. En kolay yöntem ise, eğer kabul ediliyorsa zararlı bir XML dosyası yüklemektir.

**Senaryo #1**: Saldırgan sunucudan veri ele geçirmeye çalışmaktadır:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Senaryo #2**: Saldırgan aşağıdaki ENTITY satırını değiştirerek sunucunun iç ağını dinlemektedir:

```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Senaryo #3**: Saldırgan potansiyel olarak sonu olmayan bir dosyayı dahil ederek, servis dışı bırakma saldırısı gerçekleştirmeye çalışmaktadır:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Kaynaklar

### OWASP

* [OWASP Uygulama Güvenliği Doğrulama Standardı](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Test Rehberi: XML Enjeksiyonu Testleri](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Açıklığı](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Kopya Kağıdı: XXE Önlemleri](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Kopya Kağıdı: XML Güvenliği](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### Dış Kaynaklar

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
