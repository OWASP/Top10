# A02:2025 Güvenlik Yapılandırma Hataları ![simge](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## Arka Plan. 

Önceki sürümdeki 5. sıradan yükselen bu kategoride, test edilen uygulamaların %100'ünde bir tür yapılandırma hatası tespit edildi. Ortalama görülme oranı %3,00 olan bu risk kategorisinde 719 binden fazla Common Weakness Enumeration (CWE) görülmesi kaydedildi. Yüksek düzeyde yapılandırılabilir yazılımlara geçiş arttıkça bu kategorinin üst sıralara çıkması şaşırtıcı değil. Öne çıkan CWE'ler arasında *CWE-16 Configuration* ve *CWE-611 Improper Restriction of XML External Entity Reference (XXE)* yer alıyor.


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
   <td>16
   </td>
   <td>27.70%
   </td>
   <td>3.00%
   </td>
   <td>100.00%
   </td>
   <td>52.35%
   </td>
   <td>7.96
   </td>
   <td>3.97
   </td>
   <td>719,084
   </td>
   <td>1,375
   </td>
  </tr>
</table>



## Açıklama. 

Güvenlik yapılandırma hatası, bir sistemin, uygulamanın veya bulut hizmetinin güvenlik açısından yanlış yapılandırılması ve bunun sonucunda güvenlik açıklarının ortaya çıkmasıdır.

Aşağıdaki durumlarda uygulama savunmasız olabilir:



* Uygulama yığınının herhangi bir bölümünde uygun güvenlik sıkılaştırması eksikse veya bulut hizmetlerindeki izinler hatalı yapılandırılmışsa.
* Gereksiz özellikler etkinleştirilmiş veya kurulmuşsa (ör. gereksiz portlar, hizmetler, sayfalar, hesaplar, test framework'leri veya yetkiler).
* Varsayılan hesaplar hâlâ etkinse ve parolaları değiştirilmemişse.
* Aşırı ayrıntılı hata mesajlarını yakalayacak merkezi bir yapılandırma yoksa. Hata yönetimi, kullanıcılara yığın izlerini (stack trace) veya gereğinden fazla bilgi veren başka hata mesajlarını gösteriyorsa.
* Yükseltilmiş sistemlerde en yeni güvenlik özellikleri devre dışıysa veya güvenli şekilde yapılandırılmamışsa.
* Geriye dönük uyumluluğa aşırı öncelik verilmesi güvensiz yapılandırmaya yol açıyorsa.
* Uygulama sunucularındaki, uygulama framework'lerindeki (ör. Struts, Spring, ASP.NET), kütüphanelerdeki, veritabanlarındaki vb. güvenlik ayarları güvenli değerlere ayarlanmamışsa.
* Sunucu güvenlik başlıklarını (header) veya yönergelerini göndermiyorsa ya da bunlar güvenli değerlere ayarlanmamışsa.

Koordineli ve tekrarlanabilir bir uygulama güvenliği yapılandırma sıkılaştırma süreci olmadığında sistemler daha yüksek risk altındadır.


## Nasıl Önlenir. 

Aşağıdakiler dahil güvenli kurulum süreçleri uygulanmalıdır:



* Uygun şekilde kısıtlanmış yeni bir ortamın hızlı ve kolay bir şekilde devreye alınmasını sağlayan, tekrarlanabilir bir sıkılaştırma süreci. Geliştirme, QA ve üretim ortamlarının tümü aynı şekilde yapılandırılmalı, ancak her ortamda farklı kimlik bilgileri kullanılmalıdır. Yeni bir güvenli ortam kurmak için gereken çabayı en aza indirmek üzere bu süreç otomatikleştirilmelidir.
* Gereksiz özellik, bileşen, belge veya örnek içermeyen minimal bir platform. Kullanılmayan özellikleri ve framework'leri kaldırın veya hiç kurmayın.
* Yama yönetimi sürecinin bir parçası olarak yapılandırmaları tüm güvenlik notlarına, güncellemelere ve yamalara uygun şekilde gözden geçirme ve güncelleme görevi (bkz. [A03 Yazılım Tedarik Zinciri Hataları](A03_2025-Software_Supply_Chain_Failures.md)). Bulut depolama izinlerini (ör. S3 bucket izinleri) gözden geçirin.
* Segmentasyon, konteynerleştirme veya bulut güvenlik grupları (ACL'ler) aracılığıyla bileşenler ya da kiracılar (tenant) arasında etkili ve güvenli bir ayrım sağlayan, segmentlere ayrılmış bir uygulama mimarisi.
* İstemcilere güvenlik yönergelerinin gönderilmesi; ör. Security Headers (güvenlik başlıkları).
* Tüm ortamlardaki yapılandırma ve ayarların etkinliğini doğrulayan otomatik bir süreç.
* Yedek bir önlem olarak, aşırı ayrıntılı hata mesajlarını yakalamak için proaktif olarak merkezi bir yapılandırma ekleyin.
* Bu doğrulamalar otomatik değilse en az yılda bir kez manuel olarak yapılmalıdır.
* Koda, yapılandırma dosyalarına veya pipeline'lara statik anahtarlar ya da gizli bilgiler (secret) gömmek yerine, altta yatan platformun sunduğu kimlik federasyonu, kısa ömürlü kimlik bilgileri veya rol tabanlı erişim mekanizmalarını kullanın.


## Örnek Saldırı Senaryoları. 

**Senaryo #1:** Uygulama sunucusu, üretim sunucusundan kaldırılmamış örnek uygulamalarla birlikte gelir. Bu örnek uygulamalarda, saldırganların sunucuyu ele geçirmek için kullandığı bilinen güvenlik kusurları vardır. Bu uygulamalardan birinin yönetim konsolu olduğunu ve varsayılan hesapların değiştirilmediğini varsayalım. Bu durumda saldırgan varsayılan parolayla oturum açar ve sistemi ele geçirir.

**Senaryo #2:** Sunucuda dizin listeleme devre dışı bırakılmamıştır. Saldırgan dizinleri kolayca listeleyebildiğini fark eder. Derlenmiş Java sınıflarını bulup indirir ve kodu görmek için bunları decompile ederek tersine mühendislik uygular. Ardından uygulamada ciddi bir erişim kontrolü kusuru bulur.

**Senaryo #3:** Uygulama sunucusunun yapılandırması, yığın izleri gibi ayrıntılı hata mesajlarının kullanıcılara döndürülmesine izin verir. Bu durum, hassas bilgileri veya güvenlik açığı bulunduğu bilinen bileşen sürümleri gibi altta yatan kusurları açığa çıkarabilir.

**Senaryo #4:** Bir bulut hizmet sağlayıcısında (CSP) paylaşım izinleri varsayılan olarak internete açıktır. Bu durum, bulut depolamada saklanan hassas verilere erişilmesine olanak tanır.


## Kaynaklar.

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration

## Eşlenen CWE'lerin Listesi

* [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)

* [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

* [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

* [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

* [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

* [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

* [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

* [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

* [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

* [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

* [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

* [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

* [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
