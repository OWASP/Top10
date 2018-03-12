# A6:2017 Yanlış Güvenlik Yapılandırması

| Tehdit etkenleri/Saldırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi: İstismar Edilebilirlik 3 | Yaygınlık 3 : Tespit Edilebilirlik 3 | Teknik 2 : İş |
| Saldırganlar, sisteme erişim sağlamak için veya sistem hakkında bilgi elde etmek için düzeltilmesi için gerekli olan yamaları yüklenmemiş olan açıklıkları istismar etmeye veya varsayılan hesaplara, kullanılmayan sayfalara, korunmayan dosya ve dizinlere erişmeye çalışmaktadır. | Yanlış güvenlik yapılandırması ağ servisleri, platform, web sunucusu, uygulama sunucusu, veri tabanı, çerçeve yazılımlar, özel kodlar ve önceden yüklenen sanal makineler, konteynerler veya saklama alanları dahil uygulama katmanlarından herhangi birisinde ortaya çıkabilmektedir. Otomatize tarama araçları yanlış yapılandırmanın, varsayılan hesapların veya ayarların kullanımının, gereksiz servislerin, eski seçeneklerin vb. tespitinde faydalı olmaktadır. | Bu tür açıklıklar sıklıkla saldırganlara bazı sistem verilerine veya fonksiyonlarına yetkisiz erişim sağlamaktadır. Bazen, bu tür açıklıklar sistemin tamamının ele geçirilmesi ile sonuçlanmaktadır. İş etkisi uygulama ve verinin korunma gereksinimlerine göre değişmektedir. |

## Uygulamam Açıklığı İçeriyor Mu?

Eğer uygulama aşağıdaki şartları sağlıyorsa, uygulama açıklık içeriyor olabilir:

* Uygulama katmanlarının herhangi bir parçasında uygun güvenlik sıkılaştırması bulunmuyorsa veya bulut servisleri üzerinde düzgün yapılandırılmamış izinler bulunuyorsa.
* Gerek duyulmayan özellikler (örn. gereksiz portlar, servisler, sayfalar, hesaplar veya yetkiler) aktif edilmişse veya yüklenmişse.
* Varsayılan hesaplar ve parolaları hala aktifse veya değiştirilmemişse.
* Hata işleme mekanizması dizin detayları içeriyorsa veya olması gerekenden daha detaylı bilgi içeren hata mesajları kullanıcılara gösteriliyorsa.
* Güncellenen sistemler için, son güvenlik özellikleri aktif değilse veya güvenli bir şekilde yapılandırılmamışsa.
* Uygulama sunucularında, uygulama çerçeve yazılımlarında (örn. Struts, Spring, ASP.NET), kütüphanelerde, veri tabanlarında vb. güvenlik ayarları güvenli değerlere sahip değilse.
* Sunucu güvenlik başlıklarını veya direktiflerini göndermiyorsa veya bunlar güvenli değerlere sahip değilse.
* Yazılım güncel değilse veya zafiyet içeriyorsa. (bkz. **A9:2017-Bilinen Açıklık İçeren Bileşen Kullanımı**)

Düzenlenmiş, tekrar edilebilir uygulama  güvenlik yapılandırması süreci olmadan, sistemler yüksek risk altında bulunmaktadır.

## Nasıl Önlenir

Aşağıdakiler dahil güvenli yükleme süreçleri uygulanmalıdır:

* Düzgün bir şekilde kilitlenmiş başka bir ortamda kurulumu kolay ve hızlı yapacak bir tekrarlanabilir sıkılaştırma süreci. Geliştirme, QA ve ürün ortamları, her bir ortamda farklı giriş bilgileri kullanılacak şekilde aynı şekilde yapılandırılmalıdır. Yeni bir güvenli ortamın hazırlanması için gereken iş yükünü azaltmak için bu süreç otomatize hale getirilmelidir.
* Herhangi bir gereksiz özellik, bileşen, dokümantasyon ve örnek içermeyen minimal bir platform. Kullanılmayan özellikler veya çerçeveler yüklenmemeli veya kaldırılmalıdır.
* Yama yönetim sürecinin bir parçası olarak tüm güvenlik notlarına, güncellemelerine ve yamalarına uygun yapılandırmaları gözden geçirme ve güncelleme görevi (bkz. **A9:2017-Bilinen Açıklık İçeren Bileşen Kullanımı**). Özellikle, bulut depolama izinlerini (örn. S3 bucket izinleri) gözden geçirilmelidir.
* Segmentasyon, konteyner kullanımı veya bulut güvenlik grupları (ACL) ile bileşenler arasında güvenli ve etkin bir ayırım sağlayan parçalara ayrılmış bir uygulama mimarisi.
* Güvenlik direktiflerinin istemciye gönderilmesi, örn. [Güvenlik Başlıkları](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project).
* Tüm ortamlardaki yapılandırmanın ve ayarların etkinliğini doğrulamak için otomatize bir süreç.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Uygulama sunucusu ürün ortamından kaldırılmamış örnek uygulamalar ile birlikte gelmiştir. Bu örnek uygulamalar saldırganların sunucuyu ele geçirmek için kullanacağı bilinen güvenlik açıklıkları içermektedir. Eğer bu uygulamalardan birisi yönetici konsolu ise ve varsayılan hesaplar değiştirilmemişse, saldırgan varsayılan parola ile giriş yapabilmekte ve yetkileri devralmaktadır.

**Senaryo #2**: Dizin listeleme sunucu üzerinde devre dışı bırakılmamıştır. Saldırgan dizinleri listeleyebileceğini kolayca tespit edecektir. Saldırgan kaynak koda çevireceği ve kodu görmek için ters mühendislik yapabileceği derlenmiş Java sınıflarını bulabilecek ve indirebilecektir. Saldırgan daha sonra uygulama üzerinde ciddi bir erişim kontrolü zafiyeti bulabilecektir.

**Senaryo #3**: Uygulama sunucu yapılandırması kullanıcılara detaylı hata mesajlarının, örn. dizin detaylarının, döndürülmesine izin vermektedir. Bu durum hassas bilgileri ifşa etmekte veya açıklık içerdiği bilinen bileşen sürümleri gibi başka açıklıklar hakkında bilgi vermektedir.

**Senaryo #4**: Bir bulut servis sağlayıcısı, varsayılan olarak diğer CSP kullanıcıları tarafından İnternet üzerinde paylaşma izni içermektedir. Bu durum bulut depolama alanında saklanan hassas veriye erişilmesine izin vermektedir.

## Kaynaklar

### OWASP

* [OWASP Testing Guide: Configuration Management](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [OWASP Testing Guide: Testing for Error Codes](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

Bu alanda ilave gereksinimler için, bkz. Uygulama Güvenliği Doğrulama Standardı [V19 Yapılandırma](https://www.owasp.org/index.php/ASVS_V19_Configuration).

### Dış Kaynaklar

* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
* [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
