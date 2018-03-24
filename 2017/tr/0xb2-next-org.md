# +O Kurumlar İçin Bir Sonraki Adım

## Uygulama Güvenliği Programınıza Şimdi Başlayın

Uygulama güvenliği artık opsiyonel değildir. Artan saldırılar ve düzenleyici baskılar arasında, kurumlar uygulama ve API'lerinin güvenliğini sağlamak için etkin süreçler ve yetkinlikler oluşturmalıdır. Hali hazırda üretim ortamında olan uygulama ve API'lerin sahip olduğu aşırı düzeydeki kod miktarı düşünüldüğünde, pek çok kurum aşırı sayıdaki açıklıklar hakkında bilgi sahibi olmak için zorlanmaktadır.

OWASP, kurumların uygulama ve API'lerinin günveliği hakkında bilgi sahibi olmaları ve güvenliklerini artırmaları için bir uygulama güvenliği programı oluşturmalarını tavsiye etmektedir. Uygulama güvenliğinin sağlanması, güvenlik ve denetim, yazılım geliştirme, iş geliştirme ve üst yönetim gibi bir kurumun farklı pek çok kısmının etkin bir şekilde beraber çalışmasını gerektirmektedir. Güvenlik gözlemlenebilir ve ölçülebilir olmalıdır, böylece tüm farklı oyuncular kurumun güvenlik algısını görebilir ve anlayabilir. Açıklıkları gerçekten ortadan kaldırarak veya etkilerini azaltarak kurum güvenliğinin geliştirilmesine yardım eden faaliyetlere ve sonuçlara odaklanın. [OWASP SAMM](https://www.owasp.org/index.php/OWASP_SAMM_Project) ve [CISO'lar İçin OWASP Uygulama Güvenliği Rehberi](https://www.owasp.org/index.php/Application_Security_Guide_For_CISOs) bu listedeki pek çok önemli faaliyetin kaynağıdır.

### Başlayın

* Tüm uygulamaları ve ilgili veri varlıklarını belgelendirin. Daha büyük kurumlar bu amaç için bir Yapılandırma Yönetimi Veri Tabanı (CMDB) oluşturmayı düşünmelidir.
* Bir [uygulama güvenliği programı](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_1) oluşturun ve benimseyin.
* Ana gelişim alanlarını belirlemek için kurumunuzu benzer kurumlar ile kıyaslayarak bir [yetkinlik açığı analizi](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_3) yapın ve yürütme planı hazırlayın.
* Yönetim onayı alın ve IT organizasyonunun tamamı için bir [uygulama güvenliği farkındalık kampanyası](https://www.owasp.org/index.php/SAMM_-_Education_&_Guidance_-_1) oluşturun.

### Risk Tabanlı Portfolyö Yaklaşımı

* İş perspektifi ile [uygulama portfolyönüzün](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_2) [korunma ihtiyaçlarını](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_2) belirleyin. Bu işlem korunan veri varlığı ile ilgili gizlilik yasaları ve diğer düzenlemelere göre parça parça yapılmalıdır.
* Tutarlı bir olasılık seti ve kurumunuzun risk toleransını yansıtan etki faktörleri seti ile ortak bir [risk derecelendirme modeli](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology) oluşturun. 
* Buna uygun olarak, tüm uygulama ve API'lerinizi ölçün ve önceliklendirin. Sonuçları CMDB veri tabanınıza ekleyin.
* Gereken özenin kapsamını ve düzeyini düzgün bir şekilde belirlemek için güvence yönergeleri oluşturun.

### Güçlü Bir Temele Oturtun

* Tüm geliştirme ekiplerinin uyguması için bir uygulama güvenliği çizgisi oluşturacak odaklı bir [politika ve standart](https://www.owasp.org/index.php/SAMM_-_Policy_&_Compliance_-_2) seti oluşturun.
* Bu politika ve standartlara uygun ve kullanımları hakkında tasarım ve geliştirme yönergeleri sağlayan ortak bir [tekrar kullanılabilir günvelik kontrolleri](https://www.owasp.org/index.php/OWASP_Security_Knowledge_Framework) seti tanımlayın.
* Zorunlu tutulacak ve farklı geliştirme rollerini ve konularını hedefleyecek bir [uygulama güvenliği eğitimi içeriği](https://www.owasp.org/index.php/SAMM_-_Education_&_Guidance_-_2) hazırlayın.

### Güvenliği Mevcut Süreçlerle Entegre Hale Getirin

* [Güvenli uygulama](https://www.owasp.org/index.php/SAMM_-_Construction) ve [doğrulama](https://www.owasp.org/index.php/SAMM_-_Verification) faaliyetlerini belirleyin ve bunları mevcut geliştirme ve operasyonel süreçlere entegre edin.
* Faaliyetler [tehdit modellemeyi](https://www.owasp.org/index.php/SAMM_-_Threat_Assessment_-_1), güvenli [tasarım ve tasarım gözden geçirmelerini](https://www.owasp.org/index.php/SAMM_-_Design_Review_-_1), güvenli kodlama ve [kod analizlerini](https://www.owasp.org/index.php/SAMM_-_Code_Review_-_1), [sızma testlerini](https://www.owasp.org/index.php/SAMM_-_Security_Testing_-_1) ve çözümlerini içermektedir.
* Geliştirme ve proje takımlarının başarılı olması için ilgili konu uzmanlarını ve [destek hizmetlerini](https://www.owasp.org/index.php/SAMM_-_Education_&_Guidance_-_3) sağlayın.

### Yönetimsel Görülebilirliği Sağlayın

* Metriklerle yönetin. Geliştirme ve destekleme kararlarını metriklere ve yakalanan analiz verilerine göre belirleyin. Metrikler güvenlik uygulama ve faaliyetlerine bağlılık, sunulan açıklıklar, çözülen açıklıklar, uygulama kapsamı, tip ve ortaya çıkma sayılarına göre açıklık yoğunluğu vb. içermektedir.
* Kök nedenlerin araştırılması için uygulama ve doğrulama faaliyetlerinden gelen verileri ve kurum çapında stratejik ve sistematik geliştirmeleri sağlamak için de açıklık kalıplarını analiz edin.
