# +O Organizasyonlar İçin Bir Sonraki Adım

## Uygulama Güvenliği Programınıza Şimdi Başlayın

Uygulama güvenliği artık opsiyonel değildir. Artan saldırılar ve düzenleyici baskılar arasında, organizasyonlar uygulama ve API'lerinin güvenliğini sağlamak için etkin süreçler ve yetkinlikler oluşturmalıdır. Hali hazırda üretim ortamında olan uygulama ve API'lere ait aşırı düzeydeki kod miktarı düşünüldüğünde, pek çok organizasyon aşırı düzeydeki açıklıklar hakkında bilgi sahibi olmak için zorlanmaktadır.

OWASP, organizasyonların uygulama ve API'lerinin günveliği hakkında bilgi sahibi olmaları ve güvenliklerini artırmaları için bir uygulama güvenliği programı oluşturmalarını tavsiye etmektedir. Uygulama güvenliğinin sağlanması, güvenlik ve denetim, yazılım geliştirme, iş geliştirme ve üst yönetim gibi bir organizasyonun farklı pek çok kısmının etkin bir şekilde beraber çalışmasını gerektirmektedir. Güvenlik gözlemlenebilir ve ölçülebilir olmalıdır, böylece tüm farklı oyuncular organizasyonun güvenlik duruşunu görebilir ve anlayabilir. Açıklıkları gerçekten ortadan kaldırarak veya etkilerini azaltarak kurum güvenliğinin geliştirilmesine yardım eden faaliyetlere ve sonuçlara odaklanın. [OWASP SAMM](https://www.owasp.org/index.php/OWASP_SAMM_Project) ve [CISO'lar İçin OWASP Uygulama Güvenliği Rehberi](https://www.owasp.org/index.php/Application_Security_Guide_For_CISOs) bu listedeki pek çok önemli faaliyetin kaynağıdır.

### Başlayın

* Tüm uygulamaları ve ilgili veri varlıklarını belgelendirin. Daha büyük organizasyon bu amaç için bir Yapılandırma Yönetimi Veri Tabanı (CMDB) oluşturmayı düşünmelidir.
* Bir [uygulama güvenliği programı](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_1) oluşturun ve benimseyin.
* Ana gelişim alanlarını belirlemek için organizasyonunuzu benzer organizasyonlar ile kıyaslayarak bir [yetkinlik açığı analizi](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_3) yapın ve yürütme planı hazırlayın.
* Yönetim onayı alın ve IT organizasyonunun tamamı için bir [uygulama güvenliği farkındalık kampanyası](https://www.owasp.org/index.php/SAMM_-_Education_&_Guidance_-_1) oluşturun.

### Risk Tabanlı Portfolyö Yaklaşımı

* İş perspektifi ile [uygulama portfolyönüzün](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_2) [korunma ihtiyaçlarını](https://www.owasp.org/index.php/SAMM_-_Strategy_&_Metrics_-_2) belirleyin. Bu işlem korunan veri varlığı ile ilgili gizlilik yasaları ve diğer düzenlemelere göre parça parça yapılmalıdır.
* Tutarlı bir olasılık seti ve organizasyonunuzun risk toleransını yansıtan etki faktörleri seti ile bir ortak [risk derecelendirme modeli](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology) oluşturun. 
* Buna uygun olarak, tüm uygulama ve API'lerinizi ölçün ve önceliklendirin. Sonuçları CMDB veri tabanınıza ekleyin.
* Gereken özenin kapsamını ve düzeyini düzgün bir şekilde belirlemek için güvence yönergeleri oluşturun.

### Güçlü Bir Temele Oturtun

* Tüm geliştirme ekiplerinin uyguması için bir uygulama güvenliği çizgisi oluşturacak bir odaklı [politika ve standart](https://www.owasp.org/index.php/SAMM_-_Policy_&_Compliance_-_2) seti oluşturun.
* Bu politika ve standartlara uygun ve kullanımları hakkında tasarım ve geliştirme yönergeleri sağlayan ortak bir [tekrar kullanılabilir günvelik kontrolleri](https://www.owasp.org/index.php/OWASP_Security_Knowledge_Framework) seti tanımlayın.
* Zorunlu tutulacak ve farklı geliştirme rollerini ve konularını hedefleyecek bir [uygulama güvenliği eğitimi içeriği](https://www.owasp.org/index.php/SAMM_-_Education_&_Guidance_-_2) hazırlayın.

### Integrate Security into Existing Processes

* Define and integrate [secure implementation](https://www.owasp.org/index.php/SAMM_-_Construction) and [verification](https://www.owasp.org/index.php/SAMM_-_Verification) activities into existing development and operational processes. 
* Activities include [threat modeling](https://www.owasp.org/index.php/SAMM_-_Threat_Assessment_-_1), secure [design and design review](https://www.owasp.org/index.php/SAMM_-_Design_Review_-_1), secure coding and [code review](https://www.owasp.org/index.php/SAMM_-_Code_Review_-_1), [penetration testing](https://www.owasp.org/index.php/SAMM_-_Security_Testing_-_1), and remediation.
* Provide subject matter experts and [support services for development and project teams](https://www.owasp.org/index.php/SAMM_-_Education_&_Guidance_-_3) to be successful.

### Provide Management Visibility

* Manage with metrics. Drive improvement and funding decisions based on the metrics and analysis data captured. Metrics include adherence to security practices and activities, vulnerabilities introduced, vulnerabilities mitigated, application coverage, defect density by type and instance counts, etc.
* Analyze data from the implementation and verification activities to look for root cause and vulnerability patterns to drive strategic and systemic improvements across the enterprise. Learn from mistakes and offer positive incentives to promote improvements
