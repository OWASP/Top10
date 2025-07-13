# A9:2017 Bilinen Açıklık İçeren Bileşen Kullanımı

| Tehdit etkenleri/Saldırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 2 | Yaygınlık 3 : Tespit Edilebilirlik 2 | Teknik 2 : İş |
| Pek çok bilinen açıklık için yazılmış hazır istismarların bulunması kolay olsa da, diğer açıklıklar için özel bir istismarın geliştirilmesi özel çaba gerektirmektedir. | Bu sorun aşırı derece yaygındır. Bileşen yönünden zengin uygulamalar geliştirme takımlarının bileşenleri güncel tutamamasına ve hatta uygulama ve API'lerinde hangi bileşenlerin kullanıldığını unutmalarına yol açmaktadır. Retire.js gibi bazı tarama araçları tespitte yardımcı olmaktadır, ancak istismar edilebilirliğin tespiti ilave çaba gerektirmektedir. | Bazı bilinen açıklıklar sadece ufak etkilere yol açarken, şimdiye kadarki en büyük ihlallerin bazıları bileşenlerdeki bilinen açıklıkların istismarından kaynaklanmıştır. Korunmaya çalışılan varlıklara bağlı olarak, bu risk listede birinci sıraya çıkabilecektir. |

## Uygulamam Açıklık İçeriyor Mu?

Aşağıdaki durumlarda açıklıktan söz edilebilir:

* (Hem istemci tarafında hem de sunucu tarafında) kullandığınız tüm bileşenlerin versiyonlarını bilmiyorsanız. Bu doğrudan kullandıklarınıza ilave olarak bağımlı olarak kullandıklarınızı da içermektedir.
* Eğer yazılım açıklık içeriyorsa, desteklenmiyorsa veya güncel değilse. Bu işletim sistemini, web/uygulama sunucusunu, veri tabanı yönetim sistemini (DBMS), uygulamaları, API'leri ve tüm bileşenleri, çalışma ortamlarını ve kütüphaneleri içermektedir.
* Eğer düzenli olarak açıklıkları taramıyorsanız ve kullandığınız bileşenlerin güvenlik bültenlerini takip etmiyorsanız.
* Risk tabanlı ve düzenli bir şekilde, altta kullanılan platformu, çerçeveleri ve bağımlılıkları düzeltmiyor veya güncellemiyorsanız. Bu durum genellikle yamaların aylık veya üç aylık süreçlerde yapıldığı ortamlarda ortaya çıkmaktadır ve bu durum kurumların çözebileceği açıklıklara karşı günlerce veya aylarca gereksiz bir şekilde açık olmasına neden olmaktadır.
* Eğer yazılım geliştiriciler güncellenen, iyileştirilen veya yama yüklenen kütüphanelerin uyumluluğunu test etmiyorsa.
* Eğer bileşenlerin yapılandırması güvenli olarak yapılmıyorsa (bkz. **A6:2017-Yanlış Güvenlik Yapılandırması**).

## Nasıl Önlenir

Aşağıdakileri sağlayacak bir yama yönetim süreci bulunmalıdır:

* Kullanılmayan bağımlılıkların, gereksiz özelliklerin, bileşenlerin, dosyaların ve dokümantasyonun kaldırılması.
* Hem istemci taraflı hem de sunucu taraflı bileşenlerin (örn. çerçeveler, kütüphaneler) ve bunların bağımlılıklarının versions, DependencyCheck, retire.js vb. araçlar kullanılarak sürekli olarak sürüm envanterlerinin çıkarılması.
* Bileşenlerdeki açıklıklar için CVE ve NVD gibi kaynakların sürekli izlenmesi. Süreci otomatik hale getirmek için yazılım envanter analizi araçları kullanılmalıdır. Kullanılan bileşenlerle ilgili güvenlik açıklıkları için eposta alarmlarına abone olunmalıdır.
* Sadece güvenli bağlantılar üzerinden ve resmi kaynaklardan bileşen temini. Değiştirilmiş veya zararlı bir bileşenin alınması riskini azaltmak için imzalanmış paketler tercih edilmelidir.
* Desteklenmeyen veya eski sürümleri için güvenlik yamalarının çıkmadığı kütüphaneler ve bileşenlerin takibi. Eğer yamama mümkün değilse, tespit edilen açıklığa karşı izleme, tespit veya koruma yapılabilmesi için sanal bir yama uygulaması düşünülmelidir.

Tüm kurumlar, uygulamanın veya porfolyönün yaşam süresi boyunca devam eden bir izleme, derecelendirme ve güncelleme planlarının veya yapılandırma değişiklikleri uygulama planlarının olduğundan emin olmalıdır.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Bileşenler genellikle uygulamanın sahip olduğu yetkilerle çalışmaktadır, bu yüzden herhangi bir bileşendeki açıklık ciddi bir sonuç doğurabilmektedir. Bu tür açıklıklar farkında olunmadan (örn. kodlama hatası) veya bilinçli olarak (örn. bileşendeki bir arka kapı) ortaya çıkabilmektedir. Tespit edilen bazı istismar edilebilir bileşen açıklıkları şunlardır:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), Pek çok ihlal için suçlanan ve sunucu üzerinde isteğe bağlı kod çalıştırılmasına izin veren bir Struts 2 uzaktan kod çalıştırma açıklığı.
* [Nesnelerin İnterneti (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) yama açısından genellikle zor veya imkansız olsa da, yamalarının yüklenmesi çok önemli olabilmektedir (örn. biyomedikal cihazlar).

Yamaları eksik olan veya yanlış yapılandırılmış sistemlerin tespiti için saldırganlara yardım edecek otomatize araçlar bulunmaktadır. Örneğin, [Shodan IoT arama moturu](https://www.shodan.io/report/89bnfUyJ) Nisan 2014 tarihinde yaması çıkarılan [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) açıklığından hala etkilenen cihazları bulmanıza yardım etmektedir.

## Kaynaklar

### OWASP

* [OWASP Uygulama Güvenliği Doğrulama Standardı: V1 Mimari, tasarım ve tehdit modelleme](https://wiki.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (Java ve .NET kütüphaneleri için)](https://wiki.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Test Rehberi - Uygulama Mimarisinin Haritalanması (OTG-INFO-010)](https://wiki.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Sanal Yama En İyi Kullanım Örnekleri](https://wiki.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Dış Kaynaklar

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
