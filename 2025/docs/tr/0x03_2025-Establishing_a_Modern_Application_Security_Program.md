# Modern Bir Uygulama Güvenliği Programı Oluşturmak

OWASP Top Ten listeleri, ele aldıkları konudaki en kritik risklere dikkat çekmeyi amaçlayan farkındalık belgeleridir. Eksiksiz bir liste olma iddiası taşımazlar; yalnızca bir başlangıç noktasıdırlar. Bu listenin önceki sürümlerinde, bu risklerden ve daha fazlasından kaçınmanın en iyi yolu olarak bir uygulama güvenliği programı başlatmayı önermiştik. Bu bölümde modern bir uygulama güvenliği programının nasıl başlatılıp oluşturulacağını ele alacağız.

 

Halihazırda bir uygulama güvenliği programınız varsa [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) veya DSOMM (DevSecOps Maturity Model) kullanarak programınızın olgunluk değerlendirmesini yapmayı düşünün. Bu olgunluk modelleri kapsamlı ve ayrıntılıdır; programınızı genişletmek ve olgunlaştırmak için çabalarınızı en iyi nereye odaklamanız gerektiğini belirlemenize yardımcı olabilir. Lütfen unutmayın: İyi bir iş çıkarmak için OWASP SAMM veya DSOMM'deki her şeyi yapmanız gerekmez; bu modeller size yol göstermek ve birçok seçenek sunmak için tasarlanmıştır. Ulaşılamaz standartlar koymak veya karşılanamayacak maliyette programlar tarif etmek gibi bir amaçları yoktur. Size çok sayıda fikir ve seçenek sunabilmek için geniş kapsamlı tutulmuşlardır.

 

Sıfırdan bir program başlatıyorsanız ya da OWASP SAMM veya DSOMM'yi şu an için ekibiniz açısından ‘fazla’ buluyorsanız, lütfen aşağıdaki önerileri inceleyin.


### 1. Riske Dayalı Bir Portföy Yaklaşımı Benimseyin:

* Uygulama portföyünüzün koruma ihtiyaçlarını iş perspektifinden belirleyin. Bu süreç kısmen, korunan veri varlığıyla ilgili gizlilik yasalarına ve diğer düzenlemelere göre şekillenmelidir.

* Kuruluşunuzun risk toleransını yansıtan, tutarlı bir olasılık ve etki faktörleri kümesine sahip [ortak bir risk derecelendirme modeli](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) oluşturun.


* Tüm uygulamalarınızı ve API'lerinizi buna göre ölçün ve önceliklendirin. Sonuçları [Yapılandırma Yönetimi Veritabanınıza (CMDB)](https://de.wikipedia.org/wiki/Configuration_Management_Database) ekleyin.

* Gereken kapsamı ve titizlik düzeyini doğru biçimde tanımlamak için güvence yönergeleri oluşturun.


### 2. Sağlam Bir Temel Oluşturun:

* Tüm geliştirme ekiplerinin uyması gereken asgari uygulama güvenliği gereksinimlerini (baseline) belirleyen, odaklı politikalar ve standartlar oluşturun.

* Bu politika ve standartları tamamlayan, yeniden kullanılabilir ortak güvenlik kontrolleri tanımlayın ve bunların kullanımına ilişkin tasarım ve geliştirme rehberliği sağlayın.

* Zorunlu tutulan ve farklı geliştirme rollerine ve konularına göre hedeflenmiş bir uygulama güvenliği eğitim müfredatı oluşturun.


### 3. Güvenliği Mevcut Süreçlere Entegre Edin:

* Güvenli uygulama geliştirme ve doğrulama faaliyetlerini tanımlayın ve mevcut geliştirme ve operasyon süreçlerine entegre edin.

* Bu faaliyetler arasında tehdit modellemesi, güvenli tasarım ve tasarım incelemesi, güvenli kodlama ve kod incelemesi, sızma testi ve düzeltme yer alır.

* Geliştirme ve proje ekiplerinin başarılı olabilmesi için konu uzmanları ve destek hizmetleri sağlayın.

* Mevcut sistem geliştirme yaşam döngünüzü ve tüm yazılım güvenliği faaliyetlerini, araçlarını, politikalarını ve süreçlerini gözden geçirin, ardından bunları belgeleyin.

* Yeni yazılımlar için sistem geliştirme yaşam döngüsünün (SDLC) her aşamasına bir veya daha fazla güvenlik faaliyeti ekleyin. Neler yapabileceğinize dair birçok öneriyi aşağıda sunuyoruz. Bu yeni faaliyetleri her yeni projede veya yazılım girişiminde uyguladığınızdan emin olun; böylece her yeni yazılımın kuruluşunuz için kabul edilebilir bir güvenlik duruşuyla teslim edileceğini bilirsiniz.

* Faaliyetlerinizi, nihai ürününüzün kuruluşunuz için kabul edilebilir bir risk düzeyini karşılamasını sağlayacak şekilde seçin.

* Mevcut yazılımlar (bazen eski/legacy yazılımlar olarak da adlandırılır) için resmî bir bakım planına ihtiyaç duyacaksınız; güvenli uygulamaların bakımının nasıl yapılacağına dair fikirler için aşağıdaki 'Operasyon ve Değişiklik Yönetimi' bölümüne bakın.


### 4. Uygulama Güvenliği Eğitimi:

* Geliştiricilerinize bilmelerini istediğiniz her şeyi öğretmek için bir güvenlik şampiyonu (security champion) programı ya da genel bir güvenlik eğitimi programı (bazen savunuculuk veya güvenlik farkındalığı programı olarak da adlandırılır) başlatmayı düşünün. Bu sayede geliştiricileriniz güncel kalır, işlerini güvenli bir şekilde nasıl yapacaklarını öğrenir ve çalıştığınız yerdeki güvenlik kültürü daha olumlu bir hâl alır. Bu tür programlar çoğu zaman ekipler arasındaki güveni de artırır ve daha keyifli bir çalışma ilişkisi oluşturur. OWASP, adım adım genişletilen [OWASP Security Champions Guide](https://securitychampions.owasp.org/) ile bu konuda size destek olur.

* OWASP Education Project, geliştiricileri web uygulaması güvenliği konusunda eğitmeye yardımcı olan eğitim materyalleri sunar. Güvenlik açıklarını uygulamalı olarak öğrenmek için [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/) veya [OWASP WebGoat](https://owasp.org/www-project-webgoat/) projelerini deneyin. Güncel kalmak için bir [OWASP AppSec Konferansına](https://owasp.org/events/), [OWASP Konferans Eğitimlerine](https://owasp.org/events/) veya [OWASP yerel bölüm (Chapter)](https://owasp.org/chapters/) toplantılarına katılın.


### 5. Yönetime Görünürlük Sağlayın:

* Metriklerle yönetin. İyileştirme ve bütçe kararlarını toplanan metriklere ve analiz verilerine dayandırın. Metrikler arasında güvenlik uygulamalarına ve faaliyetlerine uyum, ortaya çıkan güvenlik açıkları, giderilen güvenlik açıkları, uygulama kapsamı, türe göre kusur yoğunluğu ve örnek sayıları gibi ölçütler yer alır.

* Kurum genelinde stratejik ve sistemik iyileştirmelere yön vermek için uygulama geliştirme ve doğrulama faaliyetlerinden elde edilen verileri analiz ederek kök nedenleri ve güvenlik açığı örüntülerini arayın. Hatalardan ders çıkarın ve iyileştirmeleri desteklemek için olumlu teşvikler sunun.



## Tekrarlanabilir Güvenlik Süreçleri ve Standart Güvenlik Kontrolleri Oluşturun ve Kullanın

### Gereksinim ve Kaynak Yönetimi Aşaması:

* Bir uygulamanın iş gereksinimlerini; tüm veri varlıklarının gizliliği, özgünlüğü, bütünlüğü ve erişilebilirliğine ilişkin koruma gereksinimleri ile beklenen iş mantığı da dahil olmak üzere iş birimleriyle birlikte toplayın ve müzakere edin.

* İşlevsel ve işlevsel olmayan güvenlik gereksinimleri dahil teknik gereksinimleri derleyin. OWASP, uygulamanızın/uygulamalarınızın güvenlik gereksinimlerini belirlerken [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) standardını rehber olarak kullanmanızı önerir.

* Güvenlik faaliyetleri dahil tasarım, geliştirme, test ve operasyonun tüm yönlerini kapsayan bütçeyi planlayın ve müzakere edin.

* Güvenlik faaliyetlerini proje takviminize ekleyin.

* Projenin başlangıç toplantısında kendinizi güvenlik temsilcisi olarak tanıtın; böylece ekip kiminle iletişim kuracağını bilir.


### Teklif Talebi (RFP) ve Sözleşme Süreci:

* Gereksinimleri, güvenlik programınıza ilişkin yönergeler ve güvenlik gereksinimleri (ör. SDLC, en iyi uygulamalar) dahil olmak üzere iç veya dış geliştiricilerle müzakere edin.

*  Planlama ve tasarım aşaması dahil tüm teknik gereksinimlerin karşılanma düzeyini değerlendirin.

*  Tasarım, güvenlik ve hizmet seviyesi anlaşmaları (SLA) dahil tüm teknik gereksinimleri müzakere edin.

*  [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex) gibi şablonları ve kontrol listelerini benimseyin.<br>**Not:** *Bu ek, ABD sözleşme hukukuna göre hazırlanmıştır; bu nedenle örnek eki kullanmadan önce lütfen yetkin bir hukuk danışmanına başvurun.*


### Planlama ve Tasarım Aşaması:

*  Planlama ve tasarımı geliştiricilerle ve iç paydaşlarla (ör. güvenlik uzmanları) müzakere edin.

* Koruma ihtiyaçlarına ve beklenen tehdit düzeyine uygun güvenlik mimarisini, kontrolleri, karşı önlemleri ve tasarım incelemelerini tanımlayın. Bu çalışma güvenlik uzmanları tarafından desteklenmelidir.

* Güvenliği uygulamalarınıza ve API'lerinize sonradan eklemek yerine baştan tasarıma dahil etmek çok daha uygun maliyetlidir. OWASP, güvenliğin en başından tasarıma nasıl dahil edileceğine ilişkin rehberlik için [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) ve [OWASP Proactive Controls](https://top10proactive.owasp.org/) kaynaklarını iyi bir başlangıç noktası olarak önerir.

*  Tehdit modellemesi yapın; bkz. [OWASP Cheat Sheet: Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

*  Yazılım mimarlarınıza güvenli tasarım kavramlarını ve kalıplarını öğretin ve bunları mümkün olan yerlerde tasarımlarına eklemelerini isteyin.

*  Veri akışlarını geliştiricilerinizle birlikte inceleyin.

*  Diğer tüm kullanıcı hikâyelerinizin yanına güvenlik kullanıcı hikâyeleri de ekleyin.


### Güvenli Geliştirme Yaşam Döngüsü:


* Kuruluşunuzun uygulama ve API geliştirirken izlediği süreci iyileştirmek için OWASP, [OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/) modelini önerir. Bu model, kuruluşların karşı karşıya oldukları özgül risklere göre uyarlanmış bir yazılım güvenliği stratejisi oluşturmalarına ve uygulamalarına yardımcı olur.

*  Yazılım geliştiricilerinize güvenli kodlama eğitimi ve daha sağlam ve güvenli uygulamalar oluşturmalarına yardımcı olacağını düşündüğünüz diğer eğitimleri verin.

*  Kod incelemesi: bkz. [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).

*  Geliştiricilerinize güvenlik araçları sağlayın ve bunları nasıl kullanacaklarını öğretin; özellikle statik analiz, yazılım bileşim analizi, gizli bilgi (secret) ve [Kod Olarak Altyapı (IaC)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) tarayıcıları.

*  Mümkünse geliştiricileriniz için koruma bariyerleri (guardrails) oluşturun (onları daha güvenli seçimlere yönlendiren teknik önlemler).

*   Güçlü ve kullanılabilir güvenlik kontrolleri oluşturmak zordur. Mümkün olan her durumda güvenli varsayılanlar sunun ve ‘hazır yollar’ (paved roads) oluşturun; yani bir işi yapmanın en kolay yolunu aynı zamanda en güvenli ve açıkça tercih edilen yol hâline getirin. [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) geliştiriciler için iyi bir başlangıç noktasıdır; ayrıca günümüzde birçok modern framework yetkilendirme, doğrulama, CSRF önleme vb. için standart ve etkili güvenlik kontrolleriyle birlikte gelir.

*  Geliştiricilerinize güvenlikle ilgili IDE eklentileri sağlayın ve bunları kullanmaya teşvik edin.

*  Onlara bir gizli bilgi (secret) yönetim aracı, lisanslar ve aracın nasıl kullanılacağına dair belgeler sağlayın.

*  Kullanmaları için onlara özel (private) bir yapay zekâ sağlayın. Bu yapay zekâ ideal olarak faydalı güvenlik belgeleriyle dolu bir RAG sunucusu, ekibinizin daha iyi sonuçlar için yazdığı prompt'lar ve kuruluşunuzun tercih ettiği güvenlik araçlarını çağıran bir MCP sunucusuyla yapılandırılmış olmalıdır. Onlara yapay zekâyı güvenli bir şekilde nasıl kullanacaklarını öğretin; çünkü siz isteseniz de istemeseniz de yapay zekâ kullanacaklar.


### Sürekli Uygulama Güvenliği Testi Oluşturun:

*  Teknik işlevleri ve BT mimarisiyle entegrasyonu test edin; iş testlerini koordine edin.

* Teknik ve iş perspektiflerinden “kullanım” ve “kötüye kullanım” test senaryoları oluşturun.

* Güvenlik testlerini iç süreçlere, koruma ihtiyaçlarına ve uygulama için öngörülen tehdit düzeyine göre yönetin.

* Güvenlik test araçları (fuzzer'lar, DAST vb.), test yapılabilecek güvenli bir ortam ve bu araçların nasıl kullanılacağına dair eğitim sağlayın YA DA testleri onlar adına siz yapın YA DA bir test uzmanı tutun

*  Yüksek düzeyde güvenceye ihtiyacınız varsa resmî bir sızma testinin yanı sıra stres testi ve performans testi yapmayı da düşünün.

*  Hata raporlarından hangilerini düzeltmeleri gerektiğine karar vermelerinde geliştiricilerinizle birlikte çalışın ve yöneticilerinin bunun için onlara zaman tanımasını sağlayın.


### Devreye Alma:

* Uygulamayı devreye alın ve gerekirse daha önce kullanılan uygulamalardan geçişi gerçekleştirin.

* Değişiklik yönetimi veritabanı (CMDB) ve güvenlik mimarisi dahil tüm belgeleri tamamlayın.


### Operasyon ve Değişiklik Yönetimi:

*  Operasyon süreçleri, uygulamanın güvenlik yönetimine ilişkin yönergeleri (ör. yama yönetimi) mutlaka içermelidir.

*  Kullanıcıların güvenlik farkındalığını artırın ve kullanılabilirlik ile güvenlik arasındaki çatışmaları yönetin.

*  Değişiklikleri planlayın ve yönetin; ör. uygulamanın veya işletim sistemi, ara katman yazılımı (middleware) ve kütüphaneler gibi diğer bileşenlerin yeni sürümlerine geçiş.

*  Tüm uygulamaların, önemli ayrıntılarının tamamı belgelenmiş şekilde envanterinizde yer aldığından emin olun. CMDB'deki kayıtlar, güvenlik mimarisi, kontroller ve karşı önlemler ile runbook'lar ve proje belgeleri dahil tüm belgeleri güncelleyin.

*  Tüm uygulamalar için günlük kaydı, izleme ve uyarı mekanizmalarını işletin. Eksikse ekleyin.

*  Etkili ve verimli güncelleme ve yama süreçleri oluşturun.

*  Düzenli tarama takvimleri oluşturun (tercihen dinamik, statik, gizli bilgi (secret), IaC ve yazılım bileşim analizi taramaları).

*  Güvenlik hatalarının düzeltilmesi için SLA'lar belirleyin.

*  Çalışanların (ve ideal olarak müşterilerinizin de) hata bildirebileceği bir yol sağlayın.

*  Yazılım saldırılarının neye benzediğini bilen ve gözlemlenebilirlik araçlarına hâkim, eğitimli bir olay müdahale ekibi oluşturun.

*  Otomatik saldırıları durdurmak için engelleme veya koruma araçları çalıştırın.

*  Yapılandırmaları yılda bir (veya daha sık) sıkılaştırın.

*  En az yılda bir sızma testi yapın (uygulamanız için gereken güvence düzeyine bağlı olarak).

*  Yazılım tedarik zincirinizi sıkılaştırmak ve korumak için süreçler ve araçlar oluşturun.

*  En önemli uygulamalarınızı ve bunların bakımı için kullandığınız araçları kapsayan iş sürekliliği ve felaket kurtarma planları oluşturun ve güncel tutun.


### Sistemlerin Kullanımdan Kaldırılması:

* Gerekli tüm veriler arşivlenmelidir. Diğer tüm veriler güvenli bir şekilde silinmelidir.

* Kullanılmayan hesapları, rolleri ve izinleri silmek de dahil olmak üzere uygulamayı güvenli bir şekilde kullanımdan kaldırın.

* CMDB'de uygulamanızın durumunu "kullanımdan kaldırıldı" olarak işaretleyin.


## OWASP Top 10'u Standart Olarak Kullanmak

OWASP Top 10 öncelikle bir farkındalık belgesidir. Ancak bu durum, kuruluşların 2003'teki ilk yayımından bu yana onu fiilî bir sektör uygulama güvenliği (AppSec) standardı olarak kullanmasının önüne geçmemiştir. OWASP Top 10'u bir kodlama veya test standardı olarak kullanmak istiyorsanız, bunun yalnızca asgari düzeyi temsil ettiğini ve sadece bir başlangıç noktası olduğunu bilin.

OWASP Top 10'u standart olarak kullanmanın zorluklarından biri, belgelediğimiz şeylerin uygulama güvenliği riskleri olması ve bunların her zaman kolayca test edilebilir sorunlar olmamasıdır. Örneğin [A06:2025-Güvensiz Tasarım](A06_2025-Insecure_Design.md) çoğu test türünün kapsamı dışındadır. Bir başka örnek, günlük kaydı ve izleme mekanizmalarının devreye alınıp alınmadığının, fiilen kullanılıp kullanılmadığının ve etkili olup olmadığının test edilmesidir; bu ancak görüşmeler yapılarak ve etkili olay müdahalelerinden örnekler istenerek yapılabilir. Statik kod analizi aracı günlük kaydının bulunmadığı yerleri arayabilir; ancak iş mantığının veya erişim kontrolünün kritik güvenlik ihlallerini günlüğe kaydedip kaydetmediğini belirlemek imkânsız olabilir. Sızma testi uzmanları ise yalnızca bir test ortamında olay müdahalesini tetikleyip tetiklemediklerini belirleyebilir; test ortamları da nadiren üretim ortamıyla aynı şekilde izlenir.

OWASP Top 10'un hangi durumlarda kullanılmasının uygun olduğuna ilişkin önerilerimiz aşağıdadır:


<table>
  <tr>
   <td><strong>Kullanım Alanı</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>OWASP Application Security Verification Standard</strong>
   </td>
  </tr>
  <tr>
   <td>Farkındalık
   </td>
   <td>Evet
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Eğitim
   </td>
   <td>Başlangıç düzeyi
   </td>
   <td>Kapsamlı
   </td>
  </tr>
  <tr>
   <td>Tasarım ve mimari
   </td>
   <td>Zaman zaman
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Kodlama standardı
   </td>
   <td>Asgari düzey
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Güvenli kod incelemesi
   </td>
   <td>Asgari düzey
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Akran incelemesi kontrol listesi
   </td>
   <td>Asgari düzey
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Birim testi
   </td>
   <td>Zaman zaman
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Entegrasyon testi
   </td>
   <td>Zaman zaman
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Sızma testi
   </td>
   <td>Asgari düzey
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Araç desteği
   </td>
   <td>Asgari düzey
   </td>
   <td>Evet
   </td>
  </tr>
  <tr>
   <td>Güvenli tedarik zinciri
   </td>
   <td>Zaman zaman
   </td>
   <td>Evet
   </td>
  </tr>
</table>


Bir uygulama güvenliği standardı benimsemek isteyen herkesi [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) kullanmaya teşvik ediyoruz; çünkü ASVS doğrulanabilir ve test edilebilir olacak şekilde tasarlanmıştır ve güvenli geliştirme yaşam döngüsünün tüm aşamalarında kullanılabilir.

Araç üreticileri için kabul edilebilir tek seçenek ASVS'dir. [A06:2025-Güvensiz Tasarım](A06_2025-Insecure_Design.md) örneğinde görüldüğü gibi, OWASP Top 10 risklerinin birçoğunun doğası gereği araçlar OWASP Top 10'u kapsamlı biçimde tespit edemez, test edemez veya bunlara karşı koruma sağlayamaz. OWASP, OWASP Top 10'un tamamen kapsandığına dair iddiaları desteklemez; çünkü bu tür iddialar düpedüz gerçeği yansıtmaz.
