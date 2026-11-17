# A03:2025 Yazılım Tedarik Zinciri Hataları ![simge](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Arka Plan.

Bu kategori, Top 10 topluluk anketinde katılımcıların tam %50'si tarafından 1. sıraya konularak en üst sırada yer aldı. İlk olarak 2013 Top 10'da "A9 – Using Components with Known Vulnerabilities" (Bilinen Güvenlik Açıklarına Sahip Bileşenlerin Kullanılması) adıyla yer alan bu risk, o zamandan bu yana kapsamını genişleterek yalnızca bilinen güvenlik açıklarını içerenleri değil, tüm tedarik zinciri hatalarını kapsar hâle geldi. Kapsamın genişlemesine rağmen tedarik zinciri hatalarını tespit etmek hâlâ zordur; ilgili CWE'lere sahip yalnızca 11 Common Vulnerability and Exposures (CVE) kaydı bulunuyor. Bununla birlikte, katkı sağlanan verilerde test edilip raporlandığında bu kategori %5,19 ile en yüksek ortalama görülme oranına sahiptir. İlgili CWE'ler şunlardır: *CWE-477: Use of Obsolete Function, CWE-1104: Use of Unmaintained Third Party Components*, CWE-1329: *Reliance on Component That is Not Updateable* ve *CWE-1395: Dependency on Vulnerable Third-Party Component*.


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
   <td>6
   </td>
   <td>9.56%
   </td>
   <td>5.72%
   </td>
   <td>65.42%
   </td>
   <td>27.47%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>



## Açıklama.

Yazılım tedarik zinciri hataları, yazılımın derlenmesi, dağıtılması veya güncellenmesi sürecinde yaşanan aksaklıklar ya da diğer güvenlik ihlalleridir. Bu hatalar çoğunlukla sistemin dayandığı üçüncü taraf kodlardaki, araçlardaki veya diğer bağımlılıklardaki güvenlik açıklarından ya da kötü amaçlı değişikliklerden kaynaklanır.

Aşağıdaki durumlarda büyük olasılıkla savunmasızsınız:

* Kullandığınız tüm bileşenlerin (hem istemci hem sunucu tarafında) sürümlerini dikkatle takip etmiyorsanız. Buna doğrudan kullandığınız bileşenlerin yanı sıra iç içe geçmiş (geçişli/transitive) bağımlılıklar da dahildir.
* Yazılım savunmasızsa, desteklenmiyorsa veya güncel değilse. Buna işletim sistemi, web/uygulama sunucusu, veritabanı yönetim sistemi (DBMS), uygulamalar, API'ler ve tüm bileşenler, çalışma zamanı ortamları ve kütüphaneler dahildir.
* Düzenli olarak güvenlik açığı taraması yapmıyor ve kullandığınız bileşenlerle ilgili güvenlik bültenlerine abone olmuyorsanız.
* Tedarik zincirinizde bir değişiklik yönetimi süreciniz veya değişiklik takibiniz yoksa. Buna IDE'lerin, IDE eklentilerinin ve güncellemelerinin, kuruluşunuzun kod deposundaki değişikliklerin, sandbox'ların, imaj ve kütüphane depolarının, artifact'lerin oluşturulma ve saklanma biçiminin vb. takibi dahildir. Tedarik zincirinizin her parçası, özellikle de değişiklikler belgelenmelidir.
* Erişim kontrolüne ve en az yetki ilkesinin uygulanmasına özellikle odaklanarak tedarik zincirinizin her parçasını sıkılaştırmadıysanız.
* Tedarik zinciri sistemlerinizde hiçbir görevler ayrılığı yoksa. Hiç kimse, başka bir insanın denetimi olmadan kod yazıp bu kodu üretime kadar tek başına taşıyabilmemelidir.
* Teknoloji yığınının herhangi bir bölümünde güvenilmeyen kaynaklardan gelen bileşenler üretim ortamlarında kullanılıyor veya bu ortamları etkileyebiliyorsa.
* Altta yatan platformu, framework'leri ve bağımlılıkları riske dayalı olarak ve zamanında düzeltmiyor veya yükseltmiyorsanız. Bu durum genellikle yama işlemlerinin değişiklik kontrolü altında aylık veya üç aylık bir görev olarak yürütüldüğü ortamlarda görülür ve kuruluşları, güvenlik açıkları giderilene kadar günlerce ya da aylarca gereksiz yere risk altında bırakır.
* Yazılım geliştiriciler güncellenen, yükseltilen veya yamalanan kütüphanelerin uyumluluğunu test etmiyorsa.
* Sisteminizin her parçasının yapılandırmasını güvence altına almıyorsanız (bkz. [A02:2025-Güvenlik Yapılandırma Hataları](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
* CI/CD pipeline'ınız, özellikle karmaşık bir yapıdaysa, derleyip devreye aldığı sistemlerden daha zayıf bir güvenliğe sahipse.


## Nasıl Önlenir.

Aşağıdakileri sağlayan bir yama yönetimi süreci bulunmalıdır:



* Tüm yazılımlarınızın Yazılım Malzeme Listesini (SBOM) merkezi olarak oluşturmak ve yönetmek.
* Yalnızca doğrudan bağımlılıklarınızı değil, onların (geçişli) bağımlılıklarını ve zincirin devamını da takip etmek.
* Kullanılmayan bağımlılıkları, gereksiz özellikleri, bileşenleri, dosyaları ve belgeleri kaldırarak saldırı yüzeyini küçültmek.
* OWASP Dependency Track, OWASP Dependency Check, retire.js gibi araçlar kullanarak hem istemci hem de sunucu tarafı bileşenlerin (ör. framework'ler, kütüphaneler) ve bağımlılıklarının sürüm envanterini sürekli olarak çıkarmak.
* Kullandığınız bileşenlerdeki güvenlik açıkları için Common Vulnerability and Exposures (CVE), National Vulnerability Database (NVD) ve [Open Source Vulnerabilities (OSV)](https://osv.dev/) gibi kaynakları sürekli izlemek. Süreci otomatikleştirmek için yazılım bileşim analizi, yazılım tedarik zinciri veya güvenlik odaklı SBOM araçlarını kullanmak. Kullandığınız bileşenlerle ilgili güvenlik açığı uyarılarına abone olmak.
* Bileşenleri yalnızca resmî (güvenilir) kaynaklardan ve güvenli bağlantılar üzerinden edinmek. Değiştirilmiş, kötü amaçlı bir bileşenin dahil edilme olasılığını azaltmak için imzalı paketleri tercih etmek (bkz. [A08:2025-Yazılım ve Veri Bütünlüğü Hataları](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
* Bir bağımlılığın hangi sürümünü kullanacağınızı bilinçli olarak seçmek ve yalnızca gerektiğinde yükseltmek.
* Bakımı yapılmayan veya eski sürümleri için güvenlik yaması üretilmeyen kütüphaneleri ve bileşenleri izlemek. Yama uygulamak mümkün değilse alternatif bir çözüme geçmeyi değerlendirmek. Bu da mümkün değilse, keşfedilen sorunu izlemek, tespit etmek veya ona karşı koruma sağlamak için sanal yama (virtual patch) uygulamayı değerlendirmek.
* CI/CD, IDE ve diğer tüm geliştirici araçlarını düzenli olarak güncellemek
* Güncellemeleri tüm sistemlere aynı anda dağıtmaktan kaçınmak. Güvenilen bir tedarikçinin ele geçirilmesi ihtimaline karşı etki alanını sınırlamak için aşamalı dağıtımlar veya kanarya dağıtımları (canary deployment) kullanmak.


Aşağıdakilerde yapılan değişiklikleri takip etmek için bir değişiklik yönetimi süreci veya takip sistemi bulunmalıdır:

* CI/CD ayarları (tüm derleme araçları ve pipeline'lar)
* Kod depoları
* Sandbox alanları
* Geliştirici IDE'leri
* SBOM araçları ve oluşturulan artifact'ler
* Günlük kaydı sistemleri ve günlük kayıtları
* SaaS gibi üçüncü taraf entegrasyonlar
* Artifact depoları
* Konteyner kayıt defterleri (container registry)


MFA'yı etkinleştirmek ve IAM'i sıkı biçimde kısıtlamak dahil olmak üzere aşağıdaki sistemleri sıkılaştırın:

* Kod deponuz (gizli bilgilerin depoya eklenmemesi, branch'lerin korunması ve yedekleme dahil)
* Geliştirici iş istasyonları (düzenli yama, MFA, izleme ve daha fazlası)
* Derleme sunucunuz ve CI/CD (görevler ayrılığı, erişim kontrolü, imzalı derlemeler, ortama özgü gizli bilgiler, kurcalamayı belli eden (tamper-evident) günlük kayıtları ve daha fazlası)
* Artifact'leriniz (köken bilgisi (provenance), imzalama ve zaman damgası ile bütünlüğü sağlayın; her ortam için yeniden derlemek yerine artifact'leri bir sonraki ortama taşıyın (promote); derlemelerin değiştirilemez olmasını sağlayın)
* Kod olarak altyapı (PR'lar ve sürüm kontrolü kullanımı dahil, diğer tüm kodlar gibi yönetilmelidir)

Her kuruluş, uygulamanın veya portföyün yaşam süresi boyunca güncellemeleri ya da yapılandırma değişikliklerini izlemek, önceliklendirmek ve uygulamak için sürekli bir plan bulunduğundan mutlaka emin olmalıdır.


## Örnek Saldırı Senaryoları.

**Senaryo #1:** Güvenilen bir tedarikçi kötü amaçlı yazılımla ele geçirilir ve siz yükseltme yaptığınızda bilgisayar sistemleriniz de ele geçirilir. Bunun en bilinen örneği muhtemelen şudur:



* Yaklaşık 18.000 kuruluşun ele geçirilmesine yol açan 2019 SolarWinds saldırısı. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Senaryo #2:** Güvenilen bir tedarikçi, yalnızca belirli bir koşul altında kötü amaçlı davranacak şekilde ele geçirilir.



* 2025'te Bybit'ten 1,5 milyar dolar çalınmasına, yalnızca hedef cüzdan kullanılırken devreye giren [cüzdan yazılımındaki bir tedarik zinciri saldırısı](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/) yol açtı.

**Senaryo #3:** 2025'teki [`Shai-Hulud` tedarik zinciri saldırısı](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem), kendi kendine yayılan ilk başarılı npm solucanıydı. Saldırganlar popüler paketlerin kötü amaçlı sürümlerini yaydı; bu sürümler, hassas verileri toplayıp herkese açık GitHub depolarına sızdırmak için kurulum sonrası (post-install) bir betik kullanıyordu. Kötü amaçlı yazılım ayrıca kurbanın ortamındaki npm token'larını tespit ediyor ve bunları, erişilebilen herhangi bir paketin kötü amaçlı sürümlerini yayımlamak için otomatik olarak kullanıyordu. Solucan, npm tarafından durdurulmadan önce 500'den fazla paket sürümüne ulaştı. Gelişmiş, hızla yayılan ve zarar verici olan bu tedarik zinciri saldırısı, geliştirici makinelerini hedef alarak artık geliştiricilerin kendilerinin de tedarik zinciri saldırılarının birincil hedefleri arasında olduğunu gösterdi.

**Senaryo #4:** Bileşenler genellikle uygulamanın kendisiyle aynı yetkilerle çalıştığından herhangi bir bileşendeki kusur ciddi sonuçlar doğurabilir. Bu tür kusurlar kazara (ör. kodlama hatası) veya kasıtlı (ör. bir bileşendeki arka kapı) olabilir. Keşfedilmiş, istismar edilebilir bileşen güvenlik açıklarına bazı örnekler şunlardır:

* Saldırganın sunucuda istediği kodu çalıştırmasına olanak tanıyan bir Struts 2 uzaktan kod çalıştırma güvenlik açığı olan CVE-2017-5638, önemli ihlallerin sorumlusu olarak gösterilmiştir.
* Bir Apache Log4j uzaktan kod çalıştırma sıfırıncı gün (zero-day) güvenlik açığı olan CVE-2021-44228 ("Log4Shell"), fidye yazılımı, kripto para madenciliği ve diğer saldırı kampanyalarının sorumlusu olarak gösterilmiştir.


## Kaynaklar

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (Java ve .NET kütüphaneleri için)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) araması](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Bilinen güvenlik açıklarına sahip JavaScript kütüphanelerini tespit etmek için Retire.js](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm tedarik zinciri saldırısı](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven tedarik zinciri saldırı kampanyası](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## Eşlenen CWE'lerin Listesi

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
