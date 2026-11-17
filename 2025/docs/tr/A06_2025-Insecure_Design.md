# A06:2025 Güvensiz Tasarım ![simge](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}


## Arka Plan. 

**[A02:2025-Güvenlik Yapılandırma Hataları](A02_2025-Security_Misconfiguration.md)** ve **[A03:2025-Yazılım Tedarik Zinciri Hataları](A03_2025-Software_Supply_Chain_Failures.md)** kategorilerinin önüne geçmesiyle Güvensiz Tasarım, sıralamada iki basamak gerileyerek 4. sıradan 6. sıraya indi. Bu kategori 2021'de eklendi; o zamandan bu yana sektörde tehdit modellemesi konusunda belirgin iyileşmeler gördük ve güvenli tasarıma daha fazla önem verildiğini gözlemledik. Bu kategori, tasarım ve mimari kusurlarla ilgili risklere odaklanır ve tehdit modellemesinin, güvenli tasarım kalıplarının ve referans mimarilerin daha fazla kullanılması çağrısında bulunur. Buna bir uygulamanın iş mantığındaki kusurlar da dahildir; ör. uygulama içinde istenmeyen veya beklenmeyen durum değişikliklerinin tanımlanmamış olması. Bir topluluk olarak, kodlama alanındaki "shift-left" (sola kaydırma) yaklaşımının ötesine geçip gereksinimlerin yazılması ve uygulama tasarımı gibi, Secure by Design (Tasarımdan Güvenli) ilkeleri açısından kritik olan kodlama öncesi faaliyetlere yönelmemiz gerekiyor (ör. bkz. **[Modern Bir AppSec Programı Oluşturmak: Planlama ve Tasarım Aşaması](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**). Öne çıkan Common Weakness Enumeration (CWE) kayıtları arasında *CWE-256: Unprotected Storage of Credentials, CWE-269 Improper Privilege Management, CWE-434 Unrestricted Upload of File with Dangerous Type, CWE-501: Trust Boundary Violation ve CWE-522: Insufficiently Protected Credentials* yer alır.


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
   <td>39
   </td>
   <td>22.18%
   </td>
   <td>1.86%
   </td>
   <td>88.76%
   </td>
   <td>35.18%
   </td>
   <td>6.96
   </td>
   <td>4.05
   </td>
   <td>729,882
   </td>
   <td>7,647
   </td>
  </tr>
</table>



## Açıklama. 

Güvensiz tasarım, “eksik veya etkisiz kontrol tasarımı” olarak ifade edilen farklı zayıflıkları temsil eden geniş bir kategoridir. Güvensiz tasarım, diğer tüm Top Ten risk kategorilerinin kaynağı değildir. Güvensiz tasarım ile güvensiz uygulama (implementation) arasında bir fark olduğunu unutmayın. Tasarım kusurlarını ve uygulama hatalarını bir nedenle birbirinden ayırıyoruz: Bunların kök nedenleri farklıdır, geliştirme sürecinin farklı zamanlarında ortaya çıkarlar ve farklı düzeltme yöntemleri gerektirirler. Güvenli bir tasarımda bile istismar edilebilecek güvenlik açıklarına yol açan uygulama hataları bulunabilir. Güvensiz bir tasarım ise kusursuz bir uygulamayla düzeltilemez; çünkü belirli saldırılara karşı savunma için gereken güvenlik kontrolleri hiç oluşturulmamıştır. Güvensiz tasarıma katkıda bulunan etkenlerden biri, geliştirilen yazılıma veya sisteme özgü iş riski profilinin çıkarılmaması ve dolayısıyla ne düzeyde bir güvenlik tasarımı gerektiğinin belirlenememesidir.

Güvenli bir tasarıma sahip olmanın üç temel bileşeni şunlardır:

* Gereksinimlerin Toplanması ve Kaynak Yönetimi
* Güvenli Bir Tasarım Oluşturma
* Güvenli Bir Geliştirme Yaşam Döngüsüne Sahip Olma


### Gereksinim ve Kaynak Yönetimi

Bir uygulamanın iş gereksinimlerini; tüm veri varlıklarının gizliliği, bütünlüğü, erişilebilirliği ve özgünlüğüne ilişkin koruma gereksinimleri ile beklenen iş mantığı da dahil olmak üzere iş birimleriyle birlikte toplayın ve müzakere edin. Uygulamanızın ne ölçüde dışa açık olacağını ve (erişim kontrolü için gerekenlerin ötesinde) kiracıların (tenant) birbirinden ayrılmasına ihtiyaç duyup duymadığınızı göz önünde bulundurun. İşlevsel ve işlevsel olmayan güvenlik gereksinimleri dahil teknik gereksinimleri derleyin. Güvenlik faaliyetleri dahil tüm tasarım, geliştirme, test ve operasyon süreçlerini kapsayan bütçeyi planlayın ve müzakere edin.


### Güvenli Tasarım

Güvenli tasarım, tehditleri sürekli olarak değerlendiren ve kodun bilinen saldırı yöntemlerini önleyecek şekilde sağlam biçimde tasarlanıp test edilmesini sağlayan bir kültür ve metodolojidir. Tehdit modellemesi, iyileştirme (refinement) oturumlarına (veya benzer faaliyetlere) entegre edilmelidir; veri akışlarındaki ve erişim kontrolündeki ya da diğer güvenlik kontrollerindeki değişikliklere dikkat edin. Kullanıcı hikâyesini (story) geliştirirken doğru akışı ve hata durumlarını belirleyin; bunların sorumlu ve etkilenen taraflarca iyi anlaşıldığından ve üzerinde mutabık kalındığından emin olun. Beklenen ve hatalı akışlara ilişkin varsayımları ve koşulları, doğru ve istenen nitelikte kalmalarını sağlamak için analiz edin. Varsayımların nasıl doğrulanacağını ve doğru davranış için gereken koşulların nasıl uygulanacağını belirleyin. Sonuçların kullanıcı hikâyesinde belgelendiğinden emin olun. Hatalardan ders çıkarın ve iyileştirmeleri desteklemek için olumlu teşvikler sunun. Güvenli tasarım, yazılıma sonradan eklenebilecek bir eklenti ya da araç değildir.


### Güvenli Geliştirme Yaşam Döngüsü

Güvenli yazılım; güvenli bir geliştirme yaşam döngüsü, güvenli bir tasarım kalıbı, hazır yol (paved road) metodolojisi, güvenli bir bileşen kütüphanesi, uygun araçlar, tehdit modellemesi ve süreci iyileştirmek için kullanılan olay sonrası değerlendirmeler (post-mortem) gerektirir. Bir yazılım projesinin başında, proje boyunca ve süregelen yazılım bakımı için güvenlik uzmanlarınıza başvurun. Güvenli yazılım geliştirme çalışmalarınızı yapılandırmak için [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/) modelinden yararlanmayı değerlendirin.

Geliştiricilerin kendi sorumluluklarının önemi çoğu zaman yeterince takdir edilmez. Farkındalık, sorumluluk ve proaktif risk azaltma kültürünü teşvik edin. Güvenlik üzerine düzenli fikir alışverişleri (ör. tehdit modellemesi oturumlarında), güvenliği tüm önemli tasarım kararlarına dahil eden bir zihniyet oluşturabilir.  


## Nasıl Önlenir. 



* Güvenlik ve gizlilikle ilgili kontrollerin değerlendirilmesine ve tasarlanmasına yardımcı olacak AppSec uzmanlarıyla birlikte güvenli bir geliştirme yaşam döngüsü oluşturun ve kullanın
* Güvenli tasarım kalıplarından veya hazır yol (paved-road) bileşenlerinden oluşan bir kütüphane oluşturun ve kullanın
* Kimlik doğrulama, erişim kontrolü, iş mantığı ve temel akışlar gibi uygulamanın kritik bölümleri için tehdit modellemesi kullanın
* Güvenlik zihniyeti oluşturmak için tehdit modellemesini bir eğitim aracı olarak kullanın
* Güvenlik dilini ve kontrollerini kullanıcı hikâyelerine entegre edin
* Uygulamanızın her katmanına (ön yüzden arka uca kadar) makullük (plausibility) kontrolleri entegre edin
* Tüm kritik akışların tehdit modeline karşı dayanıklı olduğunu doğrulamak için birim ve entegrasyon testleri yazın. Uygulamanızın her katmanı için kullanım senaryolarını (use-case) *ve* kötüye kullanım senaryolarını (misuse-case) derleyin.
* Maruziyete ve koruma ihtiyaçlarına bağlı olarak katmanları sistem ve ağ düzeyinde birbirinden ayırın
* Kiracıları (tenant) tüm katmanlarda tasarım gereği sağlam biçimde birbirinden ayırın


## Örnek Saldırı Senaryoları. 

**Senaryo #1:** Bir kimlik bilgisi kurtarma iş akışında NIST 800-63b, OWASP ASVS ve OWASP Top 10 tarafından yasaklanan “soru ve cevaplar” yöntemi bulunabilir. Cevapları birden fazla kişi bilebileceğinden soru ve cevaplara kimlik kanıtı olarak güvenilemez. Bu tür bir işlev kaldırılmalı ve daha güvenli bir tasarımla değiştirilmelidir.

**Senaryo #2:** Bir sinema zinciri grup rezervasyonlarında indirim uyguluyor ve depozito istemeden önce en fazla on beş kişilik rezervasyona izin veriyor. Saldırganlar bu akışın tehdit modelini çıkarıp uygulamanın iş mantığında bir saldırı vektörü bulup bulamayacaklarını test edebilir; örneğin birkaç istekle tüm sinemalarda aynı anda altı yüz koltuk rezerve ederek büyük bir gelir kaybına yol açabilirler.

**Senaryo #3:** Bir perakende zincirinin e-ticaret web sitesinde, üst segment ekran kartlarını açık artırma sitelerinde yeniden satmak üzere satın alan karaborsacıların çalıştırdığı botlara karşı koruma yoktur. Bu durum, ekran kartı üreticileri ve perakende zinciri sahipleri için son derece kötü bir imaj yaratır ve bu kartları hiçbir fiyata edinemeyen meraklılarla kalıcı bir husumete yol açar. Dikkatli bir bot karşıtı tasarım ve ürünün satışa çıkmasından sonraki birkaç saniye içinde yapılan satın almalar gibi alan mantığı kuralları, gerçek olmayan satın almaları tespit edip bu işlemleri reddedebilir.


## Kaynaklar.



* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## Eşlenen CWE'lerin Listesi

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)

* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)

* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)

* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)

* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)

* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)

* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

* [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)

* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)

* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)
