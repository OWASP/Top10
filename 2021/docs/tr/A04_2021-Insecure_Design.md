# A04:2021 – Insecure Design   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Eşleştirildi | Maks Görülme Oranı | Ort. Görülme Oranı | Ort. Ağırlıklı Exploit | Ort. Ağırlıklı Impact | Maks Coverage | Ort. Coverage | Toplam Olay | Toplam CVE |
| :---------------: | :----------------: | :----------------: | :--------------------: | :-------------------: | :-----------: | :-----------: | :---------: | :--------: |
|         40        |       24.19%       |        3.00%       |          6.46          |          6.78         |     77.25%    |     42.51%    |   262,407   |    2,691   |

## Genel Bakış

2021 için yeni bir kategori, tasarım ve mimari hatalarla ilgili risklere odaklanır ve threat modeling, secure design patterns ve reference architectures kullanımının artırılmasını çağrılar. Topluluk olarak, coding alanındaki “shift-left” yaklaşımını aşarak, Secure by Design prensipleri için kritik olan kod-öncesi aktivitelere yönelmemiz gerekir. Dikkate değer Common Weakness Enumerations (CWE) örnekleri arasında *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation* ve *CWE-522: Insufficiently Protected Credentials* bulunur.

## Açıklama

Insecure design, “eksik veya etkisiz control design” olarak ifade edilen farklı zayıflıkları kapsayan geniş bir kategoridir. Insecure design, diğer Top 10 risk kategorilerinin kaynağı değildir. Insecure design ile insecure implementation arasında fark vardır; farklı root cause’lara ve remediation’lara sahiptirler. Güvenli bir design, yine de exploit edilebilecek implementation defect’leri içerebilir. Tanım gereği belirli saldırılara karşı gerekli security control’leri hiç oluşturulmadığından, insecure design mükemmel bir implementation ile düzeltilemez. Insecure design’a katkıda bulunan faktörlerden biri, geliştirilen yazılım veya sistemin doğasında bulunan business risk profiling eksikliği ve buna bağlı olarak hangi seviyede security design gerektiğinin belirlenememesidir.

### Requirements and Resource Management

Bir uygulama için business gereksinimlerini, tüm data asset’lerinin gizlilik, bütünlük, süreklilik (availability) ve doğrulanabilirlik (authenticity) koruma gereksinimleri ve beklenen business logic dâhil olacak şekilde business tarafıyla toplayın ve müzakere edin. Uygulamanızın ne kadar exposed olacağını ve tenant ayrımı (access control’a ek olarak) gerekip gerekmediğini hesaba katın. Functional ve non-functional security requirement’ları dâhil teknik gereksinimleri derleyin. Design, build, testing ve operation aşamalarının tamamını, security aktiviteleriyle birlikte kapsayacak bütçeyi planlayın ve müzakere edin.

### Secure Design

Secure design; tehditleri sürekli değerlendiren ve kodu bilinen attack method’larına karşı sağlam olacak şekilde tasarlayıp test eden bir kültür ve metodolojidir. Threat modeling, refinement session’larına (veya benzer aktivitelere) entegre edilmelidir; data flow’lar ve access control veya diğer security control’lerdeki değişikliklere bakın. User story geliştirme sırasında doğru akışı ve failure state’lerini belirleyin; sorumlu ve etkilenen taraflarca iyi anlaşıldığından ve üzerinde mutabık kalındığından emin olun. Varsayımları ve koşulları hem beklenen hem de failure flow’ları için analiz edin; hâlâ doğru ve arzu edilir olduklarını doğrulayın. Varsayımların nasıl validate edileceğini ve doğru davranışlar için gerekli koşulların nasıl enforce edileceğini belirleyin. Sonuçların user story içinde dokümante edilmesini sağlayın. Hatalardan öğrenin ve iyileştirmeleri teşvik etmek için pozitif teşvikler sunun. Secure design, yazılıma sonradan eklenebilecek bir eklenti ya da bir tool değildir.

### Secure Development Lifecycle

Güvenli yazılım, bir Secure Development Lifecycle, bir tür secure design pattern, paved road methodology, secured component library, tooling ve threat modeling gerektirir. Yazılım projesinin en başından tüm proje ve bakım süreci boyunca security specialist’lerinize ulaşın. Güvenli yazılım geliştirme çabalarınızı yapılandırmaya yardımcı olması için [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) kullanılmasını düşünün.

## Nasıl Önlenir

* AppSec profesyonelleriyle birlikte security ve privacy-related control’lerin değerlendirilip tasarlanacağı bir Secure Development Lifecycle kurun ve kullanın.

* Kullanıma hazır secure design patterns veya paved road component’larından oluşan bir kütüphane oluşturun ve kullanın.

* Kritik authentication, access control, business logic ve ana akışlar için threat modeling uygulayın.

* Security dilini ve control’lerini user story’lere entegre edin.

* Uygulamanızın her katmanında (frontend’den backend’e) plausibility check’leri entegre edin.

* Tüm kritik akışların threat model’e karşı dirençli olduğunu validate edecek unit ve integration test’leri yazın. Her katman için use-case *ve* misuse-case’leri derleyin.

* Maruziyete ve korunma ihtiyaçlarına bağlı olarak system ve network katmanlarında tier’ları ayırın (segregate).

* Tüm katmanlarda tenant’ları tasarım gereği güçlü şekilde ayırın.

* Kullanıcı veya servis başına resource consumption’ı sınırlayın.

## Örnek Saldırı Senaryoları

**Senaryo #1:** Bir credential recovery workflow’u “güvenlik soruları ve cevapları” içeriyor; bu yöntem NIST 800-63b, OWASP ASVS ve OWASP Top 10 tarafından yasaktır. Birden fazla kişi cevapları bilebileceği için kimlik kanıtı olarak güvenilemezler. Bu kod kaldırılmalı ve daha güvenli bir design ile değiştirilmelidir.

**Senaryo #2:** Bir sinema zinciri, grup rezervasyonlarında indirim sunuyor ve depozito gerektirmeden önce maksimum on beş katılımcı limiti var. Saldırganlar bu akışı threat model ile analiz ederek az sayıda istekle altı yüz koltuk ve tüm sinemaları aynı anda rezerve etmeyi test edebilir; bu da büyük gelir kaybına yol açar.

**Senaryo #3:** Bir perakende zincirinin e-ticaret sitesi, scalper’ların yüksek seviye ekran kartlarını satın almak için çalıştırdığı bot’lara karşı korumaya sahip değil. Bu durum, ekran kartı üreticileri ve perakende zinciri için kötü bir PR yaratır ve bu kartlara hiçbir fiyata ulaşamayan meraklılarla kalıcı bir husumete neden olur. Dikkatli anti-bot design ve domain logic kuralları (örneğin, stok açıldıktan saniyeler içinde yapılan satın alımlar) sahte satın alımları tespit edip bu işlemleri reddedebilir.

## Referanslar

* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

* [OWASP SAMM: Design\:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

* [OWASP SAMM: Design\:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)

* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## Eşleştirilen CWE Listesi

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)
[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)
[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)
[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)
[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)
[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)
[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)
[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)
[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)
[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)
[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)
[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)

