# +A: Uygulama Yöneticileri için Bir Sonraki Adım

## Bütün Uygulama Yaşam Döngüsünü Yönetin

Uygulamalar, insanların düzenli olarak oluşturduğu ve sürdürdüğü en karmaşık sistemlere aittir. Bir uygulama için IT yönetimi, bir uygulamanın bütün IT yaşam döngüsü için sorumlu olan IT uzmanları tarafından yapılmalıdır. Uygulama yöneticisi rolünün, uygulama sahibinin teknik karşılığı olarak oluşturulmasını öneriyoruz. Uygulama yöneticisi, gereksinimlerin toplanmasından sistemin kaldırılması sürecine kadarki genellikle gözden kaçırılan tüm uygulama yaşam döngüsünden sorumludur. 

## Gereksinimler ve Kaynak Yönetimi

* Tüm veri varlıklarının gizlilik, kimlik doğrulama, bütünlük ve erişilebilirlik ilkeleri ve beklenen iş mantığı ile ilgili korunma gereksinimleri dahil bir uygulama için bulunan iş gereksinimleri toplanmalı ve görüşülmelidir. 
* Fonksiyonel ve fonksiyonel olmayan güvenlik gereksinimleri dahil teknik gereksinimler toplanmalıdır.
* Güvenlik faaliyetleri dahil tasarım, geliştirme, test etme ve operasyonun tüm yönlerini kapsayan bütçe planlanmalı ve görüşülmelidir.

## Yorum Talepleri (RFP) ve Kontrat

* Güvenlik programınız, örn. SDLC, en iyi kullanım örnekleri ile ilgili kılavuzlar ve güvenlik gereksinimleri dahil gereksinimler iç ve dış geliştiricler ile görüşülmelidir.
* Planlama ve tasarım fazı dahil tüm teknik gereksinimlerin yerine getirilip getirilmediği takip edilmelidir.
* Tasarım, güvenlik ve hizmet seviyesi anlaşmaları (SLA) dahil tüm teknik gereksinimler görüşülmelidir.
* [OWASP Güvenlik Yazılım Sözleşmesi Eki](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex) gibi şablonlar ve kontrol listeleri benimsenmelidir. **Not** 
Adopt templates and checklists, such as [OWASP Secure Software Contract Annex]. **Note**: The annex is for US contract law, so please consult qualified legal advice before using the sample annex.

## Planning and Design

* Negotiate planning and design with the developers and internal shareholders, e.g. security specialists.
* Define the security architecture, controls, and countermeasures appropriate to the protection needs and the expected threat level. This should be supported by security specialists.
* Ensure that the application owner accepts remaining risks or provides additional resources.
* In each sprint, ensure security stories are created that include constraints added for non-functional requirements.

## Deployment, Testing, and Rollout

* Automate the secure deployment of the application, interfaces and all required components, including needed authorizations.
* Test the technical functions and integration with the IT architecture and coordinate business tests.
* Create "use" and "abuse" test cases from technical and business perspectives.
* Manage security tests according to internal processes, the protection needs, and the assumed threat level by the application.
* Put the application in operation and migrate from previously used applications if needed.
* Finalize all documentation, including the CMDB and security architecture.

## Operations and Change Management

* Operations must include guidelines for the security management of the application (e.g. patch management).
* Raise the security awareness of users and manage conflicts about usability vs. security.
* Plan and manage changes, e.g. migrate to new versions of the application or other components like OS, middleware, and libraries.
* Update all documentation, including in the change management data base (CMDB) and the security architecture, controls, and countermeasures, including any runbooks or project documentation.

## Retiring Systems

* Any required data should be archived. All other data should be securely wiped.
* Securely retire the application, including deleting unused accounts and roles and permissions.
* Set your application's state to retired in the CMDB.
