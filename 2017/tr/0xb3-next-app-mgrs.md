# +A: Uygulama Yöneticileri için Bir Sonraki Adım

## Bütün Uygulama Yaşam Döngüsünü Yönetin

Uygulamalar, insanların düzenli olarak oluşturduğu ve sürdürdüğü en karmaşık sistemlere aittir. Bir uygulama için IT yönetimi, bir uygulamanın bütün IT yaşam döngüsü için sorumlu olan IT uzmanları tarafından yapılmalıdır. Uygulama yöneticisi rolünün, uygulama sahibinin teknik karşılığı olarak oluşturulmasını öneriyoruz. Uygulama yöneticisi, gereksinimlerin toplanmasından sistemin kaldırılması sürecine kadarki genellikle gözden kaçırılan tüm uygulama yaşam döngüsünden sorumludur. 

## Gereksinimler ve Kaynak Yönetimi

* Tüm veri varlıklarının gizlilik, kimlik doğrulama, bütünlük ve erişilebilirlik ilkeleri ve beklenen iş mantığı ile ilgili korunma gereksinimleri dahil, bir uygulama için bulunan iş gereksinimleri toplanmalı ve görüşülmelidir. 
* Fonksiyonel ve fonksiyonel olmayan güvenlik gereksinimleri dahil teknik gereksinimler toplanmalıdır.
* Güvenlik faaliyetleri dahil tasarım, geliştirme, test etme ve operasyonun tüm yönlerini kapsayan bütçe planlanmalı ve görüşülmelidir.

## Yorum Talepleri (RFP) ve Kontrat

* Güvenlik programınız, örn. SDLC, en iyi kullanım örnekleri ile ilgili kılavuzlar ve tüm gereksinimler iç ve dış geliştiriciler ile görüşülmelidir.
* Planlama ve tasarım fazı dahil tüm teknik gereksinimlerin yerine getirilip getirilmediği takip edilmelidir.
* Tasarım, güvenlik ve hizmet seviyesi anlaşmaları (SLA) dahil tüm teknik gereksinimler görüşülmelidir.
* [OWASP Güvenli Yazılım Sözleşmesi Eki](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex) gibi şablonlar ve kontrol listeleri benimsenmelidir. **Not**:Bu ek ABD sözleşme hukukuna göredir, bu yüzden örnek eki kullanmadan önce lütfen yetkin kişilerden yasal tavsiye alınız.

## Planlama ve Tasarım

* Geliştiriciler ve güvenlik uzmanları gibi iç paydaşlar ile planlama ve tasarım görüşülmelidir.
* Korunma ihtiyaçlarına ve beklenen tehdit düzeyine uygun güvenlik mimarisi, kontrolleri ve önlemleri belirlenmelidir.
* Uygulama sahibinin kalan riskleri kabul ettiğinden ve ilave kaynaklar sağladığından emin olunmalıdır.
* Her bir sprintte, fonksiyonel olmayan gereksinimler için eklenen kısıtlamaları içerecek güvenlik hikayelerinin oluşturulduğundan emin olunmalıdır.

## Dağıtım, Test ve Yaygınlaştırma

* Uygulamanın, ara yüzlerin ve ihtiyaç duyulan yetkilendirmeler dahil tüm gerekli bileşenlerin güvenli dağıtımı otomatize edilmelidir.
* Teknik fonksiyonları ve IT mimarisi ile entegrasyon test edilmelidir ve iş testleri koordine edilmelidir.
* Teknik ve iş perspektiflerine göre "kullanım" ve "istismar" test senaryoları oluşturulmalıdır.
* Güvenlik testleri iç süreçlere, korunma ihtiyaçlarına ve uygulama tarafından varsayılan tehdit düzeyine göre yönetilmelidir.
* Uygulama aktif hale getirilmeli ve ihtiyaç duyulursa öncesinde kullanılan uygulamalara dönülmelidir.
* CMDB ve güvenlik mimarisi dahil tüm dokümantasyon son hale getirilmelidir.

## Operasyonlar ve Değişiklik Yönetimi

* Operasyonlar, uygulamanın güvenlik yönetimi için kılavuzlar (örn. yama yönetimi) içermelidir.
* Kullanıcıların güvenlik farkındalığı artırılmalı ve kullanılabilirlik ile güvenlik arasındaki çatışmazlıklar yönetilmelidir.
* Değişiklikler, örn. uygulamanın veya işletim sisteminin, ara katman ve kütüphaneler gibi diğer bileşenlerin yeni sürümlerine geçilmesi, planlanmalı ve yönetilmelidir.
* Değişiklik yönetimi veri tabanı (CMDB) dahil tüm dokümantasyon ve çalışma kitapları veya proje dokümantasyonu dahil güvenlik mimarisi, kontrolleri ve önlemleri güncellenmelidir.

## Eskiyen Sistemler

* Tüm gerekli veriler arşivlenmelidir. Diğer tüm veriler güvenli bir şekilde silinmelidir.
* Kullanılmayan hesapların, rollerin ve izinlerin silinmesi ile beraber uygulama güvenli bir şekilde kaldırılmalıdır.
* CMDB veri tabanında uygulamanın durumu kaldırıldı olarak değiştirilmelidir.
