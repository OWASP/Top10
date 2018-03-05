# I Giriş

## OWASP Top 10 - 2017 Projesine Hoş Geldiniz

Bu büyük güncelleme topluluk tarafından seçilen iki yeni açıklık olan A8:2017-Güvensiz Ters Serileştirme ve A10:2017-Yetersiz Loglama ve İzleme gibi bazı yeni açıklıklar eklemektedir. Daha önceki OWASP Top 10 sürümleri ile iki ana farklılığı büyük ölçüdeki topluluk geri bildirimi ve muhtemelen herhangi bir uygulama güvenliği standardı hazırlanırken toplanılan veri miktarından daha fazla olan ve düzinelerce organizasyondan toplanan geniş kapsamlı verilerdir. Bu durum, yeni OWASP Top 10 açıklıklarının organizasyonların karşılaştıkları en etkili uygulama güvenliği zafiyetlerini içerdiği konusunda güven vermektedir.

OWASP Top 10 2017, temel olarak uygulama güvenliği alanında uzmanlaşmış kırkdan fazla firmadan gelen verilere ve 500'den fazla kişinin katıldığı bir endüstri anketine dayanmaktadır. Bu veriler yüzlerce firmadan ve 100.000 gerçek uygulama ve API'lerden toplanan açıklıkları kapsamaktadır. Top 10 açıklıklar istismar edilebilirlik, tespit edilebilirlik ve etki hakkındaki genel tahminler ile beraber bu yaygınlık verisine göre seçilmiş ve önceliklendirilmiştir.

OWASP Top 10'in temel amacı, en yaygın ve en önemli web uygulama güvenlik zayıflıklarının sonuçları hakkında geliştiricileri, tasarımcıları, mimarları, yöneticileri ve organizasyonları eğitmektir. Top 10 projesi bu yüksek risk içeren sorunlara karşı basit korunma teknikleri ve bundan sonraki adımların ne olacağı hakkında bir rehber sağlamaktadır.

## Gelecek faaliyetler için yol haritası

**10 ile sınırlamayın**. [OWASP Developer's Guide](https://www.owasp.org/index.php/OWASP_Guide_Project) ve [OWASP Cheat Sheet Series](https://www.owasp.org/index.php/Category:Cheatsheets) projelerinde bahsedildiği gibi bir web uygulamasının güvenliğini etkileyebilecek yüzlerce sorun bulunmaktadır. Bunlar web uygulamaları ve API geliştiren herkes için önemli bir kaynaktır. Web uygulamalarında ve API'lerde etkili bir şekilde açıklıkların bulunmasına ilişkin rehber [OWASP Testing Guide](https://www.owasp.org/index.php/OWASP_Testing_Project) projesinde sağlanmıştır.

**Sürekli değişim**. OWASP Top 10 sıralaması değişmeye devam edecektir. Uygulamanızda tek bir satır kod değiştirmeseniz bile, yeni açıklıklar bulunduğu ve saldırı yöntemleri yenilendiği için açıklıklara karşı korumasız kalabilirsiniz. Lütfen daha fazla bilgi için Top 10 projesinin sonunda yer alan Geliştiriciler, Güvenlik Testçileri, Organizasyonlar ve Uygulama Yöneticileri için Bir Sonraki Adım bölümlerini gözden geçiriniz.

**Olumlu düşünme**. Açıklıkların peşinden koşmayı bırakmaya ve daha güçlü uygulama güvenliği kontrolleri oluşturmaya hazır olduğunuzda, [OWASP Proactive Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls) projesi geliştiricilerin günveliği uygulamalarına yerleştirmesine yardımcı olmak noktasında bir başlangıç noktası sağlamakta ve [OWASP Application Security Verification Standard (ASVS)](https://www.owasp.org/index.php/ASVS) ise organizasyonlar ve uygulama testçileri için neleri kontrol edecekleri noktasında bir rehber olmaktadır.

**Araçları akıllıca kullanma**. Güvenlik açıklıkları son derece karmaşık olabilmekte ve kod içerisinde derinlerde bulunabilmektedir. Çoğu durumda, bu açıklıkları bulmak ve ortadan kaldırmak için en etkili yaklaşım gelişmiş araçları kullanan uzman insanlardır. Sadece araçlara bağlı kalmak güvenliği yanlış anlamaktır ve tavsiye edilmemektedir.

**Her yerde yaygınlaştırma**. Geliştirme organizasyonunuzda güvenliği organizasyon kültürünün tamamlayıcı bir parçası yapmaya odaklanın. [OWASP Software Assurance Maturity Model (SAMM)](https://www.owasp.org/index.php/OWASP_SAMM_Project) üzerinden daha fazla bilgi edinebilirsiniz.

## Attribution

Organizasyonlara 2017 güncellemesi için sağladıkları açıklık verileri için teşekkür ederiz. Veri talebine 40'dan fazla cevap aldık. İlk kez, Top 10 sürümüne katkı olarak sağlanan tüm veriler ve katkı sağlayanların tam listesi açık bir şekilde yayınlanmıştır. Bunun toplanan en büyük ve en kapsamlı açıklık veri setlerinden birisi olduğuna inanıyoruz.

Katkı sağlayan herkesi sıralayacak kadar geniş bir yer olmadığı için, yapılan katkıları takdir etmek için ayrı bir sayfa oluşturduk. Açıklık verilerini en ön safta paylaşmak konusunda istekli oldukları için bu organizasyonlara gönülden teşekkürlerimizi sunuyoruz. Bu çalışmanın daha büyümesini ve daha fazla organizasyonu teşvik etmesini ve böylelikle de kanıta dayalı güvenlik yaklaşımının önemli kilometre taşlarından birisi olmasını ümit ediyoruz. OWASP Top 10 bu inanılmaz katkılar olmasaydı ortaya çıkamazdı.

Endüstri sıralamalı anketi tamamlamak için vakit ayıran 500'den fazla kişiye de ayrıca teşekkür ediyoruz. Yorumlarınız Top 10 sıralamasına iki yeni eklemenin yapılmasına yardımcı oldu. İlave yorumlarınız, teşvik notlarınız ve eleştirileriniz için de ayrıca teşekkür ederiz. Zamanınızın kıymetli olduğunu biliyor ve tekrar teşekkür etmek istiyoruz.

Önemli yapıcı eleştiriler ve Top 10 sıralamasına yapılan bu güncellemeyi gözden geçirmek için zaman ayıran kişilere de teşekkür etmek istiyoruz. Olabildiği kadarıyla, bu kişileri "Teşekkürler" sayfasında listelemeye çalıştık.

Ve son olarak, Top 10 projesini farklı dillere çevirerek OWASP Top 10'in tüm gezegende erişilebilir hale gelmesine yardımcı olacak tüm çevirmenlere şimdiden teşekkür ederiz.
