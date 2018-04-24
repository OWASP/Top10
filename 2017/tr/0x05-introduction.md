# I Giriş

## OWASP İlk 10 - 2017 Projesine Hoş Geldiniz

Bu güncelleme ikisi topluluk tarafından seçilen A8:2017-Güvensiz Ters Serileştirme ve A10:2017-Yetersiz Loglama ve İzleme gibi bazı yeni açıklıklar eklemektedir. Daha önceki OWASP İlk 10 sürümleri ile iki ana farklılığı; büyük ölçüde topluluk geri bildirimi, muhtemelen herhangi bir uygulama güvenliği standardı hazırlanırken toplanılan veri miktarından daha fazla olan ve düzinelerce kurumdan toplanan geniş kapsamlı verilerdir. Bu durum, yeni OWASP İlk 10 açıklıklarının kurumların karşılaştıkları en riskli uygulama güvenliği zafiyetlerini içerdiği konusunda teminat vermektedir.

OWASP İlk 10 2017, temel olarak uygulama güvenliği alanında uzmanlaşmış kırkdan fazla firmadan gelen verilere ve 500'den fazla kişinin katıldığı bir endüstri anketine dayanmaktadır. Bu veriler yüzlerce firmadan, 100.000 gerçek uygulama ve API'den toplanan açıklıkları kapsamaktadır. İlk 10 açıklıkları istismar edilebilirliği, tespit edilebilirliği ve etkisi hakkındaki genel tahminler ile beraber zafiyet yaygınlık verilerine göre seçilmiş ve sıralanmıştır.

OWASP İlk 10'un temel amacı, en yaygın ve en önemli web uygulama güvenlik zayıflıklarının sonuçları hakkında geliştiricileri, tasarımcıları, sistem mimarlarını, yöneticileri ve organizasyonları eğitmektir. İlk 10 projesi bu yüksek risk içeren sorunlara karşı basit korunma yöntemleri ve bundan sonraki adımların ne olacağı hakkında bir rehber sağlamaktadır.

## Gelecek faaliyetler için yol haritası

**10 ile sınırlı kalmayın**. [OWASP Geliştiri Rehberi](https://www.owasp.org/index.php/OWASP_Guide_Project) ve [OWASP Kopya Kağıtları'nda](https://www.owasp.org/index.php/Category:Cheatsheets) bahsedildiği gibi, bir web uygulamasının güvenliğini etkileyebilecek yüzlerce sorun bulunmaktadır. Bu dokümanlar web uygulaması ve API geliştiren herkes için önemli bir kaynaktır. Web uygulamalarında ve API'lerde açıklıkların bulunmasına ilişkin rehber [OWASP Test Rehberi](https://www.owasp.org/index.php/OWASP_Testing_Project) projesinde sağlanmıştır.

**Sürekli değişim**. OWASP İlk 10 sıralaması değişmeye devam edecektir. Uygulamanızda tek bir satır kod değiştirmeseniz bile, yeni açıklıklar bulunduğu ve saldırı yöntemleri yenilendiği için açıklıklara karşı korumasız kalabilirsiniz. Lütfen daha fazla bilgi için İlk 10 projesinin sonunda yer alan Geliştiriciler, Güvenlik Testi Ekipleri, Kurumlar ve Uygulama Yöneticileri için Bir Sonraki Adım bölümlerini gözden geçiriniz.

**Olumlu düşünme**. Açıklıkların peşinden koşmayı bırakmaya ve daha güçlü uygulama güvenliği kontrolleri oluşturmaya hazır olduğunuzda, [OWASP Proaktif Kontroller](https://www.owasp.org/index.php/OWASP_Proactive_Controls) projesi geliştiricilerin güvenli uygulama geliştirme konusunda bir başlangıç noktası olmakta ve [OWASP Uygulama Güvenliği Doğrulama Standardı (ASVS)](https://www.owasp.org/index.php/ASVS) ise kurumlar ve uygulama testi ekipleri için kontrol edecekleri maddeleri içeren bir rehber olmaktadır.

**Araçları akıllıca kullanma**. Güvenlik açıklıkları son derece karmaşık olabilmekte ve kod içerisinde derinlerde bulunabilmektedir. Çoğu durumda, bu açıklıkları bulmak ve ortadan kaldırmak için en etkili yaklaşım gelişmiş araçları kullanan uzmanlardır. Sadece araçlara bağlı kalmak güvenliği yanlış anlamaktır ve tavsiye edilmemektedir.

**Her yöne yaygınlaştırma**. Kurumunuzda güvenliği kurum kültürünün tamamlayıcı bir parçası yapmaya odaklanın. [OWASP Yazılım Garanti Olgunluk Modeli (SAMM)](https://www.owasp.org/index.php/OWASP_SAMM_Project) üzerinden daha fazla bilgi edinebilirsiniz.

## Teşekkürler

Kurumlara 2017 güncellemesi için sağladıkları açıklık verileri için teşekkür ederiz. Veri talebine 40'dan fazla cevap aldık. İlk kez, İlk 10 sürümüne katkı olarak sağlanan tüm veriler ve katkı sağlayanların tam listesi açık bir şekilde yayınlanmıştır. Bunun şimdiye kadar toplanan en büyük ve en kapsamlı açıklık veri setlerinden birisi olduğuna inanıyoruz.

Katkı sağlayan herkesi sıralayacak kadar geniş bir yer olmadığı için, yapılan katkılara teşekkür etmek için ayrı bir sayfa oluşturduk. Açıklık verilerini paylaşma noktasında istekli bir şekilde en ön safta oldukları için bu kurumlara gönülden teşekkürlerimizi sunuyoruz. Bu çalışmanın daha da büyümesini ve daha fazla kurumu teşvik etmesini ve böylelikle de kanıta dayalı güvenlik yaklaşımının önemli kilometre taşlarından birisi olmasını ümit ediyoruz. OWASP İlk 10 bu inanılmaz katkılar olmasaydı ortaya çıkamazdı.

Endüstri anketini tamamlamak için vakit ayıran 500'den fazla kişiye de ayrıca teşekkür ediyoruz. Yorumlarınız İlk 10 sıralamasına iki yeni eklemenin yapılmasına yardımcı oldu. İlave yorumlarınız, teşvikleriniz ve eleştirileriniz için de ayrıca teşekkür ederiz. Ayırdığınız kıymetli zamanınız için tekrar teşekkür etmek istiyoruz.

Önemli yapıcı eleştiriler ve İlk 10 sıralamasına yapılan bu güncellemeyi gözden geçirmek için zaman ayıran kişilere de teşekkür etmek istiyoruz. Olabildiğince bu kişileri "Teşekkürler" sayfasında listelemeye çalıştık.

Ve son olarak, İlk 10 projesini farklı dillere çevirerek OWASP İlk 10'un tüm dünyada erişilebilir hale gelmesine yardımcı olacak tüm çevirmenlere şimdiden teşekkür ederiz.
