# OWASP Top 10 ile bir AppSec Programına Nasıl Başlanır

Geçmişte, OWASP Top 10 hiçbir zaman bir AppSec programının temeli olarak tasarlanmamıştı. Ancak uygulama güvenliği yolculuğuna yeni başlayan birçok organizasyon için bir yerden başlamak şart. OWASP Top 10 2021, kontrol listeleri vb. için iyi bir başlangıç temeli olsa da tek başına yeterli değildir.

## Aşama 1. AppSec programınızın boşluklarını ve hedeflerini belirleyin

Birçok Application Security (AppSec) programı emeklemeden ya da yürüyemeden koşmaya çalışır. Bu çabalar başarısızlığa mahkûmdur. CISO’lar ve AppSec liderliğinin, 1–3 yıllık bir dönemde zayıflıkları ve iyileştirme alanlarını belirlemek için [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) kullanmalarını şiddetle tavsiye ediyoruz. İlk adım, şu an nerede olduğunuzu değerlendirmek, yönetişim, tasarım, implementasyon, doğrulama ve operasyonlardaki hemen çözmeniz gereken boşluklar ile bekleyebilecekleri belirlemek ve on beş OWASP SAMM güvenlik pratiğinin implementasyonunu veya iyileştirilmesini önceliklendirmektir. OWASP SAMM, yazılım güvence çabalarınızda iyileştirmeler yapmanıza ve bunları ölçmenize yardımcı olabilir.

## Aşama 2. Paved road secure development lifecycle için plan yapın

Geleneksel olarak “unicorn”ların alanı olan paved road konsepti, AppSec kaynaklarını her yıl artan development team hızına göre ölçeklemenin ve en büyük etkiyi yaratmanın en kolay yoludur.

Paved road konsepti “en kolay yol aynı zamanda en güvenli yoldur” anlayışıdır ve tercihen development team ile security team’in aynı ekip olması şeklinde derin bir ortaklık kültürünü içermelidir. Paved road, insecure alternatifleri tespit edip değiştirmek için enterprise genelinde drop-in secured replacements kütüphanesi oluşturarak ve iyileştirmelerin nerede yapılabileceğini görmeye yardımcı olacak tooling ile sürekli iyileştirme, ölçme ve tespit etmeyi amaçlar. Bu, mevcut development tool’larının insecure build’leri raporlamasına ve development team’lerin insecure alternatiflerden kendi kendine uzaklaşmasına yardımcı olur.

Paved road göz korkutucu görünebilir, ancak zaman içinde artımlı olarak inşa edilmelidir. Orada başka AppSec programları da vardır; özellikle Microsoft Agile Secure Development Lifecycle. Her AppSec program metodolojisi her işletmeye uygun değildir.

## Aşama 3. Paved road’u development team’lerinizle implement edin

Paved road’lar ilgili development ve operations team’lerinin onayı ve doğrudan katılımıyla inşa edilir. Paved road, işletme ile stratejik olarak hizalanmalı ve daha güvenli uygulamaların daha hızlı teslim edilmesine yardımcı olmalıdır. Paved road’un geliştirilmesi, eski günlerdeki gibi uygulama başına geçici çözümler değil, tüm enterprise veya uygulama ekosistemini kapsayan bütünsel bir egzersiz olmalıdır.

## Aşama 4. Yaklaşan ve mevcut tüm uygulamaları paved road’a taşıyın

Paved road detection tool’larını geliştirirken ekleyin ve development team’lere uygulamalarının güvenliğini, paved road’un unsurlarını doğrudan nasıl benimseyebileceklerine dair bilgi sağlayın. Paved road’un bir yönü benimsendikten sonra, organizasyonlar mevcut kodu ve yasaklanmış alternatifleri kullanan check-in’leri inceleyen ve build’i veya check-in’i uyaran ya da reddeden continuous integration kontrolleri implement etmelidir. Bu, zaman içinde insecure seçeneklerin koda sızmasını, teknik borcu ve hatalı, insecure bir uygulamayı önler. Bu uyarılar secure alternatife link vermeli, böylece development team’e doğru cevap anında sunulur. Ekip hızlıca refactor edip paved road bileşenini benimseyebilir.

## Aşama 5. Paved road’un OWASP Top 10’da bulunan sorunları hafiflettiğini test edin

Paved road bileşenleri, OWASP Top 10 ile ilgili önemli bir sorunu ele almalıdır; örneğin vulnerable components’ı otomatik tespit etmek veya düzeltmek, injection’ları tespit eden bir static code analysis IDE plugin’i veya daha da iyisi injection’a karşı güvenli olduğu bilinen bir library kullanmaya başlamak gibi. Ekipler için sağlanan bu secure drop-in replacements ne kadar çok olursa o kadar iyidir. AppSec ekibinin kritik bir görevi, bu bileşenlerin güvenliğinin sürekli olarak değerlendirilip iyileştirildiğinden emin olmaktır. İyileştirildiklerinde, bileşenin tüketicileriyle bir iletişim yolu, tercihen otomatik, değilse en azından bir dashboard vb. üzerinde vurgulanarak, bir upgrade gerçekleşmesi gerektiğini belirtmelidir.

## Aşama 6. Programınızı olgun bir AppSec programına dönüştürün

OWASP Top 10’da durmamalısınız. Sadece 10 risk kategorisini kapsar. Organizasyonların Application Security Verification Standard’ı benimsemelerini ve geliştirilen uygulamaların risk seviyesine bağlı olarak seviye 1, 2 ve 3 için paved road bileşenleri ve testleri kademeli olarak eklemelerini şiddetle tavsiye ediyoruz.

## Ötesine geçmek

Tüm harika AppSec programları asgari gerekliliklerin ötesine geçer. AppSec zafiyetlerinin üstesinden gelebilmemiz için herkesin ilerlemeye devam etmesi gerekir.

* **Kavramsal bütünlük**. Olgun AppSec programları, ister resmi bir cloud ya da enterprise security architecture olsun, ister threat modeling, bir güvenlik mimarisi kavramı içermelidir.

* **Otomasyon ve ölçek**. Olgun AppSec programları teslimatlarının mümkün olduğunca çoğunu otomatikleştirmeye çalışır; karmaşık penetration testing adımlarını betiklerle taklit etmek, development team’lere doğrudan sunulan static code analysis tool’ları, dev team’lere AppSec unit ve integration testleri oluşturmada yardımcı olmak ve daha fazlası.

* **Kültür**. Olgun AppSec programları, development team’in bir parçası olarak hareket ederek insecure design’ı ortadan kaldırmaya ve mevcut kodun teknik borcunu temizlemeye çalışır; kenarda duran bir ekip olarak değil. Development team’lerini “biz” ve “onlar” diye gören AppSec ekipleri başarısızlığa mahkûmdur.

* **Sürekli iyileştirme**. Olgun AppSec programları sürekli olarak iyileştirmeye bakar. Bir şey işe yaramıyorsa yapmayı bırakın. Bir şey hantalsa veya ölçeklenebilir değilse, iyileştirmek için çalışın. Development team’ler tarafından kullanılmayan ve etkisi olmayan/az olan bir şey varsa, farklı bir şey yapın. 1970’lerden beri desk check gibi testler yapıyor olmamız bunun iyi bir fikir olduğu anlamına gelmez. Ölçün, değerlendirin ve ardından inşa edin veya iyileştirin.

