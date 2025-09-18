# A11:2021 – Sonraki Adımlar

Tasarımı gereği OWASP Top 10 doğası gereği en önemli on riskle sınırlıdır. Her OWASP Top 10 sürümünde, kapsamlı biçimde değerlendirilmesine rağmen sonunda listeye giremeyen “eşikte” riskler olur. Verileri nasıl yorumlamaya ya da esnetmeye çalışırsak çalışalım, diğer riskler daha yaygın ve daha etkiliydi.

Olgun bir appsec programına doğru ilerleyen kuruluşlar veya kapsamlarını genişletmek isteyen güvenlik danışmanları ya da araç sağlayıcıları için aşağıdaki üç konu tespit ve iyileştirme çabasına fazlasıyla değerdir.

## Code Quality issues

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      38     |       49.46%       |        2.22%       |          7.1         |         6.7         |    60.85%    |    23.42%    |       101736      |    7564    |

* **Açıklama.** Code quality sorunları; bilinen güvenlik kusurları veya pattern’lar, değişkenlerin birden çok amaç için yeniden kullanımı, debugging çıktılarında hassas bilgilerin ifşası, off-by-one hataları, time of check/time of use (TOCTOU) race condition’ları, signed/unsigned dönüşüm hataları, use-after-free ve daha fazlasını içerir. Bu bölümün ayırt edici özelliği, genellikle sıkı compiler flag’leri, static code analysis araçları ve IDE linter plugin’leriyle tespit edilebilmeleridir. Modern diller tasarım gereği bu sorunların çoğunu ortadan kaldırmıştır; örneğin Rust’ın memory ownership ve borrowing konsepti, Rust’ın threading tasarımı ve Go’nun strict typing ile bounds checking yaklaşımı.

* **Nasıl önlenir.** Editor ve dilinizin static code analysis seçeneklerini etkinleştirip kullanın. Bir static code analysis aracı kullanmayı düşünün. Hata sınıflarını ortadan kaldıran Rust veya Go gibi bir dil ya da framework kullanmanın/migrate etmenin mümkün olup olmadığını değerlendirin.

* **Örnek saldırı senaryoları.** Bir saldırgan, birden fazla thread arasında statik olarak paylaşılan bir değişken üzerinden bir race condition’dan yararlanarak hassas bilgilere erişebilir ya da bu bilgileri güncelleyebilir.

* **Referanslar**

  * [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)
  * [Google Code Review Guide](https://google.github.io/eng-practices/review/)

## Denial of Service

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      8      |       17.54%       |        4.89%       |          8.3         |         5.9         |    79.58%    |    33.26%    |       66985       |     973    |

* **Açıklama.** Yeterli kaynak sağlandığında denial of service her zaman mümkündür. Ancak tasarım ve coding pratikleri, denial of service’in büyüklüğü üzerinde önemli bir etkiye sahiptir. Diyelim ki linke sahip herkes büyük bir dosyaya erişebiliyor veya her sayfada hesaplama açısından pahalı bir işlem gerçekleşiyor. Bu durumda denial of service gerçekleştirmek çok daha az çaba gerektirir.

* **Nasıl önlenir.** Kodu CPU, I/O ve memory kullanımı açısından performans testlerine tabi tutun; pahalı işlemleri yeniden mimarileştirin, optimize edin veya cache’leyin. Büyük objeler için access control’leri düşünün; yalnızca yetkili kişilerin devasa dosya/objelere erişebilmesini sağlayın ya da bu içerikleri bir edge caching network üzerinden sunun.

* **Örnek saldırı senaryoları.** Bir saldırgan, bir işlemin tamamlanmasının 5-10 saniye sürdüğünü tespit eder. Dört concurrent thread çalıştığında sunucunun yanıt vermeyi kestiği gözlemlenir. Saldırgan 1000 thread kullanır ve tüm sistemi çevrimdışı hale getirir.

* **Referanslar**

  * [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
  * [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Memory Management Errors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      14     |        7.03%       |        1.16%       |          6.7         |         8.1         |    56.06%    |    31.74%    |       26576       |    16184   |

* **Açıklama.** Web uygulamaları genellikle Java, .NET veya node.js (JavaScript ya da TypeScript) gibi managed memory dillerinde yazılır. Ancak bu diller, buffer/heap overflow, use-after-free, integer overflow ve daha fazlası gibi memory management sorunlarına sahip sistem dilleri üzerinde yazılmıştır. Yıllar içinde, web uygulama dili nominal olarak “memory safe” olsa bile temelin aynı olmadığını kanıtlayan pek çok sandbox escape görülmüştür.

* **Nasıl önlenir.** Modern API’lerin birçoğu artık Rust veya Go gibi memory-safe dillerde yazılıyor. Rust özelinde memory safety dilin kritik bir özelliğidir. Mevcut kod için sıkı compiler flag’leri, strong typing, static code analysis ve fuzz testing; memory leak’leri, memory ve array overrun’ları ve daha fazlasını tespit etmede faydalı olabilir.

* **Örnek saldırı senaryoları.** Buffer ve heap overflow’lar yıllardır saldırganların temel araçlarından olmuştur. Saldırgan, verisini bir programa gönderir; program bu veriyi boyutu yetersiz bir stack buffer’a yazar. Sonuç olarak call stack üzerindeki bilgiler, fonksiyonun return pointer’ı dahil, overwrite edilir. Veri, return pointer’ın değerini öyle ayarlar ki fonksiyon döndüğünde kontrol, saldırganın verisinin içinde bulunan kötü niyetli koda aktarılır.

* **Referanslar**

  * [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
  * [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
  * [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)

