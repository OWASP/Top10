# A08:2025 Yazılım veya Veri Bütünlüğü Hataları ![simge](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Arka Plan. 

Yazılım veya Veri Bütünlüğü Hataları, önceki adı olan "Software *and* Data Integrity Failures" (Yazılım *ve* Veri Bütünlüğü Hataları) üzerinde açıklık getiren küçük bir değişiklikle 8. sıradaki yerini sürdürüyor. Bu kategori, güven sınırlarının korunamamasına ve yazılım, kod ve veri artifact'lerinin bütünlüğünün Yazılım Tedarik Zinciri Hatalarına göre daha alt bir düzeyde doğrulanamamasına odaklanır. Kategori, bütünlük doğrulanmadan yazılım güncellemeleri ve kritik verilerle ilgili varsayımlarda bulunulmasını ele alır. Öne çıkan Common Weakness Enumeration (CWE) kayıtları arasında *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, *CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes* ve *CWE-502: Deserialization of Untrusted Data* yer alır.


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
   <td>14
   </td>
   <td>8.98%
   </td>
   <td>2.75%
   </td>
   <td>78.52%
   </td>
   <td>45.49%
   </td>
   <td>7.11
   </td>
   <td>4.79
   </td>
   <td>501,327
   </td>
   <td>3,331
   </td>
  </tr>
</table>



## Açıklama. 

Yazılım ve veri bütünlüğü hataları, geçersiz veya güvenilmeyen kod ya da verilerin güvenilir ve geçerli kabul edilmesine karşı koruma sağlamayan kod ve altyapıyla ilgilidir. Buna bir örnek, bir uygulamanın güvenilmeyen kaynaklardan, depolardan ve içerik dağıtım ağlarından (CDN) gelen eklentilere, kütüphanelere veya modüllere dayanmasıdır. Yazılım bütünlüğü kontrollerini ne kullanan ne de sağlayan güvensiz bir CI/CD pipeline'ı, yetkisiz erişime, güvensiz veya kötü amaçlı koda ya da sistemin ele geçirilmesine zemin hazırlayabilir. Bir başka örnek, kodu veya artifact'leri güvenilmeyen yerlerden çeken ve/veya bunları kullanmadan önce (imzayı ya da benzer bir mekanizmayı kontrol ederek) doğrulamayan bir CI/CD'dir. Son olarak, günümüzde birçok uygulama otomatik güncelleme işlevi içerir; bu işlevde güncellemeler yeterli bütünlük doğrulaması yapılmadan indirilir ve daha önce güvenilen uygulamaya uygulanır. Saldırganlar, tüm kurulumlara dağıtılıp çalıştırılmak üzere kendi güncellemelerini yükleyebilir. Bir diğer örnek, nesnelerin veya verilerin saldırganın görebileceği ve değiştirebileceği bir yapıya kodlandığı ya da serileştirildiği durumdur; böyle bir yapı güvensiz seri durumdan çıkarmaya (insecure deserialization) karşı savunmasızdır.


## Nasıl Önlenir. 



* Yazılımın veya verinin beklenen kaynaktan geldiğini ve değiştirilmediğini doğrulamak için dijital imzalar veya benzer mekanizmalar kullanın.
* npm veya Maven gibi kütüphanelerin ve bağımlılıkların yalnızca güvenilir depoları kullandığından emin olun. Risk profiliniz daha yüksekse, incelenmiş ve güvenilirliği bilinen dahili bir depo barındırmayı değerlendirin.
* Yazılım pipeline'ınıza kötü amaçlı kod veya yapılandırma eklenme olasılığını en aza indirmek için kod ve yapılandırma değişikliklerine yönelik bir inceleme süreci bulunduğundan emin olun.
* Derleme ve dağıtım süreçlerinden geçen kodun bütünlüğünü güvence altına almak için CI/CD pipeline'ınızda uygun ayrım, yapılandırma ve erişim kontrolü bulunduğundan emin olun.
* İmzasız veya şifrelenmemiş serileştirilmiş verilerin güvenilmeyen istemcilerden alınıp, serileştirilmiş verinin kurcalanmasını veya yeniden oynatılmasını (replay) tespit edecek bir bütünlük kontrolü ya da dijital imza olmadan kullanılmadığından emin olun.


## Örnek Saldırı Senaryoları. 

**Senaryo #1 Güvenilmeyen Bir Kaynaktan Web İşlevselliği Dahil Edilmesi:** Bir şirket, destek işlevselliği için harici bir hizmet sağlayıcıdan yararlanıyor. Kolaylık olsun diye `myCompany.SupportProvider.com` adresini `support.myCompany.com` adresine eşleyen bir DNS kaydı oluşturmuş. Bu, `myCompany.com` alan adında ayarlanan, kimlik doğrulama çerezleri dahil tüm çerezlerin artık destek sağlayıcısına da gönderileceği anlamına gelir. Destek sağlayıcısının altyapısına erişimi olan herkes, `support.myCompany.com` adresini ziyaret etmiş tüm kullanıcılarınızın çerezlerini çalabilir ve oturum ele geçirme (session hijacking) saldırısı gerçekleştirebilir.

**Senaryo #2 İmzasız Güncelleme:** Birçok ev yönlendiricisi, set üstü kutu, cihaz ürün yazılımı (firmware) ve benzerleri, güncellemeleri imzalı ürün yazılımı aracılığıyla doğrulamaz. İmzasız ürün yazılımları saldırganların giderek daha fazla hedef aldığı bir alandır ve durumun daha da kötüleşmesi beklenmektedir. Bu ciddi bir endişe kaynağıdır; çünkü çoğu zaman sorunu gidermenin, gelecekteki bir sürümde düzeltme yapıp önceki sürümlerin zamanla kullanımdan kalkmasını beklemekten başka bir yolu yoktur.

**Senaryo #3 Güvenilmeyen Bir Kaynaktan Paket Kullanımı:** Bir geliştirici aradığı paketin güncel sürümünü bulmakta zorlanır ve paketi olağan, güvenilir paket yöneticisinden değil, internetteki bir web sitesinden indirir. Paket imzalı değildir; bu nedenle bütünlüğünü doğrulama imkânı yoktur. Paket kötü amaçlı kod içerir.

**Senaryo #4 Güvensiz Seri Durumdan Çıkarma (Insecure Deserialization):** Bir React uygulaması, bir dizi Spring Boot mikro hizmetini çağırıyor. Fonksiyonel programlama yaklaşımını benimseyen geliştiriciler, kodlarının değişmez (immutable) olmasını sağlamaya çalışmış. Buldukları çözüm, kullanıcı durumunu serileştirip her istekle birlikte karşılıklı olarak aktarmak olmuş. Bir saldırgan (base64 biçimindeki) "rO0" Java nesne imzasını fark eder ve uygulama sunucusunda uzaktan kod çalıştırmak için [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) aracını kullanır.

## Kaynaklar.

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)


## Eşlenen CWE'lerin Listesi

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

* [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

* [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

* [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

* [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)

* [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

* [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

* [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

* [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
