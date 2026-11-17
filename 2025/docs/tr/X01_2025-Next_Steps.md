# Sonraki Adımlar

OWASP Top 10, doğası gereği en önemli on riskle sınırlıdır. Her OWASP Top 10 sürümünde, listeye dahil edilmesi uzun uzun değerlendirilen ancak sonunda listeye giremeyen “sınırda” riskler bulunur. Diğer riskler daha yaygın ve daha etkiliydi.

Aşağıdaki üç sorun; olgun bir uygulama güvenliği programı oluşturmaya çalışan kuruluşlar, güvenlik danışmanlık firmaları veya sundukları çözümlerin kapsamını genişletmek isteyen araç üreticileri için tespit edilmeye ve giderilmeye fazlasıyla değer.


## X01:2025 Uygulama Dayanıklılığı Eksikliği {: #x012025-lack-of-application-resilience }

### Arka Plan. 

Bu kategori, 2021'deki Hizmet Reddi (Denial of Service) kategorisinin yeniden adlandırılmış hâlidir. Önceki ad bir kök nedeni değil, bir belirtiyi tanımladığı için değiştirildi. Bu kategori, dayanıklılık sorunlarıyla ilgili zayıflıkları tanımlayan CWE'lere odaklanır. Bu kategorinin puanı, A10:2025-İstisnai Durumların Hatalı Ele Alınması kategorisininkine çok yakındı. İlgili CWE'ler şunlardır: *CWE-400 Uncontrolled Resource Consumption, CWE-409 Improper Handling of Highly Compressed Data (Data Amplification), CWE-674 Uncontrolled Recursion* ve *CWE-835 Loop with Unreachable Exit Condition ('Infinite Loop').*


### Puan Tablosu.


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
   <td>16
   </td>
   <td>20.05%
   </td>
   <td>4.55%
   </td>
   <td>86.01%
   </td>
   <td>41.47%
   </td>
   <td>7.92
   </td>
   <td>3.49
   </td>
   <td>865,066
   </td>
   <td>4,423
   </td>
  </tr>
</table>



### Açıklama. 

Bu kategori, uygulamaların strese, arızalara ve uç durumlara verdiği yanıtta, uygulamanın arızadan kurtulamamasına yol açan sistemik bir zayıflığı temsil eder. Bir uygulama beklenmeyen koşulları, kaynak kısıtlarını ve diğer olumsuz olayları kontrollü biçimde ele alamadığında, bunlara dayanamadığında veya bunlardan kurtulamadığında kolayca erişilebilirlik sorunlarına (en yaygın olarak), ama aynı zamanda veri bozulmasına, hassas veri ifşasına, zincirleme arızalara ve/veya güvenlik kontrollerinin atlatılmasına yol açabilir.

Bunun yanı sıra [X02:2025 Bellek Yönetimi Hataları](#x022025-memory-management-failures) da uygulamanın, hatta tüm sistemin çökmesine yol açabilir.

### Nasıl Önlenir 

Bu tür bir güvenlik açığını önlemek için sistemlerinizi mutlaka arızaya ve arızadan kurtulmaya göre tasarlamalısınız.

* En çok kaynak tüketen işlemlere özellikle dikkat ederek sınırlar, kotalar ve yük devretme (failover) işlevleri ekleyin
* Yoğun kaynak kullanan sayfaları belirleyin ve önceden plan yapın: Özellikle çok fazla kaynak (ör. CPU, bellek) gerektiren gereksiz ‘gadget’ları ve işlevleri bilinmeyen veya güvenilmeyen kullanıcılara açmayarak saldırı yüzeyini küçültün
* İzin listeleri (allow-list) ve boyut sınırlamalarıyla sıkı girdi doğrulaması yapın, ardından kapsamlı şekilde test edin
* Yanıt boyutlarını sınırlayın ve istemciye asla ham yanıtlar göndermeyin (işlemeyi sunucu tarafında yapın)
* Varsayılan olarak güvenli/kapalı durumu tercih edin (asla açık değil), varsayılan olarak erişimi reddedin ve bir hata olursa işlemi geri alın
* İstek iş parçacıklarında (request thread) engelleyici senkron çağrılardan kaçının (asenkron/engellemeyen çağrılar kullanın, zaman aşımları ve eşzamanlılık sınırları belirleyin vb.)
* Hata yönetimi işlevlerinizi dikkatle test edin
* Devre kesici (circuit breaker), bölme (bulkhead), yeniden deneme mantığı ve kontrollü işlev kaybı (graceful degradation) gibi dayanıklılık kalıplarını uygulayın
* Performans ve yük testleri yapın; risk iştahınız buna uygunsa kaos mühendisliğini de ekleyin
* Makul ve karşılanabilir olduğu durumlarda yedekliliği (redundancy) mimariye dahil edin ve uygulayın
* İzleme, gözlemlenebilirlik ve uyarı mekanizmaları uygulayın
* Geçersiz gönderici adreslerini RFC 2267'ye uygun şekilde filtreleyin
* Bilinen botnet'leri parmak izleri ve IP adresleri üzerinden ya da davranışlarına göre dinamik olarak engelleyin
* İş Kanıtı (Proof-of-Work): Normal kullanıcıları pek etkilemeyen ancak çok sayıda istek göndermeye çalışan botları etkileyen, kaynak tüketen işlemleri *saldırgan* tarafında başlatın. Sistemin genel yükü arttığında, özellikle daha az güvenilir olan veya bot gibi görünen sistemler için İş Kanıtını zorlaştırın
* Sunucu tarafındaki oturum süresini hareketsizliğe ve kesin bir zaman aşımına göre sınırlayın
* Oturuma bağlı bilgi depolamayı sınırlayın


### Örnek Saldırı Senaryoları. 

**Senaryo #1:** Saldırganlar sistemde arızaları tetiklemek için uygulama kaynaklarını kasıtlı olarak tüketir ve bu durum hizmet reddine yol açar. Bu; belleğin tüketilmesi, disk alanının doldurulması, CPU'nun doyuma ulaştırılması veya sonsuz bağlantı açılması şeklinde olabilir.

**Senaryo #2:** Uygulamanın iş mantığını bozan, özel olarak hazırlanmış yanıtlara yol açan girdi fuzzing'i.

**Senaryo #3:** Saldırganlar uygulamanın bağımlılıklarına odaklanarak API'leri veya diğer harici hizmetleri devre dışı bırakır ve uygulama çalışmaya devam edemez.


### Kaynaklar.

* [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### Eşlenen CWE'lerin Listesi
* [CWE-73  External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
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
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
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
* [CWE-653 Improper Isolation or Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
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


## X02:2025 Bellek Yönetimi Hataları {: #x022025-memory-management-failures }

### Arka Plan. 

Java, C#, JavaScript/TypeScript (node.js), Go ve "güvenli" Rust gibi diller bellek açısından güvenlidir. Bellek yönetimi sorunları genellikle C ve C++ gibi bellek açısından güvenli olmayan dillerde ortaya çıkar. Bu kategori, ilişkili CVE sayısında üçüncü sırada olmasına rağmen topluluk anketinde en düşük puanı, verilerde ise düşük bir puan aldı. Bunun, web uygulamalarının daha geleneksel masaüstü uygulamalarına göre baskın olmasından kaynaklandığını düşünüyoruz. Bellek yönetimi güvenlik açıkları sıklıkla en yüksek CVSS puanlarına sahiptir. 


### Puan Tablosu.


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
   <td>24
   </td>
   <td>2.96%
   </td>
   <td>1.13%
   </td>
   <td>55.62%
   </td>
   <td>28.45%
   </td>
   <td>6.75
   </td>
   <td>4.82
   </td>
   <td>220,414
   </td>
   <td>30,978
   </td>
  </tr>
</table>



### Açıklama. 

Bir uygulama belleği kendisi yönetmek zorunda kaldığında hata yapmak çok kolaydır. Bellek açısından güvenli diller giderek daha sık kullanılıyor; ancak dünya genelinde üretimde hâlâ çok sayıda eski (legacy) sistem, bellek açısından güvenli olmayan dillerin kullanılmasını gerektiren yeni düşük seviyeli sistemler ve ana bilgisayarlar (mainframe), IoT cihazları, ürün yazılımları ve kendi belleğini yönetmek zorunda kalabilecek diğer sistemlerle etkileşime giren web uygulamaları bulunuyor. Bu kategoriyi temsil eden CWE'ler şunlardır: *CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')* ve *CWE-121 Stack-based Buffer Overflow*.

Bellek yönetimi hataları şu durumlarda ortaya çıkabilir:

* Bir değişken için yeterli bellek ayırmadığınızda
* Girdiyi doğrulamadığınız için heap'te, yığında (stack) veya bir arabellekte taşma meydana geldiğinde
* Değişkenin türünün tutabileceğinden daha büyük bir veri değeri sakladığınızda 
* Ayrılmamış belleği veya adres alanlarını kullanmaya çalıştığınızda
* Bir eksik/bir fazla (off-by-one) hatalarına yol açtığınızda (saymaya sıfır yerine 1'den başlamak gibi)
* Serbest bırakıldıktan sonra bir nesneye erişmeye çalıştığınızda
* İlk değeri atanmamış değişkenler kullandığınızda
* Bellek sızıntısına yol açtığınızda veya başka bir şekilde, uygulamamız çökene kadar kullanılabilir belleğin tamamını hatalı biçimde tükettiğinizde

Bellek yönetimi hataları uygulamanın, hatta tüm sistemin çökmesine yol açabilir; ayrıca bkz. [X01:2025 Uygulama Dayanıklılığı Eksikliği](#x012025-lack-of-application-resilience)


### Nasıl Önlenir. 

Bellek yönetimi hatalarını önlemenin en iyi yolu bellek açısından güvenli bir dil kullanmaktır. Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript vb. bunlara örnektir. Yeni uygulamalar geliştirirken, bellek açısından güvenli bir dile geçmenin getireceği öğrenme sürecine değeceği konusunda kuruluşunuzu ikna etmek için çaba gösterin. Kapsamlı bir yeniden yapılandırma (refactor) yapıyorsanız, mümkün ve uygulanabilir olduğunda bellek açısından güvenli bir dilde yeniden yazılması için ısrar edin.

Bellek açısından güvenli bir dil kullanamıyorsanız aşağıdakileri uygulayın:

* Bellek yönetimi hatalarının istismar edilmesini zorlaştıran şu sunucu özelliklerini etkinleştirin: adres alanı düzeni rastgeleleştirme (ASLR), Data Execution Protection (DEP) ve Structured Exception Handling Overwrite Protection (SEHOP).
* Uygulamanızı bellek sızıntılarına karşı izleyin.
* Sisteminize gelen tüm girdileri çok dikkatli şekilde doğrulayın ve beklentileri karşılamayan tüm girdileri reddedin.
* Kullandığınız dili inceleyerek güvensiz ve daha güvenli fonksiyonların bir listesini çıkarın, ardından bu listeyi tüm ekibinizle paylaşın. Mümkünse güvenli kodlama yönergenize veya standardınıza ekleyin. Örneğin C dilinde strcpy() yerine strncpy(), strcat() yerine strncat() kullanmayı tercih edin.
* Kullandığınız dil veya framework bellek güvenliği kütüphaneleri sunuyorsa bunları kullanın. Örneğin: Safestringlib veya SafeStr.
* Mümkün olan her durumda ham diziler ve işaretçiler yerine yönetilen arabellekler ve dizeler kullanın.
* Bellek sorunlarına ve/veya tercih ettiğiniz dile odaklanan güvenli kodlama eğitimleri alın. Eğitmeninize bellek yönetimi hataları konusunda endişeli olduğunuzu bildirin.
* Kod incelemeleri ve/veya statik analizler yapın.
* StackShield, StackGuard ve Libsafe gibi bellek yönetimine yardımcı olan derleyici araçlarını kullanın.
* Sisteminize gelen her girdi üzerinde fuzzing yapın.
* Sızma testi yaptırıyorsanız, test uzmanına bellek yönetimi hataları konusunda endişeli olduğunuzu ve test sırasında bu konuya özellikle dikkat etmesini istediğinizi bildirin.
*  Tüm derleyici hatalarını *ve* uyarılarını düzeltin. Programınız derleniyor diye uyarıları göz ardı etmeyin.
* Altta yatan altyapınızın düzenli olarak yamalandığından, tarandığından ve sıkılaştırıldığından emin olun.
* Altta yatan altyapınızı özellikle olası bellek güvenlik açıklarına ve diğer arızalara karşı izleyin.
* Adres yığınınızı taşma saldırılarına karşı korumak için [kanarya değerleri (canary)](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) kullanmayı değerlendirin.

### Örnek Saldırı Senaryoları. 

**Senaryo #1:** Arabellek taşmaları en bilinen bellek güvenlik açığıdır: Saldırgan bir alana kabul edebileceğinden daha fazla bilgi gönderir ve ilgili değişken için oluşturulan arabelleğin taşmasına neden olur. Başarılı bir saldırıda taşan karakterler yığın işaretçisinin (stack pointer) üzerine yazılır ve saldırganın programınıza kötü amaçlı komutlar eklemesine olanak tanır.

**Senaryo #2:** Use-After-Free (UAF), tarayıcı hata ödül (bug bounty) programlarına oldukça sık bildirilecek kadar yaygın görülür. DOM öğelerini manipüle eden JavaScript kodunu işleyen bir web tarayıcısı düşünün. Saldırgan, bir nesne (ör. bir DOM öğesi) oluşturan ve bu nesneye referanslar elde eden bir JavaScript yükü (payload) hazırlar. Dikkatli manipülasyonlarla tarayıcının, nesneye işaret eden sarkan bir işaretçiyi (dangling pointer) korurken nesnenin belleğini serbest bırakmasını tetikler. Tarayıcı belleğin serbest bırakıldığını fark etmeden önce saldırgan, *aynı* bellek alanını kaplayan yeni bir nesne ayırır. Tarayıcı orijinal işaretçiyi kullanmaya çalıştığında işaretçi artık saldırganın kontrolündeki verileri gösterir. Bu işaretçi bir sanal fonksiyon tablosuna aitse, saldırgan kod yürütmesini kendi yüküne yönlendirebilir. 

**Senaryo #3:** Kullanıcı girdisini kabul eden bir ağ hizmeti, bu girdiyi doğru şekilde doğrulamadan veya temizlemeden doğrudan günlük kaydı fonksiyonuna aktarıyor. Kullanıcıdan gelen girdi, günlük kaydı fonksiyonuna syslog("%s", user_input) yerine formatı belirtmeyen syslog(user_input) biçiminde aktarılıyor. Saldırgan, yığın belleğini okumak (hassas veri ifşası) için %x veya bellek adreslerine yazmak için %n gibi format belirteçleri içeren kötü amaçlı yükler gönderir. Birden fazla format belirtecini zincirleyerek yığının haritasını çıkarabilir, önemli adresleri bulabilir ve ardından bunların üzerine yazabilir. Bu bir format dizesi (format string) güvenlik açığı (kontrolsüz dize formatı) olur. 

Not: Modern tarayıcılar bu tür saldırılara karşı [tarayıcı sandbox'ı](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing) ASLR, DEP/NX, RELRO ve PIE dahil çok katmanlı savunmalar kullanır. Bir tarayıcıya yönelik bellek yönetimi hatası saldırısını gerçekleştirmek kolay değildir.

### Kaynaklar.

* [OWASP topluluk sayfaları: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: fuzzing kaynakları listesi](https://github.com/secfigo/Awesome-Fuzzing) 
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### Eşlenen CWE'lerin Listesi
* [CWE-14 Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
* [CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-124 Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html)
* [CWE-125 Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-126 Buffer Over-read](https://cwe.mitre.org/data/definitions/126.html)
* [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-191 Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
* [CWE-196 Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html)
* [CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
* [CWE-415 Double Free](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-457 Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
* [CWE-459 Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
* [CWE-467 Use of sizeof() on a Pointer Type](https://cwe.mitre.org/data/definitions/467.html)
* [CWE-787 Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
* [CWE-788 Access of Memory Location After End of Buffer](https://cwe.mitre.org/data/definitions/788.html)
* [CWE-824 Access of Uninitialized Pointer](https://cwe.mitre.org/data/definitions/824.html)



## X03:2025 Yapay Zekâ Tarafından Üretilen Koda Uygunsuz Güven ('Vibe Coding')

### Arka Plan.

Şu anda tüm dünya yapay zekâdan söz ediyor ve onu kullanıyor; yazılım geliştiriciler de buna dahil. Yapay zekâ tarafından üretilen kodla ilgili henüz herhangi bir CVE veya CWE bulunmasa da yapay zekânın ürettiği kodun çoğu zaman insanların yazdığı koddan daha fazla güvenlik açığı içerdiği iyi bilinen ve belgelenmiş bir gerçektir.


### Açıklama.

Yazılım geliştirme pratiklerinin, yalnızca yapay zekâ desteğiyle yazılan kodu değil, neredeyse tamamen insan denetimi olmadan yazılan ve commit edilen kodu da (genellikle vibe coding olarak adlandırılır) içerecek şekilde değiştiğini görüyoruz. Bloglardan veya web sitelerinden kod parçacıklarını iki kez düşünmeden kopyalamak hiçbir zaman iyi bir fikir olmadığı gibi, bu durumda sorun daha da büyür. İyi ve güvenli kod parçacıkları geçmişte de nadirdi, bugün de nadirdir; sistem kısıtları nedeniyle yapay zekâ tarafından istatistiksel olarak göz ardı edilebilirler.


### Nasıl Önlenir.
Kod yazan herkese, yapay zekâ kullanırken aşağıdakileri dikkate almalarını önemle tavsiye ediyoruz:

* Bir yapay zekâ tarafından yazılmış ya da çevrim içi bir forumdan kopyalanmış olsa bile, gönderdiğiniz tüm kodu okuyabilmeli ve tamamen anlayabilmelisiniz. Commit ettiğiniz tüm koddan siz sorumlusunuz.
* Yapay zekâ desteğiyle yazılan tüm kodu, ideal olarak hem kendi gözlerinizle hem de bu amaçla geliştirilmiş güvenlik araçlarıyla (statik analiz gibi) güvenlik açıklarına karşı kapsamlı şekilde incelemelisiniz. [OWASP Cheat Sheet Series: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html) kaynağında açıklanan klasik kod inceleme tekniklerini kullanmayı değerlendirin.
* İdeal olarak kodunuzu kendiniz yazın, iyileştirme önerilerini yapay zekâya bırakın, yapay zekânın kodunu kontrol edin ve sonuçtan memnun kalana kadar düzeltmeleri yapay zekâya yaptırın.
* Kendi topladığınız ve incelediğiniz güvenli kod örneklerini ve kuruluşunuzun güvenli kodlama yönergesi, standardı veya politikası gibi belgeleri içeren bir Retrieval Augmented Generation (RAG) sunucusu kullanmayı ve politikaların veya standartların uygulanmasını RAG sunucusuna yaptırmayı değerlendirin.
* Tercih ettiğiniz yapay zekâ araç(lar)ıyla birlikte kullanmak üzere gizlilik ve güvenlik için koruma bariyerleri (guardrails) uygulayan araçlar satın almayı değerlendirin.
* Tercihen yapay zekânın kuruluşunuzun verileri, sorguları, kodu veya diğer hassas bilgileri üzerinde eğitilmeyeceğini taahhüt eden bir sözleşmeyle (gizlilik sözleşmesi dahil) özel (private) bir yapay zekâ satın almayı değerlendirin.
* IDE'niz ile yapay zekâ arasına bir Model Context Protocol (MCP) sunucusu yerleştirmeyi ve bu sunucuyu tercih ettiğiniz güvenlik araçlarının kullanımını zorunlu kılacak şekilde yapılandırmayı değerlendirin.
* Geliştiricileri (ve tüm çalışanları) kuruluşunuzda yapay zekâyı nasıl kullanmaları ve nasıl kullanmamaları gerektiği konusunda bilgilendirmek için SDLC'nizin bir parçası olarak politikalar ve süreçler uygulayın.
* BT güvenliği en iyi uygulamalarını dikkate alan, iyi ve etkili prompt'lardan oluşan bir liste oluşturun. Bu prompt'lar ideal olarak kurum içi güvenli kodlama yönergelerinizi de dikkate almalıdır. Geliştiriciler bu prompt'ları programları için bir başlangıç noktası olarak kullanabilir.
* Yapay zekâ, onu hem etkili hem de güvenli biçimde kullanma yollarıyla birlikte, büyük olasılıkla sistem geliştirme yaşam döngünüzün her aşamasının bir parçası hâline gelecektir. Akıllıca kullanın.
* Karmaşık fonksiyonlarda, iş açısından kritik programlarda veya uzun süre kullanılacak programlarda vibe coding kullanılması **<u>önerilmez</u>**.
* Gölge yapay zekâ (Shadow AI) kullanımına karşı teknik kontroller ve önlemler uygulayın.
* Geliştiricilerinizi politikalarınızın yanı sıra güvenli yapay zekâ kullanımı ve yazılım geliştirmede yapay zekâ kullanımına ilişkin en iyi uygulamalar konusunda eğitin.


### Kaynaklar.

* [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


### Eşlenen CWE'lerin Listesi
-yok-
