# A10:2025 İstisnai Durumların Hatalı Ele Alınması ![simge](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## Arka Plan. 

İstisnai Durumların Hatalı Ele Alınması, 2025 için yeni bir kategoridir. 24 CWE içeren bu kategori; uygunsuz hata yönetimi, mantık hataları, açık kalacak şekilde başarısız olma (failing open) ve sistemlerin karşılaşabileceği olağan dışı durumlardan kaynaklanan diğer ilgili senaryolara odaklanır. Kategoride, daha önce düşük kod kalitesiyle ilişkilendirilen bazı CWE'ler yer alıyor. O sınıflandırma bizim için fazla genel kalıyordu; bizce bu daha spesifik kategori daha iyi bir rehberlik sunuyor.

Bu kategorideki öne çıkan CWE'ler: *CWE-209 Generation of Error Message Containing Sensitive Information, CWE-234 Failure to Handle Missing Parameter, CWE-274 Improper Handling of Insufficient Privileges, CWE-476 NULL Pointer Dereference* ve *CWE-636 Not Failing Securely ('Failing Open')*.


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
   <td>24
   </td>
   <td>20.67%
   </td>
   <td>2.95%
   </td>
   <td>100.00%
   </td>
   <td>37.95%
   </td>
   <td>7.11
   </td>
   <td>3.81
   </td>
   <td>769,581
   </td>
   <td>3,416
   </td>
  </tr>
</table>



## Açıklama. 

Yazılımda istisnai durumların hatalı ele alınması, programların olağan dışı ve öngörülemeyen durumları önleyememesi, tespit edememesi ve bunlara yanıt verememesi sonucunda ortaya çıkar; bu da çökmelere, beklenmeyen davranışlara ve bazen güvenlik açıklarına yol açar. Bu durum aşağıdaki 3 başarısızlıktan bir veya birkaçını içerebilir: Uygulama olağan dışı bir durumun ortaya çıkmasını önlemez, durumu gerçekleştiği anda tanımlamaz ve/veya sonrasında duruma yetersiz yanıt verir ya da hiç yanıt vermez.

 

İstisnai durumlar; eksik, zayıf veya yetersiz girdi doğrulamasından, hataların oluştukları fonksiyonlarda değil de geç aşamada ve üst düzeyde ele alınmasından, bellek, yetki veya ağ sorunları gibi beklenmeyen ortam durumlarından, tutarsız istisna yönetiminden ya da hiç ele alınmayan istisnalardan kaynaklanabilir ve sistemin bilinmeyen, öngörülemeyen bir duruma düşmesine yol açabilir. Bir uygulamanın bir sonraki komutundan emin olmadığı her durumda, bir istisnai durum hatalı ele alınmış demektir. Bulunması zor hatalar ve istisnalar, uygulamanın tamamının güvenliğini uzun süre tehdit edebilir.

 

İstisnai durumları hatalı ele aldığımızda pek çok farklı güvenlik açığı ortaya çıkabilir;

örneğin mantık hataları, taşmalar, yarış durumları (race condition), sahte işlemler ya da bellek, durum, kaynak, zamanlama, kimlik doğrulama ve yetkilendirme ile ilgili sorunlar. Bu tür güvenlik açıkları bir sistemin veya verilerinin gizliliğini, erişilebilirliğini ve/veya bütünlüğünü olumsuz etkileyebilir. Saldırganlar bu güvenlik açığından yararlanmak için uygulamanın kusurlu hata yönetimini manipüle eder. 


## Nasıl Önlenir. 

Bir istisnai durumu doğru şekilde ele alabilmek için bu tür durumlara karşı plan yapmak (en kötüsünü beklemek) zorundayız. Olası her sistem hatasını doğrudan oluştuğu yerde ‘yakalamak’ ve ardından ele almak (yani sorunu çözmek ve sorundan kurtulmayı sağlamak için anlamlı bir şey yapmak) zorundayız. Ele alma sürecinin bir parçası olarak (kullanıcıyı anlaşılır şekilde bilgilendirmek için) bir hata döndürmeli, olayı günlüğe kaydetmeli ve gerekli gördüğümüzde bir uyarı üretmeliyiz. Gözden kaçırdığımız bir şey olması ihtimaline karşı global bir istisna işleyicimiz de olmalıdır. İdeal olarak, devam eden bir saldırıya işaret eden tekrarlanan hataları veya örüntüleri izleyen ve bir tür yanıt, savunma ya da engelleme başlatabilecek izleme ve/veya gözlemlenebilirlik araçlarına ya da işlevlerine de sahip olmalıyız. Bu, hata yönetimi zayıflıklarımızı hedef alan betikleri ve botları engellememize ve bunlara yanıt vermemize yardımcı olabilir.

 

İstisnai durumları yakalayıp ele almak, programlarımızın altyapısının öngörülemeyen durumlarla baş başa bırakılmamasını sağlar. Herhangi bir türde bir işlemin ortasındaysanız, işlemin her parçasını geri almanız ve baştan başlamanız (güvenli şekilde başarısız olma, failing closed olarak da bilinir) son derece önemlidir. Bir işlemi yarıda kaldığı noktadan kurtarmaya çalışmak, çoğu zaman telafisi mümkün olmayan hatalara yol açar.

 

İstisnai durumları en baştan önlemek için mümkün olan her yerde hız sınırlama, kaynak kotaları, kısma (throttling) ve diğer sınırlamaları ekleyin. Bilgi teknolojilerinde hiçbir şey sınırsız olmamalıdır; aksi hâlde uygulama dayanıklılığı eksikliği, hizmet reddi, başarılı kaba kuvvet saldırıları ve olağanüstü yüksek bulut faturaları ortaya çıkar. 

Belirli bir oranın üzerinde tekrarlanan aynı hataların yalnızca ne sıklıkla ve hangi zaman aralığında meydana geldiklerini gösteren istatistikler olarak çıktılanıp çıktılanmaması gerektiğini değerlendirin. Otomatik günlük kaydına ve izlemeye engel olmaması için bu bilgi orijinal mesaja eklenmelidir; bkz. [A09:2025 Güvenlik Günlüğü Kaydı ve Uyarı Hataları](A09_2025-Security_Logging_and_Alerting_Failures.md).

Bunlara ek olarak sıkı girdi doğrulamasını (kabul etmek zorunda olduğumuz, potansiyel olarak tehlikeli karakterler için temizleme veya kaçışlama ile birlikte), *merkezi* hata yönetimini, günlük kaydını, izlemeyi ve uyarıyı ve global bir istisna işleyicisini de dahil etmek isteriz. Bir uygulamada istisnai durumları ele almak için birden fazla fonksiyon bulunmamalı; bu işlem tek bir yerde ve her seferinde aynı şekilde yapılmalıdır. Ayrıca bu bölümdeki tüm öneriler için proje güvenlik gereksinimleri oluşturmalı, projelerimizin tasarım aşamasında tehdit modellemesi ve/veya güvenli tasarım incelemesi faaliyetleri yürütmeli, kod incelemesi veya statik analiz yapmalı ve nihai sistem üzerinde stres, performans ve sızma testleri gerçekleştirmeliyiz.

 

Mümkünse kuruluşunuzun tamamı istisnai durumları aynı şekilde ele almalıdır; bu, bu önemli güvenlik kontrolündeki hatalar açısından kodun incelenmesini ve denetlenmesini kolaylaştırır.


## Örnek Saldırı Senaryoları. 

**Senaryo #1:** Uygulama, dosya yüklenirken oluşan istisnaları yakalayıp ardından kaynakları düzgün şekilde serbest bırakmazsa, istisnai durumların hatalı ele alınması yoluyla kaynak tükenmesi (Hizmet Reddi) meydana gelebilir. Her yeni istisna, tüm kaynaklar tükenene kadar kaynakları kilitli ya da başka bir şekilde kullanılamaz durumda bırakır.

**Senaryo #2:** Uygunsuz hata yönetimi veya veritabanı hataları yoluyla tam sistem hatasının kullanıcıya gösterilmesi sonucunda hassas veri ifşası. Saldırgan, hassas sistem bilgilerini kullanarak daha etkili bir SQL enjeksiyonu saldırısı oluşturmak için hataları zorlamaya devam eder. Kullanıcıya gösterilen hata mesajlarındaki hassas veriler, saldırgan için keşif (reconnaissance) bilgisi niteliğindedir.

**Senaryo #3:** Bir saldırgan, ağ kesintileri yoluyla çok adımlı bir işlemi yarıda keserek finansal işlemlerde durum bozulmasına yol açabilir. İşlem sırasının şöyle olduğunu düşünün: kullanıcı hesabından para çek, hedef hesaba para yatır, işlemi günlüğe kaydet. Sistem, işlemin ortasında bir hata oluştuğunda işlemin tamamını düzgün şekilde geri almazsa (fail closed), saldırgan kullanıcının hesabını boşaltabilir ya da saldırganın hedefe birden çok kez para göndermesine olanak tanıyan bir yarış durumu (race condition) ortaya çıkabilir.


## Kaynaklar.

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [İstisnai bir durumun hatalı ele alınmasına gerçek dünyadan bir örnek](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/) 

## Eşlenen CWE'lerin Listesi
* [CWE-209	Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215	Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234	Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235	Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248	Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252	Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274	Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280	Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369	Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390	Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391	Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394	Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396	Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397	Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460	Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476	NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478	Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484	Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550	Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636	Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703	Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754	Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755	Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756	Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)
