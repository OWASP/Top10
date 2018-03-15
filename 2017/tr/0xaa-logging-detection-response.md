# A10:2017 Yetersiz Loglama ve İzleme

| Tehdit etkenleri/Saldırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 2 | Yaygınlık 3 : Tespit Edilebilirlik 1 | Teknik 2 : İş |
| Yetersiz loglama ve izleme açıklıklarının istismarı neredeyse tüüm büyük ihlallerin ana nedenidir. Saldırganlar tespit edilmeksizin amaçlarına ulaşmak için izleme ve zamanında müdahalenin eksikliğini kullanmaktadır. | Bu açıklık [endüstri anketine](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) dayanarak Top 10 listesinde yer almaktadır. Yeterli düzeyde izleme yapılıp yapılmadığına karar verirken kullanılacak bir strateji sızma testi sonrası logların incelenmesidir. Test ekibinin eylemleri, çıkarabilecekleri zararları anlamak için yeterli olacak şekilde kayıt altına alınmalıdır. | Başarılı pek çok saldırı açıklık araştırması ile başlamaktadır. Bu tür araştırmalara izin verilmesi başarılı istismar oranını neredeyse %100 oranında artırmaktadır. 2016 yılında, bir ihlalin tespiti, zararın oluşması için yeterli bir süre olan [ortalama 191 gün](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) olmuştur. |

## Uygulamam Açıklık İçeriyor Mu?

Yetersiz loglama, tespit, izleme ve aktif müdahale aşağıdaki durumlarda ortaya çıkmaktadır:

* Giriş işlemleri, başarısız giriş denemeleri ve yüksek değerli işlemler gibi denetlenebilir olaylar loglanmadığında.
* Uyarı ve hatalar yetersiz veya açık olmayan log mesajları oluşturuyorsa veya hiç oluşturmuyorsa.
* Uygulamaların ve API'lerin logları şüphe çekici faaliyetler için izlenmediğinde.
* Loglar sadece yerel olarak saklandığında.
* Uygun alarm üretme sınırları ve yanıt yükseltme süreçleri yerinde veya etkin olmadığında.
* [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) gibi [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) araçları tarafından yapılan sızma testi ve taramalar alarm üretmediğinde.
* Uygulama gerçek zamanlı olarak veya neredeyse gerçek zamanlı olarak aktif saldırıları tespit edemediğinde veya alarm üretmediğinde.

Eğer loglama ve alarm kayıtları bir kullanıcı veya bir saldırgan tarafından görüntülenebilirse, bilgi ifşası açıklığı bulunmaktadır. (bkz. A3:2017-Hassas Bilgi İfşası).

## Nasıl Önlenir

Uygulama tarafından saklanan veya işlenen her bir risk için:

* Şüpheli veya zararlı hesapların belirlenmesi için yeterli kullanıcı bağlanmıyla tüm giriş, erişim kontrolü eksiklikleri ve sunucu taraflı girdi doğrulama hatalarının loglandığından emin olunmalı ve ileri zamanlı adli bilişim analizlerine izin vermek için yeterli bir süre için tutulmalıdır.
* Logların merkezi bir log yönetim çözümü tarafından kolayca tüketilebileceği bir formatta üretildiğinden emin olunmalıdır.
* Değiştirme ve silmeleri engellemek için sadece ekleme yapılabilen veri tabanı tabloları gibi bütünlük kontrolü içeren denetim izlerinin yüksek değerli işlemler için bulunduğundan emin olunmalıdır.
* Şüpheli faaliyetlerin tespit edilebileceği ve zamanında müdahale edilebileceği şekilde etkin izleme ve alarm üretimi sağlanmalıdır.
* [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) veya daha ileri sürümleri gibi bir olay müdahale ve kurtarma planı oluşturulmalı veya benimsenmelidir.

[OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project) gibi açık kaynak kodlu ve ticari uygulama koruma çerçeveleri, [OWASP ModSecurity Temel Kural Seti ile ModSecurity](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project) gibi web uygulama güvenlik duvarları ve özelleştirilmiş gösterge panelleri ve alarm üretme özellikleri ile log korelasyon yazılımları bulunmaktadır.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Küçük bir takım tarafından yürütülen bir açık kaynak proje forum yazılımı, yazılımında bulunan bir açıklık kullanılarak ele geçirilmiştir. Saldırganlar bir sonraki sürüme ait bir iç kaynak kod deposu ve tüm forum içeriğini temizlemiştir. Kaynak kod kurtarılabilse de, izleme, loglama veya alarmlama eksikliği daha da kötü bir ihlale yol açmıştır. Forum yazılım projesi bu sorunun bir sonucu olarak artık aktif değildir.

**Senaryo #2**: Bir saldırgan, yaygın parola kullanan kullanıcılar için tarama yapmaktadır. Saldırganlar bu parolaları kullanarak tüm hesapları ele geçirebilmektedir. Diğer tüm kullanıcılar için, bu tarama sadece bir tane yanlış giriş bırakmaktadır. Birkaç gün sonra, bu durum farklı bir parola ile tekrar edilebilmektedir.

**Senaryo #3**: Bir tane büyük US perakendecisinin, eklentileri analiz eden bir iç kötücül yazlım analiz kum havuzuna sahip olduğu raporlanmıştır. Kum havuzu yazılımı potansiyel olarak istenmeyen yazılım tespit etmiştir, ancak hiçbir kimse bu tespite cevap vermemiştir. Dış bir banka tarafından yapılan sahte kart işlemleri sayesinde bu ihlal tespit edilmeden önce, kum havuzu bir süredir uyarılar üretmekteydi.

## Kaynaklar

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### Dış Kaynaklar

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
