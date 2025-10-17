# A09:2021 – Security Logging and Monitoring Failures    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      4      |       19.23%       |        6.51%       |         6.87         |         4.99        |    53.67%    |    39.97%    |       53,615      |     242    |

## Genel Bakış

Security logging ve monitoring, Top 10 topluluk anketinde (#3) yer aldı ve OWASP Top 10 2017’deki onuncu sıradan biraz yükseldi. Logging ve monitoring test etmesi zor alanlardır; çoğu zaman röportajlar veya bir penetration test sırasında saldırıların tespit edilip edilmediğini sorma yoluyla değerlendirilir. Bu kategori için çok fazla CVE/CVSS verisi olmasa da ihlallerin tespiti ve yanıtlanması kritiktir. Yine de accountability, görünürlük, incident alerting ve forensics açısından çok etkili olabilir. Bu kategori, *CWE-778 Insufficient Logging*’in ötesine genişleyerek *CWE-117 Improper Output Neutralization for Logs*, *CWE-223 Omission of Security-relevant Information* ve *CWE-532 Insertion of Sensitive Information into Log File*’ı da kapsar.

## Açıklama

OWASP Top 10 2021’e geri dönen bu kategori, aktif ihlallerin tespiti, yükseltilmesi (escalate) ve bunlara yanıt verilmesine yardımcı olur. Logging ve monitoring olmadan ihlaller tespit edilemez. Yetersiz logging, detection, monitoring ve aktif yanıt aşağıdaki durumların herhangi birinde gerçekleşir:

* Login’ler, başarısız login’ler ve yüksek değerli işlemler gibi denetlenebilir (auditable) event’ler log’lanmıyorsa.
* Uyarılar ve hatalar hiç, yetersiz veya belirsiz log mesajları üretiyorsa.
* Uygulama ve API log’ları şüpheli aktivite için monitor edilmiyorsa.
* Log’lar sadece lokal olarak tutuluyorsa.
* Uygun alerting eşikleri ve response escalation süreçleri yoksa veya etkisizse.
* Dynamic application security testing (DAST) araçları (ör. OWASP ZAP) ile yapılan penetration test ve taramalar alert tetiklemiyorsa.
* Uygulama aktif saldırıları gerçek zamanlı veya near real-time olarak tespit, escalate veya alert edemiyorsa.
* Logging ve alerting event’lerini bir kullanıcıya veya saldırgana görünür kılarak bilgi sızıntısına (information leakage) açık hale geliniyorsa (bkz. [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).
* Log verisi doğru şekilde encode edilmezse logging veya monitoring sistemlerine injection veya saldırılara açık olunuyorsa.

## Nasıl Önlenir

Uygulamanın riskine bağlı olarak geliştiriciler aşağıdaki kontrollerin bir kısmını veya tamamını uygulamalıdır:

* Tüm login, access control ve server-side input validation hatalarının; şüpheli veya kötü niyetli hesapları tanımlayacak yeterli user context ile log’lanmasını ve gecikmeli adli analiz (forensic analysis) için yeterince uzun süre tutulmasını sağlayın.
* Log’ların, log management çözümlerinin kolayca tüketebileceği bir formatta üretilmesini sağlayın.
* Logging veya monitoring sistemlerine injection/saldırıları önlemek için log verisini doğru şekilde encode edin.
* Yüksek değerli işlemler için, kurcalamayı (tampering) veya silmeyi önleyecek integrity kontrollerine sahip audit trail (ör. append-only database tabloları) sağlayın.
* DevSecOps ekipleri, şüpheli aktivitelerin hızlıca tespit edilip yanıtlanacağı etkili monitoring ve alerting kurmalıdır.
* National Institute of Standards and Technology (NIST) 800-61r2 veya daha yenisi gibi bir incident response ve recovery planı oluşturun veya benimseyin.

OWASP ModSecurity Core Rule Set gibi ticari ve açık kaynak uygulama koruma framework’leri ile Elasticsearch, Logstash, Kibana (ELK) stack gibi açık kaynak log korelasyon yazılımları; custom dashboard ve alerting özellikleri sunar.

## Örnek Saldırı Senaryoları

**Senaryo #1:** Bir çocuk sağlık planı sağlayıcısının web sitesi işletmecisi, monitoring ve logging eksikliği nedeniyle bir ihlali tespit edemedi. Harici bir taraf, saldırganın 3.5 milyonun üzerinde çocuğa ait binlerce hassas sağlık kaydına erişip bunları değiştirdiğini bildirdi. Olay sonrası incelemede, web sitesi geliştiricilerinin önemli zafiyetleri ele almadığı görüldü. Sistem üzerinde logging veya monitoring olmadığından, veri ihlali 2013’ten beri — yedi yılı aşkın bir süre — devam ediyor olabilirdi.

**Senaryo #2:** Büyük bir Hint havayolu şirketi, milyonlarca yolcunun on yılı aşkın kişisel verilerini (pasaport ve kredi kartı verileri dâhil) etkileyen bir veri ihlali yaşadı. Veri ihlali, üçüncü taraf bir cloud hosting sağlayıcısında meydana geldi ve ihlal bir süre sonra havayoluna bildirildi.

**Senaryo #3:** Büyük bir Avrupa havayolu şirketi GDPR kapsamında raporlanabilir bir ihlal yaşadı. İhlalin, saldırganlar tarafından istismar edilen payment application güvenlik zafiyetlerinden kaynaklandığı ve 400.000’den fazla müşteri ödeme kaydının toplandığı bildirildi. Havayolu, gizlilik düzenleyicisi tarafından 20 milyon pound para cezasına çarptırıldı.


## Referanslar

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V7 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Eşleştirilen CWE'lerin Listesi

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
