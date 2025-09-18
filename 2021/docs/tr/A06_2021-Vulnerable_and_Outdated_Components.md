# A06:2021 – Vulnerable and Outdated Components    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :----------: | :----------: | :------------------: | :-----------------: | :---------------: | :--------: |
|      3      |       27.96%       |        8.77%       |    51.78%    |    22.47%    |         5.00         |         5.00        |       30,457      |      0     |

## Genel Bakış

Top 10 topluluk anketinde #2 idi ve ayrıca verilere göre de Top 10’a girecek kadar yeterli veriye sahipti. Vulnerable Components, test edilmesi ve riskinin değerlendirilmesiyle mücadele ettiğimiz bilinen bir sorundur ve dâhil edilen CWE’lere eşlenen herhangi bir Common Vulnerabilities and Exposures (CVEs) bulunmayan tek kategoridir; bu nedenle varsayılan exploits/impact ağırlığı 5.0 olarak kullanılır. Dikkate değer CWE’ler arasında *CWE-1104: Use of Unmaintained Third-Party Components* ile 2013 ve 2017 Top 10’dan iki CWE bulunur.

## Açıklama

Aşağıdaki durumlarda muhtemelen savunmasızsınız:

* Kullandığınız tüm bileşenlerin (hem client-side hem de server-side) versiyonlarını bilmiyorsanız. Buna doğrudan kullandıklarınızın yanı sıra nested dependency’ler de dahildir.
* Yazılım (OS, web/application server, database management system (DBMS), uygulamalar, APIs ve tüm bileşenler, runtime environment’lar ve kütüphaneler dâhil) savunmasız, desteklenmiyor veya güncel değilse.
* Düzenli olarak zafiyet taraması yapmıyor ve kullandığınız bileşenlerle ilgili security bulletin’lere abone olmuyorsanız.
* Temel platformu, framework’leri ve dependency’leri risk temelli ve zamanında düzeltmiyor veya upgrade etmiyorsanız. Bu genellikle patching’in aylık veya üç aylık bir change control görevi olduğu ortamlarda yaşanır ve kuruluşları düzeltilmiş zafiyetlere karşı günlerce veya aylarca gereksiz açıkta bırakır.
* Yazılım geliştiriciler, güncellenmiş, upgrade edilmiş veya patch uygulanmış kütüphanelerin uyumluluğunu test etmiyorsa.
* Bileşenlerin configuration’larını güvence altına almıyorsanız (bkz. [A05:2021-Security Misconfiguration](A05_2021-Security_Misconfiguration.md)).

## Nasıl Önlenir

Aşağıdakileri kapsayan bir patch management süreci olmalıdır:

* Kullanılmayan dependency’leri, gereksiz özellikleri, bileşenleri, dosyaları ve dokümantasyonu kaldırın.
* Hem client-side hem de server-side bileşenlerin (örn. framework’ler, kütüphaneler) ve dependency’lerinin versiyonlarını sürekli olarak envanterleyin; versions, OWASP Dependency Check, retire.js vb. araçları kullanın. Common Vulnerabilities and Exposures (CVE) ve National Vulnerability Database (NVD) gibi kaynakları bileşenlerdeki zafiyetler için sürekli izleyin. Bu süreci otomatikleştirmek için software composition analysis araçlarını kullanın. Kullandığınız bileşenlerle ilgili security vulnerability e-posta uyarılarına abone olun.
* Bileşenleri yalnızca resmi kaynaklardan ve güvenli bağlantılar üzerinden edinin. Değiştirilmiş, kötü amaçlı bir bileşen ekleme olasılığını azaltmak için imzalı paketleri tercih edin (bkz. [A08:2021-Software and Data Integrity Failures](A08_2021-Software_and_Data_Integrity_Failures.md)).
* Bakımı yapılmayan veya eski versiyonlar için security patch üretmeyen kütüphane ve bileşenleri izleyin. Patching mümkün değilse, keşfedilen soruna karşı izleme, tespit veya koruma sağlayacak bir virtual patch uygulamayı değerlendirin.

Her kuruluş, uygulamanın veya portföyün yaşam döngüsü boyunca izleme, önceliklendirme (triage) ve update/konfigürasyon değişikliklerini uygulamaya yönelik sürekli bir plan sağlamalıdır.

## Örnek Saldırı Senaryoları

**Senaryo #1:** Bileşenler genellikle uygulamanın kendisiyle aynı ayrıcalıklarla çalıştığından, herhangi bir bileşendeki kusurlar ciddi etkilere yol açabilir. Bu kusurlar kazara (örn. coding error) veya kasıtlı (örn. bir bileşende backdoor) olabilir. Keşfedilmiş bazı istismar edilebilir bileşen zafiyetleri şunlardır:

* CVE-2017-5638, server üzerinde arbitrary code execution’a imkân veren bir Struts 2 remote code execution zafiyeti, büyük ihlallerden sorumlu tutulmuştur.
* Internet of Things (IoT) genellikle patch’lenmesi zor veya imkânsız olsa da, bunların patch’lenmesinin önemi büyük olabilir (örn. biyomedikal cihazlar).

Saldırganların patch uygulanmamış veya misconfigured sistemleri bulmasına yardımcı olan otomatik araçlar vardır. Örneğin, Shodan IoT arama motoru, Nisan 2014’te patch’lenen Heartbleed zafiyetinden hâlâ etkilenen cihazları bulmanıza yardımcı olabilir.


## Referanslar
- [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](/www-project-application-security-verification-standard)

- [OWASP Dependency Check (for Java and .NET libraries)](/www-project-dependency-check)

- [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture)

- [OWASP Virtual Patching Best Practices](/www-community/Virtual_Patching_Best_Practices)

- [The Unfortunate Reality of Insecure Libraries](https://cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf)

- [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)

- [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)

- [GitHub Advisory Database](https://github.com/advisories)

- [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)

- [SAFECode Software Integrity Controls \[PDF\]](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)


## Eşleştirilen CWE Listesi

[CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/937.html)

[CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

[CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
