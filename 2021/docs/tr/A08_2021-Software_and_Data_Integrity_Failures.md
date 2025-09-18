# A08:2021 – Software and Data Integrity Failures    ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 6.94                 | 7.94                | 75.04%       | 45.35%       | 47,972            | 1,152      |

## Genel Bakış

2021 için yeni bir kategori; doğrulama yapmadan software update’ler, kritik veriler ve CI/CD pipeline’larıyla ilgili varsayımlara odaklanır. Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) verilerinde en yüksek ağırlıklı impact’lerden birine sahiptir. Dikkate değer Common Weakness Enumerations (CWEs) arasında *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, *CWE-494: Download of Code Without Integrity Check* ve *CWE-502: Deserialization of Untrusted Data* bulunur.

## Açıklama 

Software ve data integrity hataları; integrity ihlallerine karşı koruma sağlamayan code ve infrastructure ile ilgilidir. Örneğin bir uygulamanın, güvenilmeyen kaynaklardan, repository’lerden ve content delivery network’lerden (CDN) plugin, library veya module’lere dayanması. Güvensiz bir CI/CD pipeline, yetkisiz erişim, malicious code veya sistem compromise riskini artırabilir. Son olarak, birçok uygulamada artık auto-update fonksiyonu vardır; burada update’ler yeterli integrity doğrulaması olmadan indirilir ve daha önce trusted olan uygulamaya uygulanır. Saldırganlar potansiyel olarak kendi update’lerini yükleyip tüm kurulumlara dağıtılmasını ve çalıştırılmasını sağlayabilir. Başka bir örnek; object’lerin veya verilerin attacker’ın görüp değiştirebileceği bir yapıya encode veya serialize edilmesi; bu, insecure deserialization’a karşı savunmasızdır.

## Nasıl Önlenir

-   Software veya verinin beklenen kaynaktan geldiğini ve değiştirilmediğini doğrulamak için dijital imza (digital signature) veya benzeri mekanizmalar kullanın.

-   npm veya Maven gibi library ve dependency’lerin trusted repository’lerden tüketildiğinden emin olun. Risk profiliniz yüksekse, vet edilmiş internal known-good bir repository barındırmayı düşünün.

-   OWASP Dependency Check veya OWASP CycloneDX gibi bir software supply chain security aracı kullanarak bileşenlerin bilinen zafiyetler içermediğini doğrulayın.

-   Software pipeline’ınıza malicious code veya configuration sokulma olasılığını en aza indirmek için code ve configuration değişiklikleri için bir review süreci sağlayın.

-   CI/CD pipeline’ınızın build ve deploy süreçlerinden geçen code’un integrity’sini korumak için uygun ayrıştırma (segregation), configuration ve access control’e sahip olduğundan emin olun.

-   İmzalanmamış veya encrypt edilmemiş serialized veriyi, integrity check veya digital signature olmaksızın untrusted client’lara göndermeyin; serialized verinin kurcalanmasını (tampering) veya replay’ini tespit edecek bir mekanizma kullanın.

## Örnek Saldırı Senaryoları

**Senaryo #1 İmzasız update:** Birçok ev router’ı, set-top box, device firmware’i ve diğerleri firmware update’lerini signed olarak doğrulamaz. Unsigned firmware, saldırganlar için büyüyen bir hedeftir ve yalnızca kötüleşmesi beklenir. Çoğu zaman remediation mekanizması yoktur; bir sonraki versiyonda düzeltmek ve eski versiyonların kullanım dışı kalmasını beklemekten başka çare olmaz.

**Senaryo #2 SolarWinds malicious update:** Devlet aktörlerinin update mekanizmalarını hedef aldığı bilinmektedir; yakın geçmişte dikkat çeken örnek SolarWinds Orion saldırısıdır. Software’ı geliştiren şirketin secure build ve update integrity süreçleri vardı; yine de bunlar atlatıldı ve birkaç ay boyunca 18.000’den fazla kuruluşa yüksek hedefli malicious bir update dağıtıldı; bunların yaklaşık 100 kadarı etkilendi. Bu, türünün en kapsamlı ve en önemli ihlallerinden biridir.

**Senaryo #3 Insecure Deserialization:** Bir React uygulaması bir dizi Spring Boot microservice’i çağırıyor. Fonksiyonel programlama yaklaşımıyla code’u immutable tutmak istiyorlar. Çözüm olarak user state’i serialize edip her istekte ileri-geri taşıyorlar. Bir saldırgan, “rO0” Java object imzasını (base64 içinde) fark ediyor ve Java Serial Killer aracını kullanarak application server üzerinde remote code execution elde ediyor.

## References

-   \[OWASP Cheat Sheet: Software Supply Chain Security\](Coming Soon)

-   \[OWASP Cheat Sheet: Secure build and deployment\](Coming Soon)

-    [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) 
 
-   [OWASP Cheat Sheet: Deserialization](
    <https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   [SAFECode Software Integrity Controls](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   [A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)

-   [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## List of Mapped CWEs

[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
