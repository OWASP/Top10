# A05:2021 – Security Misconfiguration    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Eşleştirildi | Maks Görülme Oranı | Ort. Görülme Oranı | Ort. Ağırlıklı Exploit | Ort. Ağırlıklı Impact | Maks Coverage | Ort. Coverage | Toplam Olay | Toplam CVE |
| :---------------: | :----------------: | :----------------: | :--------------------: | :-------------------: | :-----------: | :-----------: | :---------: | :--------: |
|         20        |       19.84%       |        4.51%       |          8.12          |          6.56         |     89.58%    |     44.84%    |   208,387   |     789    |

## Genel Bakış

Önceki sürümdeki #6’dan yükselerek, uygulamaların %90’ı bir tür misconfiguration için test edildi; ortalama görülme oranı %4.51 ve bu risk kategorisinde 208 binden fazla Common Weakness Enumeration (CWE) olayı kaydedildi. Yüksek düzeyde konfigüre edilebilir yazılımlara geçiş arttıkça, bu kategorinin yükselmesi şaşırtıcı değildir. Dikkate değer CWE’ler arasında *CWE-16 Configuration* ve *CWE-611 Improper Restriction of XML External Entity Reference* bulunur.

## Açıklama

Uygulama aşağıdaki durumlarda zafiyete açık olabilir:

* Application stack’in herhangi bir bölümünde uygun security hardening eksikse veya cloud servislerinde izinler yanlış konfigüre edildiyse.

* Gereksiz özellikler etkinleştirilmiş ya da kurulmuşsa (ör. gereksiz port’lar, servisler, sayfalar, hesaplar veya ayrıcalıklar).

* Varsayılan hesaplar ve bunların parolaları hâlâ etkin ve değişmemişse.

* Error handling, kullanıcıya stack trace’ler veya aşırı bilgi içeren hata mesajları gösteriyorsa.

* Yükseltilmiş sistemlerde, en yeni security özellikleri devre dışıysa veya güvenli şekilde konfigüre edilmemişse.

* Application server’ları, application framework’leri (ör. Struts, Spring, ASP.NET), kütüphaneler, veritabanları vb. içindeki security ayarları güvenli değerlere set edilmemişse.

* Server, security header’ları veya directive’leri göndermiyorsa ya da bunlar güvenli değerlere set edilmemişse.

* Yazılım güncel değilse veya zafiyetliyse (bkz. [A06:2021 – Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)).

Planlı ve tekrarlanabilir bir application security configuration süreci olmadan sistemler daha yüksek risk altındadır.

## Nasıl Önlenir

Güvenli kurulum süreçleri uygulanmalıdır; bunlar şunları içerir:

* Tekrarlanabilir bir hardening süreci, uygun şekilde kilitlenmiş başka bir ortamın hızlı ve kolay şekilde deploy edilmesini sağlar. Development, QA ve production ortamları aynı şekilde konfigüre edilmeli; her ortamda farklı credential’lar kullanılmalıdır. Yeni güvenli bir ortam kurulumunda eforu minimize etmek için bu süreç otomatikleştirilmelidir.

* Gereksiz özellikler, bileşenler, dokümantasyon ve örnekler olmadan minimal bir platform. Kullanılmayan feature ve framework’leri kaldırın ya da hiç kurmayın.

* Patch management sürecinin bir parçası olarak, tüm security notlarına, update ve patch’lere uygun konfigürasyonları gözden geçirip güncelleme görevi (bkz. [A06:2021 – Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)). Cloud storage izinlerini (ör. S3 bucket permission’ları) gözden geçirin.

* Segmentasyon, containerization veya cloud security group’ları (ACL’ler) ile bileşenler veya tenant’lar arasında etkili ve güvenli ayrım sağlayan segmented bir application architecture.

* Client’lara security directive’leri göndermek; ör. Security Headers.

* Tüm ortamlarda konfigürasyon ve ayarların etkinliğini doğrulayan otomatik bir süreç.

## Örnek Saldırı Senaryoları

**Senaryo #1:** Application server, production’da kaldırılmamış sample application’larla birlikte geliyor. Bu sample’ların bilinen security açıkları vardır ve saldırganlar server’ı ele geçirmek için bunları kullanır. Bu uygulamalardan biri admin console ise ve varsayılan hesaplar değiştirilmemişse, saldırgan default password’lerle giriş yapar ve kontrolü ele geçirir.

**Senaryo #2:** Server’da directory listing devre dışı değildir. Bir saldırgan, dizinleri basitçe listeyebildiğini keşfeder. Derlenmiş Java class’larını bulur ve indirir; bunları decompile ederek kodu inceler. Ardından uygulamada ciddi bir access control açığı bulur.

**Senaryo #3:** Application server konfigürasyonu, detaylı hata mesajlarının (ör. stack trace’ler) kullanıcılara döndürülmesine izin verir. Bu, potansiyel olarak hassas bilgileri veya bilinen zafiyetlere sahip bileşen versiyonları gibi temel açıkları ortaya çıkarabilir.

**Senaryo #4:** Bir cloud service provider (CSP), diğer CSP kullanıcıları tarafından Internet’e açık varsayılan paylaşım izinlerine sahiptir. Bu durum, cloud storage içinde saklanan hassas verilere erişilmesine olanak tanır.


## Referanslar

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   [Application Security Verification Standard V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Eşleştirilen CWE Listesi

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
