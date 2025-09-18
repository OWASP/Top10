# A10:2021 – Server-Side Request Forgery (SSRF)    ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      1      |        2.72%       |        2.72%       |         8.28         |         6.72        |    67.72%    |    67.72%    |       9,503       |     385    |

## Genel Bakış

Bu kategori, Top 10 topluluk anketinden (#1) eklendi. Veriler, ortalamanın üzerinde test kapsamıyla birlikte nispeten düşük bir görülme oranı ve ortalamanın üzerinde Exploit ile Impact potansiyel dereceleri göstermektedir. Yeni girdiler genellikle dikkat ve farkındalık için tek bir CWE veya küçük bir CWE kümesi olacağından, odaklanmaları ve gelecekteki bir sürümde daha büyük bir kategoriye katlanmaları umulur.

## Açıklama

SSRF hataları, bir web uygulaması kullanıcı tarafından sağlanan URL’yi doğrulamadan uzak bir kaynağı fetch ettiğinde ortaya çıkar. Bu, saldırganın uygulamayı, firewall, VPN veya başka bir network access control list (ACL) ile korunuyor olsa bile beklenmeyen bir hedefe crafted bir istek göndermeye zorlamasına imkân tanır.

Modern web uygulamaları son kullanıcılara kullanışlı özellikler sundukça, bir URL’i fetch etmek yaygın bir senaryo hâline gelir. Sonuç olarak, SSRF’nin görülme sıklığı artıyor. Ayrıca cloud servisleri ve mimarilerin karmaşıklığı nedeniyle SSRF’nin ciddiyeti de yükseliyor.

## Nasıl Önlenir

Geliştiriciler, aşağıdaki defense-in-depth kontrollerinin bir kısmını veya tamamını uygulayarak SSRF’yi önleyebilir:

### **Network katmanından**

* Uzak kaynak erişimi fonksiyonelliğini ayrı network’lere ayırın; SSRF’nin etkisini azaltın.
* “Varsayılan olarak reddet (deny by default)” firewall policy’leri veya network access control kuralları uygulayın; temel intranet trafiği dışındaki her şeyi engelleyin.<br/>
  *İpuçları:*<br/>
  \~ Firewall kuralları için uygulama bazlı sahiplik ve lifecycle oluşturun.<br/>
  \~ Firewall’larda kabul edilen *ve* engellenen tüm network akışlarını log’layın (bkz. [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)).

### **Application katmanından**

* Tüm client tarafından sağlanan input verisini sanitize ve validate edin.
* URL schema, port ve destination’ı pozitif bir allow list ile zorunlu kılın.
* Ham (raw) response’ları client’a göndermeyin.
* HTTP redirection’ları devre dışı bırakın.
* DNS rebinding ve “time of check, time of use” (TOCTOU) race condition gibi saldırılardan kaçınmak için URL tutarlılığının farkında olun.

SSRF’yi bir deny list veya regular expression kullanarak azaltmayın. Saldırganların deny list’leri atlamak için payload listeleri, araçları ve yetenekleri vardır.

### **Düşünülebilecek Ek Önlemler:**

* Önyüz (front) sistemlerinde başka security-relevant servisleri (örn. OpenID) deploy etmeyin. Bu sistemlerde local trafiği (örn. localhost) kontrol edin.
* Yönetilebilir, dedike kullanıcı gruplarına sahip frontend’ler için, çok yüksek koruma ihtiyacı düşünülüyorsa bağımsız sistemlerde network encryption (örn. VPN) kullanın.

## Örnek Saldırı Senaryoları

Saldırganlar, aşağıdaki senaryolar gibi web application firewall’ları, firewall’lar veya network ACL’leri ile korunan sistemlere SSRF kullanarak saldırabilir:

**Senaryo #1: İç sunucuların port taraması** – Network mimarisi segmentlenmemişse, saldırganlar bağlantı sonuçlarından veya SSRF payload bağlantılarını kurma/ret etme süresinden iç ağları haritalayabilir ve iç sunucularda portların açık mı kapalı mı olduğunu belirleyebilir.

**Senaryo #2: Hassas veri sızıntısı** – Saldırganlar yerel dosyalara veya iç servislere erişerek `file:///etc/passwd` ve `http://localhost:28017/` gibi hassas bilgileri elde edebilir.

**Senaryo #3: Cloud servislerinin metadata storage’ına erişim** – Çoğu cloud sağlayıcısında `http://169.254.169.254/` gibi metadata storage bulunur. Bir saldırgan, metadata’yı okuyarak hassas bilgiler elde edebilir.

**Senaryo #4: İç servislerin ele geçirilmesi** – Saldırgan, iç servisleri kötüye kullanarak Remote Code Execution (RCE) veya Denial of Service (DoS) gibi sonraki saldırıları gerçekleştirebilir.

## Referanslar

* [OWASP - Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
* [Acunetix - What is Server-Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)
* [SSRF bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)
* [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## Eşlenen CWE Listesi

[CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

