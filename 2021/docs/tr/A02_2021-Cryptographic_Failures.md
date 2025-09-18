# A02:2021 – Cryptographic Failures    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Eşleştirildi | Maks Görülme Oranı | Ort. Görülme Oranı | Ort. Ağırlıklı Exploit | Ort. Ağırlıklı Impact | Maks Coverage | Ort. Coverage | Toplam Olay | Toplam CVE |
| :---------------: | :----------------: | :----------------: | :--------------------: | :-------------------: | :-----------: | :-----------: | :---------: | :--------: |
|         29        |       46.44%       |        4.49%       |          7.29          |          6.81         |     79.33%    |     34.85%    |   233,788   |    3,075   |

## Genel Bakış

Daha önce *Sensitive Data Exposure* olarak bilinen ve bir kök neden yerine daha çok geniş bir semptomu tanımlayan kategori, bir basamak yükselerek #2’ye geldi. Odak noktası, kriptografiyle (veya yokluğuyla) ilgili hatalardır. Bunlar çoğu zaman hassas verilerin açığa çıkmasına yol açar. Dikkate değer Common Weakness Enumeration (CWE) örnekleri arasında *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky Crypto Algorithm* ve *CWE-331: Insufficient Entropy* yer alır.

## Açıklama

İlk yapılacak şey, hem transit halinde hem de at rest durumundaki verilerin korunma ihtiyacını belirlemektir. Örneğin parolalar, kredi kartı numaraları, sağlık kayıtları, kişisel bilgiler ve ticari sırlar; özellikle bu veriler gizlilik yasalarına (ör. AB’nin GDPR’ı) veya düzenlemelere (ör. finansal veriler için PCI DSS) tabi ise, ekstra koruma gerektirir. Böyle veriler için:

* Herhangi bir veri clear text olarak mı iletiliyor? Bu, HTTP, SMTP, FTP gibi protokolleri ve STARTTLS gibi TLS upgrade’lerini de kapsar. Harici internet trafiği tehlikelidir. Load balancer’lar, web server’lar veya back-end sistemler arasındaki tüm internal trafiği doğrulayın.

* Varsayılan olarak veya eski kodlarda herhangi bir eski/zayıf kriptografik algoritma ya da protokol kullanılıyor mu?

* Varsayılan crypto key’ler mi kullanılıyor, zayıf key’ler mi üretiliyor veya doğru key management/rotation eksik mi? Crypto key’ler source code repository’lere commitlenmiş mi?

* Encryption zorunlu kılınmıyor mu; örneğin (browser) security directive’leri veya HTTP header’ları eksik mi?

* Alınan server certificate ve trust chain düzgün biçimde doğrulanıyor mu?

* Initialization vector’lar (IV) yok sayılıyor, yeniden kullanılıyor veya ilgili mode of operation için yeterince güvenli üretilmiyor mu? ECB gibi güvenli olmayan bir mode kullanılıyor mu? Sadece encryption yerine authenticated encryption daha uygunken yanlış kullanım var mı?

* Password-based key derivation function olmaksızın parolalar crypto key olarak mı kullanılıyor?

* Kriptografik amaçlar için tasarlanmamış randomness mi kullanılıyor? Doğru fonksiyon seçilmiş olsa bile developer tarafından seed edilmesi gerekiyor mu ve eğer gerekmiyorsa, developer güçlü seeding’i düşük entropy/tahmin edilebilir bir seed ile ezmiş olabilir mi?

* MD5 veya SHA1 gibi deprecated hash fonksiyonları kullanılıyor mu ya da kriptografik hash gereken yerlerde non-cryptographic hash fonksiyonları mı kullanılıyor?

* PKCS number 1 v1.5 gibi deprecated cryptographic padding yöntemleri kullanılıyor mu?

* Cryptographic error message’lar veya side-channel bilgiler exploitable mı; örneğin padding oracle saldırılarıyla?

ASVS Crypto (V7), Data Protection (V9) ve SSL/TLS (V10)’a bakın.

## Nasıl Önlenir

Minimum olarak şunları yapın ve referansları danışın:

* Uygulamanın işlediği, depoladığı veya ilettiği verileri sınıflandırın. Hangi verilerin gizlilik yasaları, düzenleyici gereklilikler veya iş ihtiyaçları açısından hassas olduğunu belirleyin.

* Gereksiz yere hassas veri depolamayın. Mümkün olan en kısa sürede atın veya PCI DSS uyumlu tokenization ya da truncation kullanın. Saklanmayan veri çalınamaz.

* Tüm hassas verileri at rest durumda encrypt edin.

* Güncel ve güçlü standart algoritma, protokol ve key’leri kullanın; doğru key management uygulayın.

* Tüm verileri in transit durumda TLS gibi secure protocol’lerle encrypt edin; forward secrecy (FS) cipher’ları, server tarafında cipher önceliklendirmesi ve secure parametreler kullanın. HTTP Strict Transport Security (HSTS) gibi directive’lerle encryption’ı zorunlu kılın.

* Hassas veri içeren response’lar için caching’i devre dışı bırakın.

* Veri sınıflandırmasına göre gerekli security control’lerini uygulayın.

* Hassas veri taşımak için FTP ve SMTP gibi legacy protokolleri kullanmayın.

* Parolaları Argon2, scrypt, bcrypt veya PBKDF2 gibi güçlü, adaptive ve salted hashing function’larıyla, uygun work factor (delay factor) kullanarak saklayın.

* Initialization vector (IV) seçimi mode of operation’a uygun olmalıdır. Birçok mode için CSPRNG (cryptographically secure pseudo random number generator) uygundur. Nonce gerektiren mode’larda IV için CSPRNG gerekmez. Tüm durumlarda, sabit bir key için aynı IV asla iki kez kullanılmamalıdır.

* Sadece encryption yerine her zaman authenticated encryption kullanın.

* Key’ler kriptografik olarak rastgele üretilmeli ve memory’de byte array olarak saklanmalıdır. Eğer password kullanılacaksa, uygun bir password-based key derivation function ile key’e dönüştürülmelidir.

* Gereken yerlerde kriptografik randomness kullanıldığından ve tahmin edilebilir/düşük entropy ile seed edilmediğinden emin olun. Modern API’lerin çoğu güvenlik için developer’ın CSPRNG’yi seed etmesini gerektirmez.

* MD5, SHA1, PKCS number 1 v1.5 gibi deprecated kriptografik fonksiyon ve padding şemalarından kaçının.

* Konfigürasyon ve ayarların etkinliğini bağımsız şekilde doğrulayın.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Bir uygulama, veritabanındaki kredi kartı numaralarını otomatik veritabanı encryption’ı ile şifreliyor. Ancak bu veriler geri çekildiğinde otomatik olarak decrypt ediliyor; bu da bir SQL injection açığının kredi kartı numaralarını clear text olarak almasına izin veriyor.

**Senaryo #2**: Bir site tüm sayfalar için TLS kullanmıyor/enforce etmiyor veya zayıf encryption destekliyor. Bir saldırgan (ör. güvensiz bir kablosuz ağda) ağ trafiğini izliyor, bağlantıları HTTPS’ten HTTP’ye downgrade ediyor, istekleri kesiyor ve kullanıcının session cookie’sini çalıyor. Saldırgan daha sonra bu cookie’yi yeniden oynatıp kullanıcının (authenticated) oturumunu ele geçiriyor ve özel verilere erişiyor veya bunları değiştiriyor. Alternatif olarak taşınan tüm verileri de manipüle edebilir (ör. bir para transferinin alıcısını).

**Senaryo #3**: Parola veritabanı, herkesin parolasını unsalted veya basit hash’lerle saklıyor. Bir file upload açığı, saldırganın parola veritabanını almasına izin veriyor. Tüm unsalted hash’ler, önceden hesaplanmış hash’lerin bulunduğu rainbow table ile açığa çıkarılabiliyor. Basit veya hızlı hash fonksiyonlarıyla üretilen hash’ler, salted olsalar bile GPU’larla kırılabilir.

## Referanslar

* [OWASP Proactive Controls: Protect Data Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

* [OWASP Application Security Verification Standard (V7, 9, 10)](https://owasp.org/www-project-application-security-verification-standard)

* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)

## Eşleştirilen CWE Listesi

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

