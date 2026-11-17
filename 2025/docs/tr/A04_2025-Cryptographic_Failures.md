# A04:2025 Kriptografik Hatalar ![simge](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## Arka Plan. 

İki basamak gerileyerek 4. sıraya inen bu zayıflık kategorisi; kriptografi eksikliği, yeterince güçlü olmayan kriptografi, kriptografik anahtarların sızdırılması ve ilgili hatalarla bağlantılı başarısızlıklara odaklanır. Bu riskteki en yaygın Common Weakness Enumeration (CWE) kayıtlarından üçü, zayıf bir sözde rastgele sayı üreticisinin kullanımıyla ilgilidir: *CWE-327 Use of a Broken or Risky Cryptographic Algorithm, CWE-331: Insufficient Entropy*, *CWE-1241: Use of Predictable Algorithm in Random Number Generator* ve *CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)*.



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
   <td>32
   </td>
   <td>13.77%
   </td>
   <td>3.80%
   </td>
   <td>100.00%
   </td>
   <td>47.74%
   </td>
   <td>7.23
   </td>
   <td>3.90
   </td>
   <td>1,665,348
   </td>
   <td>2,185
   </td>
  </tr>
</table>



## Açıklama. 

Genel olarak, aktarım hâlindeki tüm veriler [taşıma katmanında](https://en.wikipedia.org/wiki/Transport_layer) ([OSI katmanı](https://en.wikipedia.org/wiki/OSI_model) 4) şifrelenmelidir. CPU performansı ve özel anahtar/sertifika yönetimi gibi eskiden karşılaşılan engeller artık aşılmıştır: CPU'lar şifrelemeyi hızlandırmak için tasarlanmış komutlar içerir (ör. [AES desteği](https://en.wikipedia.org/wiki/AES_instruction_set)); özel anahtar ve sertifika yönetimi ise [LetsEncrypt.org](https://LetsEncrypt.org) gibi hizmetlerle kolaylaşmıştır ve büyük bulut sağlayıcıları kendi platformları için daha da sıkı entegre edilmiş sertifika yönetimi hizmetleri sunmaktadır. 

Taşıma katmanının güvenliğini sağlamanın ötesinde, hangi verilerin depolanırken (at rest) şifrelenmesi gerektiğini ve hangi verilerin aktarım sırasında ([uygulama katmanında](https://en.wikipedia.org/wiki/Application_layer), OSI katmanı 7) ek şifreleme gerektirdiğini belirlemek önemlidir. Örneğin parolalar, kredi kartı numaraları, sağlık kayıtları, kişisel bilgiler ve ticari sırlar, özellikle AB Genel Veri Koruma Tüzüğü (GDPR) gibi gizlilik yasalarına veya PCI Veri Güvenliği Standardı (PCI DSS) gibi düzenlemelere tabiyse ek koruma gerektirir. Bu tür verilerin tamamı için:



* Varsayılan olarak veya eski kodlarda eski ya da zayıf kriptografik algoritmalar veya protokoller kullanılıyor mu?
* Varsayılan kriptografik anahtarlar mı kullanılıyor, zayıf anahtarlar mı üretiliyor, anahtarlar yeniden mi kullanılıyor ya da uygun anahtar yönetimi ve rotasyonu eksik mi? 
* Kriptografik anahtarlar kaynak kod depolarına ekleniyor mu?
* Şifreleme zorunlu tutulmuyor mu; ör. HTTP başlıklarındaki (tarayıcı) güvenlik yönergeleri veya başlıklar eksik mi?
* Alınan sunucu sertifikası ve güven zinciri doğru şekilde doğrulanıyor mu?
* Başlatma vektörleri göz ardı mı ediliyor, yeniden mi kullanılıyor ya da kullanılan kriptografik çalışma kipi için yeterince güvenli şekilde üretilmiyor mu? ECB gibi güvensiz bir çalışma kipi mi kullanılıyor? Kimlik doğrulamalı şifrelemenin (authenticated encryption) daha uygun olduğu durumlarda yalnızca şifreleme mi kullanılıyor?
* Parola tabanlı bir anahtar türetme fonksiyonu olmadan parolalar kriptografik anahtar olarak mı kullanılıyor?
* Kriptografik gereksinimleri karşılamak üzere tasarlanmamış bir rastgelelik kaynağı mı kullanılıyor? Doğru fonksiyon seçilmiş olsa bile, bu fonksiyonun geliştirici tarafından tohumlanması (seed) gerekiyor mu; gerekmiyorsa, geliştirici fonksiyonun yerleşik güçlü tohumlama işlevini yeterli entropiden/öngörülemezlikten yoksun bir tohum değeriyle geçersiz kılmış mı?
* MD5 veya SHA1 gibi kullanımdan kaldırılmış hash fonksiyonları mı kullanılıyor ya da kriptografik hash fonksiyonlarının gerektiği yerlerde kriptografik olmayan hash fonksiyonları mı kullanılıyor?
* Kriptografik hata mesajları veya yan kanal bilgileri, örneğin padding oracle saldırıları biçiminde istismar edilebilir mi?
* Kriptografik algoritma daha zayıf bir algoritmaya düşürülebilir (downgrade) veya atlatılabilir mi?

Bkz. ASVS kaynakları: Cryptography (V11), Secure Communication (V12) ve Data Protection (V14).


## Nasıl Önlenir. 

En azından aşağıdakileri uygulayın ve kaynaklara başvurun:



* Bir uygulama tarafından işlenen, saklanan veya iletilen verileri sınıflandırın ve etiketleyin. Gizlilik yasalarına, düzenleyici gereksinimlere veya iş ihtiyaçlarına göre hangi verilerin hassas olduğunu belirleyin.
* En hassas anahtarlarınızı donanım tabanlı veya bulut tabanlı bir HSM'de saklayın.
* Mümkün olan her durumda kriptografik algoritmaların güvenilirliği kanıtlanmış implementasyonlarını kullanın.
* Hassas verileri gereksiz yere saklamayın. Bu verileri mümkün olan en kısa sürede silin ya da PCI DSS uyumlu tokenizasyon veya hatta kırpma (truncation) yöntemlerini kullanın. Saklanmayan veri çalınamaz.
* Depolanan tüm hassas verileri şifrelediğinizden emin olun.
* Güncel ve güçlü standart algoritmaların, protokollerin ve anahtarların kullanıldığından emin olun; uygun anahtar yönetimi uygulayın.
* Aktarım hâlindeki tüm verileri yalnızca >= TLS 1.2 protokolleriyle ve ileri gizlilik (forward secrecy, FS) sağlayan şifre takımlarıyla şifreleyin; şifre bloğu zincirleme (CBC) şifre takımlarına desteği kaldırın, kuantum anahtar değişim algoritmalarını destekleyin. HTTPS için şifrelemeyi HTTP Strict Transport Security (HSTS) ile zorunlu kılın. Her şeyi bir araçla kontrol edin.
* Hassas veri içeren yanıtlar için önbelleğe almayı devre dışı bırakın. Buna CDN'inizdeki, web sunucunuzdaki ve uygulama düzeyindeki her türlü önbelleğe alma (ör. Redis) dahildir.
* Veri sınıflandırmasına göre gerekli güvenlik kontrollerini uygulayın.
* FTP ve STARTTLS gibi şifrelenmemiş protokolleri kullanmayın. Gizli verileri iletmek için SMTP kullanmaktan kaçının.
* Parolaları Argon2, yescrypt, scrypt veya PBKDF2-HMAC-SHA-512 gibi iş faktörüne (gecikme faktörü) sahip, güçlü, uyarlanabilir ve tuz (salt) kullanan hash fonksiyonlarıyla saklayın. bcrypt kullanan eski sistemler için [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) kaynağından daha fazla öneri alın
* Başlatma vektörleri mutlaka çalışma kipine uygun şekilde seçilmelidir. Bu, bir CSPRNG (kriptografik olarak güvenli sözde rastgele sayı üreticisi) kullanmak anlamına gelebilir. Nonce gerektiren kiplerde başlatma vektörü (IV) için CSPRNG gerekmez. Her durumda, sabit bir anahtar için aynı IV asla iki kez kullanılmamalıdır.
* Yalnızca şifreleme yerine her zaman kimlik doğrulamalı şifreleme (authenticated encryption) kullanın.
* Anahtarlar kriptografik olarak rastgele üretilmeli ve bellekte bayt dizileri olarak saklanmalıdır. Parola kullanılıyorsa, uygun bir parola tabanlı anahtar türetme fonksiyonuyla mutlaka anahtara dönüştürülmelidir.
* Uygun yerlerde kriptografik rastgeleliğin kullanıldığından ve bunun öngörülebilir bir şekilde ya da düşük entropiyle tohumlanmadığından emin olun. Çoğu modern API, güvenli olması için geliştiricinin CSPRNG'yi tohumlamasını gerektirmez.
* MD5, SHA1, Cipher Block Chaining Mode (CBC), PKCS number 1 v1.5 gibi kullanımdan kaldırılmış kriptografik fonksiyonlardan, blok oluşturma yöntemlerinden ve dolgu (padding) şemalarından kaçının.
* Ayarların ve yapılandırmaların güvenlik gereksinimlerini karşıladığından, bunları güvenlik uzmanlarına, bu amaçla tasarlanmış araçlara veya her ikisine inceleterek emin olun.
* Yüksek riskli sistemlerin en geç 2030 yılı sonuna kadar güvenli hâle gelmesi için kuantum sonrası kriptografiye (PQC) şimdiden hazırlanmanız gerekir; bkz. kaynak (ENISA).


## Örnek Saldırı Senaryoları. 

**Senaryo #1**: Bir site tüm sayfalarda TLS kullanmıyor veya zorunlu tutmuyor ya da zayıf şifrelemeyi destekliyor. Saldırgan ağ trafiğini izler (ör. güvensiz bir kablosuz ağda), bağlantıları HTTPS'ten HTTP'ye düşürür, istekleri ele geçirir ve kullanıcının oturum çerezini çalar. Ardından bu çerezi yeniden kullanarak (replay) kullanıcının (kimliği doğrulanmış) oturumunu ele geçirir ve kullanıcının özel verilerine erişir veya bunları değiştirir. Saldırgan bunun yerine iletilen tüm verileri, örneğin bir para transferinin alıcısını da değiştirebilir.

**Senaryo #2**: Parola veritabanı, tüm kullanıcıların parolalarını saklamak için tuzsuz veya basit hash'ler kullanıyor. Bir dosya yükleme kusuru, saldırganın parola veritabanını ele geçirmesine olanak tanır. Tuzsuz hash'lerin tamamı, önceden hesaplanmış hash'lerden oluşan bir gökkuşağı tablosuyla (rainbow table) açığa çıkarılabilir. Basit veya hızlı hash fonksiyonlarıyla üretilen hash'ler, tuzlanmış olsalar bile GPU'larla kırılabilir.


## Kaynaklar.



* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data ](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS): ](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12, ](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)


## Eşlenen CWE'lerin Listesi

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)

* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)

* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)

* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)

* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)

* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
