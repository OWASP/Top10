# A07:2025 Kimlik Doğrulama Hataları ![simge](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## Arka Plan. 

Kimlik Doğrulama Hataları, bu kategorideki 36 CWE'yi daha doğru yansıtmak amacıyla adında küçük bir değişiklik yapılarak 7. sıradaki yerini koruyor. Standartlaştırılmış framework'lerin sağladığı faydalara rağmen bu kategori, 2021'deki 7. sırasını korudu. Öne çıkan CWE'ler arasında *CWE-259 Use of Hard-coded Password*, *CWE-297: Improper Validation of Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, *CWE-384: Session Fixation* ve *CWE-798 Use of Hard-coded Credentials* yer alıyor.


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
   <td>36
   </td>
   <td>15.80%
   </td>
   <td>2.92%
   </td>
   <td>100.00%
   </td>
   <td>37.14%
   </td>
   <td>7.69
   </td>
   <td>4.44
   </td>
   <td>1,120,673
   </td>
   <td>7,147
   </td>
  </tr>
</table>



## Açıklama. 

Saldırganın bir sistemi, geçersiz veya yanlış bir kullanıcıyı meşru kullanıcı olarak tanıyacak şekilde kandırabildiği durumlarda bu güvenlik açığı mevcuttur. Uygulamada aşağıdaki durumlar varsa kimlik doğrulama zayıflıkları bulunabilir:

* Saldırganın, sızdırılmış geçerli kullanıcı adı ve parola listelerine sahip olduğu credential stuffing (kimlik bilgisi doldurma) gibi otomatik saldırılara izin veriliyorsa. Son zamanlarda bu saldırı türü, saldırganın erişim elde etmek için sızdırılmış kimlik bilgilerinin varyasyonlarını veya artırılmış hâllerini denediği (örneğin Password1!, Password2!, Password3! vb.) hibrit parola saldırılarını, yani hibrit credential stuffing'i (password spray saldırıları olarak da bilinir) kapsayacak şekilde genişlemiştir.

* Hızla engellenmeyen kaba kuvvet (brute force) veya diğer otomatik, betik tabanlı saldırılara izin veriliyorsa.

* "Password1" ya da "admin" kullanıcı adıyla "admin" parolası gibi varsayılan, zayıf veya iyi bilinen parolalara izin veriliyorsa.

* Kullanıcıların, sızdırıldığı zaten bilinen kimlik bilgileriyle yeni hesap oluşturmasına izin veriliyorsa.

* Güvenli hâle getirilmesi mümkün olmayan "bilgiye dayalı cevaplar" gibi zayıf veya etkisiz kimlik bilgisi kurtarma ve parola sıfırlama süreçlerinin kullanılmasına izin veriliyorsa.

* Parolaları düz metin, şifrelenmiş veya zayıf hash'lenmiş olarak tutan veri depoları kullanılıyorsa (bkz.[ A04:2025-Kriptografik Hatalar](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)).

* Çok faktörlü kimlik doğrulama eksik veya etkisizse.

* Çok faktörlü kimlik doğrulama kullanılamadığında zayıf veya etkisiz yedek yöntemlerin kullanılmasına izin veriliyorsa. 

* Oturum tanımlayıcısı URL'de, gizli bir alanda veya istemcinin erişebildiği başka bir güvensiz konumda açığa çıkarılıyorsa.

* Başarılı oturum açma işleminden sonra aynı oturum tanımlayıcısı yeniden kullanılıyorsa.

* Oturum kapatma sırasında veya belirli bir hareketsizlik süresinin ardından kullanıcı oturumları ya da kimlik doğrulama token'ları (özellikle çoklu oturum açma (SSO) token'ları) doğru şekilde geçersiz kılınmıyorsa.

* Sağlanan kimlik bilgilerinin kapsamı ve hedeflenen alıcısı (audience) doğru şekilde doğrulanmıyorsa.

## Nasıl Önlenir. 

* Mümkün olan yerlerde, otomatik credential stuffing, kaba kuvvet ve çalınmış kimlik bilgilerinin yeniden kullanılması saldırılarını önlemek için çok faktörlü kimlik doğrulamayı uygulayın ve kullanımını zorunlu kılın.

* Mümkün olan yerlerde, kullanıcıların daha iyi seçimler yapmasına yardımcı olmak için parola yöneticilerinin kullanımını teşvik edin ve mümkün kılın.

* Özellikle yönetici kullanıcılar için, hiçbir varsayılan kimlik bilgisiyle ürün teslim etmeyin veya devreye almayın.

* Yeni veya değiştirilmiş parolaları en kötü 10.000 parola listesine karşı test etmek gibi zayıf parola kontrolleri uygulayın.

* Yeni hesap oluşturma ve parola değiştirme sırasında, sızdırıldığı bilinen kimlik bilgisi listelerine karşı doğrulama yapın (ör. [haveibeenpwned.com](https://haveibeenpwned.com) kullanarak).

* Parola uzunluğu, karmaşıklığı ve rotasyonu politikalarını, Ezberlenmiş Sırlar (Memorized Secrets) için [National Institute of Standards and Technology (NIST) 800-63b'nin 5.1.1 bölümündeki yönergelerle](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) veya diğer modern, kanıta dayalı parola politikalarıyla uyumlu hâle getirin.

* Bir ihlalden şüphelenmediğiniz sürece insanları parolalarını periyodik olarak değiştirmeye zorlamayın. İhlalden şüpheleniyorsanız parola sıfırlamayı derhâl zorunlu kılın. 

* Tüm sonuçlar için aynı mesajı (“Geçersiz kullanıcı adı veya parola.”) kullanarak kayıt, kimlik bilgisi kurtarma ve API yollarının hesap tespiti (account enumeration) saldırılarına karşı sıkılaştırıldığından emin olun.

* Başarısız oturum açma girişimlerini sınırlayın veya giderek artan gecikmelerle yavaşlatın; ancak bir hizmet reddi senaryosu yaratmamaya dikkat edin. Tüm başarısız girişimleri günlüğe kaydedin ve credential stuffing, kaba kuvvet veya diğer saldırılar tespit edildiğinde ya da bunlardan şüphelenildiğinde yöneticileri uyarın.

* Oturum açıldıktan sonra yüksek entropiye sahip, yeni ve rastgele bir oturum kimliği üreten, sunucu tarafında çalışan, güvenli ve yerleşik bir oturum yöneticisi kullanın. Oturum tanımlayıcıları URL'de yer almamalı, güvenli bir çerezde güvenli şekilde saklanmalı ve oturum kapatıldıktan sonra, hareketsizlik zaman aşımında ve mutlak zaman aşımında geçersiz kılınmalıdır. 

* İdeal olarak, kimlik doğrulama, kimlik ve oturum yönetimi için hazır ve güvenilirliği kanıtlanmış bir sistem kullanın. Mümkün olduğunda, sıkılaştırılmış ve iyi test edilmiş bir sistem satın alıp kullanarak bu riski devredin.

* Sağlanan kimlik bilgilerinin amaçlanan kullanımını doğrulayın; ör. JWT'ler için `aud`, `iss` claim'lerini ve kapsamlarını (scope) doğrulayın


## Örnek Saldırı Senaryoları. 

**Senaryo #1:** Bilinen kullanıcı adı ve parola kombinasyonlarından oluşan listelerin kullanıldığı credential stuffing, günümüzde çok yaygın bir saldırıdır. Son zamanlarda saldırganların yaygın insan davranışlarından yola çıkarak parolaları ‘artırdığı’ veya başka şekillerde uyarladığı görülmüştür. Örneğin ‘Winter2025’i ‘Winter2026’ya ya da ‘ILoveMyDog6’yı ‘ILoveMyDog7’ veya ‘ILoveMyDog5’e çevirmek gibi. Parola denemelerinin bu şekilde uyarlanmasına hibrit credential stuffing saldırısı veya password spray saldırısı denir ve bu saldırılar geleneksel sürümden bile daha etkili olabilir. Bir uygulama otomatik tehditlere (kaba kuvvet, betikler veya botlar) ya da credential stuffing'e karşı savunma uygulamıyorsa, kimlik bilgilerinin geçerli olup olmadığını belirlemek ve yetkisiz erişim elde etmek için uygulama bir parola kâhini (password oracle) olarak kullanılabilir.

**Senaryo #2:** Başarılı kimlik doğrulama saldırılarının çoğu, parolaların tek kimlik doğrulama faktörü olarak kullanılmaya devam edilmesinden kaynaklanır. Bir zamanlar en iyi uygulama olarak kabul edilen parola rotasyonu ve karmaşıklık gereksinimleri, kullanıcıları hem parolalarını yeniden kullanmaya hem de zayıf parolalar seçmeye yöneltir. Kuruluşlara, NIST 800-63 uyarınca bu uygulamalara son vermeleri ve tüm önemli sistemlerde çok faktörlü kimlik doğrulamayı zorunlu kılmaları önerilir.

**Senaryo #3:** Uygulamanın oturum zaman aşımları doğru şekilde uygulanmamıştır. Bir kullanıcı, bir uygulamaya erişmek için herkesin kullanımına açık bir bilgisayar kullanır ve "oturumu kapat" seçeneğini seçmek yerine yalnızca tarayıcı sekmesini kapatıp uzaklaşır. Buna bir başka örnek de çoklu oturum açma (SSO) oturumunun tekli oturum kapatma (Single Logout, SLO) ile kapatılamamasıdır. Yani tek bir oturum açma işlemi sizi örneğin e-posta okuyucunuzda, belge sisteminizde ve sohbet sisteminizde oturum açmış hâle getirir; ancak oturum kapatma yalnızca o anda kullanılan sistemde gerçekleşir. Kurban oturumu başarıyla kapattığını düşündükten sonra, kullanıcının kimliği bazı uygulamalarda hâlâ doğrulanmış durumdayken bir saldırgan aynı tarayıcıyı kullanırsa kurbanın hesabına erişebilir. Aynı sorun ofislerde ve kurumlarda, hassas bir uygulamadan düzgün şekilde çıkılmadığında ve bir iş arkadaşının kilitlenmemiş bilgisayara (geçici olarak) erişimi olduğunda da yaşanabilir.

## Kaynaklar.

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## Eşlenen CWE'lerin Listesi

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)
