# A3:2017 Hassas Bilgi İfşası

| Tehdit etkenleri/Saldırı vektörleri | Güvenlik zafiyeti | Etkiler |
| -- | -- | -- |
| Erişim düzeyi : İstismar Edilebilirlik 2 | Yaygınlık 3 : Tespit Edilebilirlik 2 | Teknik 3 : İş |
| Doğrudan şifrelemeye saldırmak yerine saldırganlar anahtarları çalmakta, ortadaki adam saldırıları gerçekleştirmekte veya sunucudan transit halindeyken veya istemcinin tarayıcısından açık metin verileri çalmaktadır. Genellikle, elle yapılacak bir saldırı gerekmektedir. Daha önceden elde edilen parola veri tabanları grafik işleme üniteleri (GPU) tarafından kaba kuvvet saldırısında kullanılmaktadır. | Son birkaç yıldır, bu açıklık ciddi etkileri olan en yaygın saldırılara neden olmuştur. En yaygın açıklık hassas verinin şifrelenmemesidir. Şifreleme uygulandığında, özellikle zayıf parola özeti ile saklama yöntemleri için zayıf anahtar üretimi ve yönetimi, zayıf algoritma, protokol ve anahtar kullanımı yaygındır. Veri transit halindeyken, sunucu taraflı açıklıkların tespit edilmesi kolaydır, ancak durağan veri için tespit zor olmaktadır. | Eksiklikler sıklıkla korunması gereken tüm veriyi tehlikeye atmaktadır. Genellikle, bu veriler AB GDPR veya yerel gizlilik kanunları gibi yasalarda veya düzenlenmelerde tanımlandığı gibi koruma gerektiren kredi kartı numarası, kişisel veriler, giriş bilgileri, sağlık kayıtları gibi hassas kişisel bilgileri (PII) içermektedir. |

## Uygulamam Açıklık İçeriyor Mu?

Yapılacak ilk şey transit ve durağan veri için koruma gereksinimlerinin belirlenmesidir. Örneğin, parolalar, kredi kartı numaraları, sağlık kayıtları, kişisel bilgiler ve iş sırları, özellikle veri AB Genel Veri Koruma Tüzüğü (GDPR) gibi yasalar veya PCI Veri Güvenliği Standardı (PCI DSS) gibi finansal veri koruma düzenlemeleri tarafından korunuyorsa, ilave koruma önlemleri gerektirmektedir. Bu kapsamdaki tüm veriler için:

* Herhangi bir veri açık metin olarak iletiliyor mu? Bu HTTP, SMTP ve FTP gibi protokolleri ilgilendirmektedir. Özellikle dış internet trafiği tehlike taşımaktadır. Tüm iç trafik örn. yük dengeleyiciler, web sunucuları veya arka uç sistemleri arasındaki trafik, doğrulanmalıdır. 
* Varsayılan olarak ve eski kod içerisinde herhangi bir eski veya zayıf kriptografik algoritma kullanılmakta mı? 
* Varsayılan kripto anahtarları kullanılmakta mı, zayıf kripto anahtarları üretilmekte veya tekrar kullanılmakta mı? Yeterli anahtar yönetimi veya değişimi bulunmakta mı?
* Şifreleme zorunlu tutuluyor mu? örn. herhangi bir tarayıcı güvenlik direktifi veya başlığı eksik mi?
* Kullanıcı aracısı (örn. uygulama, mail istemcisi) alınan sunucu sertifikasının geçerli olup olmadığını doğruluyor mu?

Bakınız ASVS [Şifreleme (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [Veri Koruma (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection) ve [SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications).

## Nasıl Önlenir

En azından aşağıdakiler yapılmalı ve referanslara başvurulmalıdır:

* Bir uygulama tarafından işlenen, saklanılan veya iletilen veri sınıflandırılmalıdır. Gizlilik kanunlarına, yasal gereksinimlere ve iş ihtiyaçlarına göre hassas olan veriler belirlenmelidir.
* Her bir sınıflandırma için kontroller uygulanmalıdır.
* Gerek duyulmayacaksa hassas veriler saklanmamalıdır. Mümkün olduğunca erken bir şekilde hassas veri elden çıkarılmalı veya PCI DSS standardına uygun bir şekilde dizgeciklendirilmeli veya silinmelidir. Saklanmayan veri çalınamaz. 
* Durağan tüm hassas verilerin şifrelendiğinden emin olunmalıdır.
* Güncel ve güçlü algortimaların, protokollerin ve anahtarların kullanıldığından emin olunmalıdır. Düzgün bir anahtar yönetimi yapılmalıdır.
* Mükemmel iletme gizliliği (PFS) şifreleri, sunucu tarafından şifre önceliklendirmesi ve güvenli parametreler ile TLS protokolü gibi güvenli protokoller ile tüm veriler transit haldeyken şifrelenmelidir.
* Hassas veriler içeren cevapların önbelleğe alınması engellenmelidir.
* Parolaları [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) veya [PBKDF2](https://wikipedia.org/wiki/PBKDF2) gibi güçlü, adaptif ve tuzlama kullanan özet fonksiyonları ile saklayınız.
* Birbirinden bağımsız olarak yapılandırmanın ve ayarların etkinliği tespit edilmelidir.

## Örnek Saldırı Senaryoları

**Senaryo #1**: Bir uygulama kredi kartı numaralarını otomatik veri tabanı şifrelemesini kullanarak bir veri tabanında tutmaktadır. Ancak, bu veri, veri tabanından alınırken otomatik olarak çözülmektedir ve bu da bir SQL enjeksiyonu açıklığı sayesinde kredi kartı numaralarının açık metin olarak alınmasına izin vermektedir.

**Senaryo #2**: Bir site tüm sayfaları için TLS protokolünü zorunlu tutmamaktadır veya zayıf şifrelemeyi desteklemektedir. Bir saldırgan ağ trafiğini dinlemekte (örn. güvensiz bir kablosuz ağda), bağlantıları HTTPS'den HTTP'e düşürmekte, isteklerde araya girmekte ve kullanıcının oturum çerezini çalmaktadır. Saldırgan daha sonra bu çerezi tekrar yollamakta ve kullanıcının (kimliği doğrulanmış) oturumunu çalmakta, kullanıcının kişisel verisine erişmekte ve bunu değiştirmektedir. Bunların yerine, bir para transferindeki alıcı ismi gibi iletilen veriyi de değiştirebilmektedir.

**Senaryo #3**: Bir parola veri tabanı, kullanıcıların parolalarını saklamak için tuzlanmamış veya basit özet fonksiyonlarını kullanmaktadır. Bir dosya yükleme açıklığı saldırganın parola veri tabanına ulaşmasını sağlamaktadır. Tuzlanmamış tüm özetler, önceden hesaplanmış özetler ile yapılan bir kaba kuvvet saldırısı sonucu çözülebilmektedir. Basit veya hızlı özet fonksiyonları tarafından üretilen özetler, tuzlanmış olsalar bile GPU'lar tarafından kırılabilmektedir.

## Kaynaklar

* [OWASP Proaktif Kontroller: Verinin Korunması](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Uygulama Güvenliği Doğrulama Standardı]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Kopya Kağıdı: Taşıma Katmanı Korumaları](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Kopya Kağıdı: Kullanıcı Gizliliğinin Korunması](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Kopya Kağıdı: Parola](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) ve [Kriptografik Saklama](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Güvenlik Başlıkları Projesi](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Kopya Kağıdı: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Test Rehberi: Zayıf kriptografi testleri](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Dış Kaynaklar

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
