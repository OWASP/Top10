# A2:2017 Yetersiz Kimlik Doğrulama

| Tehdit Etkenleri/Sadlırı vektörleri | Güvenlik zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 3 | Yaygınlık 2 : Tespit Edilebilirlik 2 | Teknik 3 : İş |
| Saldırganlar yüz milyonlarca geçerli kullanıcı adı ve parola kombinasyonlarına, varsayılan yönetici hesap listelerine, otomatize kaba kuvvet ve sözlük saldırısı araçlarına sahiptir. Oturum yönetimi saldırıları, özellikle süresi dolmayan oturum anahtarları, iyi anlaşılmaktadır. | Yetersiz kimlik doğrulama açıklıkları, pek çok kimlik ve erişim kontrollerinin tasarım ve uygulamasından dolayı son derece yaygındır. Oturum yönetimi kimlik doğrulamanın ve erişim kontrollerinin temel taşıdır ve durum tutan tüm uygulamalarda bulunmaktadır. Saldırganlar yetersiz kimlik doğrulama açıklıklarını kendileri tespit edebilmekte ve parola listeleri içeren otomatize araçları ve sözlük saldırılarını kullanarak bunları istismar etmektedirler. | Saldırganlar sistemi ele geçirmek için sadece birkaç hesaba veya bir tane yönetici hesabına erişmek zorundadır. Uygulamanın alanına bağlı olarak, bu kara para aklama, sosyal güvenlik dolandırıcılığı, kimlik hırsızlığına izin verebilir veya son derece hassas olan ve yasal olarak korunan bilgileri ifşa edebilir. |

## Uygulamam Açıklığı İçeriyor Mu?

Kullanıcının kimliğinin onaylanması, kimlik doğrulama ve oturum yönetimi, kimlik doğrulama ile ilgili saldırılara karşı korunmak için son derece büyük önem taşımaktadır.

Uygulama aşağıdaki durumlarda kimlik doğrulama açıklıkları içeriyor olabilir:

*  Saldırganın geçerli kullanıcı adı ve parola listesine sahip olduğu [sözlük saldırıları](https://www.owasp.org/index.php/Credential_stuffing) gibi otomatize saldırılara izin veriyorsa.
* Kaba kuvvet veya diğer otomatize saldırılara izin veriyorsa.
* "Password1" veya "admin/admin" gibi varsayılan, zayıf veya herkesçe bilinen parolalara izin veriyorsa.
* Güvenli yapılması mümkün olmayan "güvenlik soruları" gibi zayıf veya etkisiz hesap kurtarma ve unutulan parola süreçleri kullanıyorsa. 
* Açık metin, şifrelenmiş veya zayıf bir şekilde özeti alınmış parolalar kullanıyorsa (Bakınız **A3:2017-Hassas Bilgi İfşası**).
* Eksik veya etkisiz çok katmanlı kimlik doğrulamaya sahipse.
* Oturum ID değerlerini URL üzerinden taşıyorsa (örn. URL'i yeniden yazma).
* Başarılı giriş sonrası oturum ID değerlerini değiştirmiyorsa.
* Oturum ID değerlerini doğru bir şekilde geçersiz kılmıyorsa. Çıkış veya hareketsizlik durumunda kullanıcı oturumları veya kimlik doğrulama anahtarları (özellikle tek oturum açma(SSO) anahtarları) düzgün bir şekilde geçersiz kılınmıyorsa.

## Nasıl Önlenir

* Otomatize saldırıları, sözlük saldırılarını, kaba kuvvet saldırılarını ve çalınan giriş bilgilerinin tekrar kullanılması saldırılarını önlemek için mümkün olduğunca çok katmanlı kimlik doğrulama uygulanmalıdır. 
* Özellikle yönetici kullanıcıları için herhangi bir varsayılan giriş bilgisi kullanılmamalı veya bu şekilde kullanıma sunulmamalıdır.
* [En kötü 10000 parola](https://github.com/danielmiessler/SecLists/tree/master/Passwords) gibi bir listeye karşı yeni veya değiştirilmiş parolaları kıyaslamak gibi zayıf parola kontrolleri uygulanmalıdır.
* Parola uzunluğu, karmaşıklığı ve değiştirme politikaları, [NIST 800-63 B's guidelines in section 5.1.1 for Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) veya diğer modern, kanıta dayalı parola politikalarına göre belirlenmelidir.
* Tüm sonuçlar için aynı mesaj kullanılarak, kayıt yapma, hesap kurtarma ve API yolları geçerli hesapları toplama saldırılarına karşı güçlendirilmelidir.
* Başarısız giriş denemelerini sınırlandırılmalı veya artarak geciktirilmelidir. Tüm başarısız denemeler loglanmalı ve sözlük saldırıları, kaba kuvvet saldırıları veya diğer saldırılar tespit edildiğinde yöneticiler uyarılmalıdır.
* Giriş yapıldıktan sonra yeni bir rastgele oturum ID değeri üreten ve büyük bir entropiye sahip olan sunucu taraflı, güvenli ve gömülü bir oturum yöneticisi kullanılmalıdır. Oturum ID değerleri URL üzerinde olmamalı, güvenli bir şekilde saklanmalı ve çıkış yapıldıktan, belirli bir süre hareketsiz kaldıktan ve geçerlilik süresi dolduktan sonra geçersiz kılınmalıdır. 

## Örnek Saldırı Senaryoları

**Senaryo #1**: [Sözlük saldırıları](https://www.owasp.org/index.php/Credential_stuffing), [bilinen parola listelerinin](https://github.com/danielmiessler/SecLists) kullanımı yaygın saldırılardır. Eğer bir uygulama otomatize tehdit veya sözlük saldırısı koruması içermiyorsa, uygulama geçerli giriş bilgilerinin toplanması için kullanılabilir.

**Senaryo #2**: Pek çok kimlik doğrulama saldırısı sadece parolaların sürekli kullanımından kaynaklanmaktadır. En iyi uygulama örnekleri düşünüldüğünde, parola değiştirme ve karmaşıklık gereksinimleri, kullanıcıların zayıf parolaları kullanmaları ve bunları tekrar tekrar kullanmaları konusunda teşvik edici olarak görülmektedir. Organizasyonların NIST 800-63 uyarınca bu uygulamaları durdurması ve çok katmanlı kimlik doğrulama kullanması tavsiye edilmektedir.

**Senaryo #3**: Uygulama oturum zaman aşımları düzgün bir şekilde belirlenmemiştir. Bir kullanıcı uygulamaya erişmek için herkes tarafından erişilebilir bir bilgisayar kullanmaktadır. Kullanıcı "çıkış yap" seçeneğini kullanmak yerine, tarayıcı sekmesini kapatmış ve oradan uzaklaşmıştır. Bu durumda, saldırgan bir saat sonra aynı tarayıcıyı kullandığında kullanıcının hala kimlik doğrulaması yapılmış olacaktır.

## Kaynaklar

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
 and [Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
* [OWASP Automated Threats Handbook](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Dış Kaynaklar

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - kimlik doğrulama hakkında tam, modern ve kanıta dayalı tavsiyeler için. 
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
