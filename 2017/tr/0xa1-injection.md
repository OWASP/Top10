# A1:2017 Enjeksiyon

| Tehdit Etkenleri/Saldırı Vektörleri | Güvenlik Zafiyeti           | Etkiler               |
| -- | -- | -- |
| Erişim Düzeyi : İstismar Edilebilirlik 3 | Yaygınlık 2 : Tespit Edilebilirlik 3 | Teknik 3 : İş |
| Neredeyse tüm veri kaynakları (çevresel değişkenler, parametreler, iç ve dış web servisleri ve tüm kullanıcı türleri) bir enjeksiyon vektörü olabilmektedir. [Enjeksiyon açıklıkları](https://www.owasp.org/index.php/Injection_Flaws) saldırgan zararlı bir veriyi yorumlayıcıya gönderdiğinde ortaya çıkmaktadır. | Enjeksiyon açıklıkları eski kodlarda başta olmak üzere son derece yaygındır. Enjeksiyon açıklıkları genellikle SQL, LDAP, XPath veya NoSQL sorgularında, OS komutlarında, XML ayrıştırıcılarında, SMTP başlıklarında, programlama dillerinde ve ORM sorgularında görülmektedir. Enjeksiyon açıklıkları kaynak kod incelenirken kolaylıkla tespit edilebilmektedir. Tarama ve fuzzer araçları saldırganların enjeksiyon açıklıklarını bulmalarına yardımcı olabilmektedir.| Enjeksiyon saldırıları verilerin kaybedilmesi, bozulması veya yetkisiz kimselere sızdırılması, inkar edilememezliğin yitirilmesi veya servis dışı bırakma saldırıları ile sonuçlanabilmektedir. Enjeksiyon saldırıları bazı durumlarda sunucunun tamamen ele geçirilebilmesine yol açmaktadır. İş etkisi uygulamanın ihtiyaçlarına ve sahip olduğu veriye göre değişmektedir.|

## Uygulamam Açıklığı İçeriyor Mu?

Aşağıdaki durumlarda, bir uygulamanın ilgili açıklığı içerdiği söylenebilir:

* Kullanıcı tarafından sağlanan girdiler uygulama tarafından doğrulanmadığında, filtrelenmediğinde veya sterilize edilmediğinde.
* Kullanıldığı bağlama göre sterilize edilmeden yapılan ve parametrik olmayan veya dinamik olan sorgular doğrudan yorumlayıcı tarafından kullanıldığında.  
* Zararlı veri hassas kayıtları getirmek için ORM arama parametreleri arasında kullanıldığında.
* Zararlı veri SQL OR komutu ile dinamik sorgularda, komutlarda veya saklı yordamlarda normal yapının zararlı veri ile birleştirilebileceği bir şekilde doğrudan kullanıldığında.
* En yaygın enjeksiyon saldırıları SQL, NoSQL, OS komut, ORM, LDAP, EL veya OGNL enjeksiyonlarıdır. Saldırının mantığı tüm yorumlayıcılar için aynıdır. Kaynak kod analizi uygulamanın enjeksiyon açıklıkları içerip içermediğini anlamak için en iyi yöntemdir. Kaynak kod analizi sonrasında veya sırasında, eksiksiz bir şekilde tüm parametreler, başlıklar, URL'ler, çerezler, JSON verileri, SOAP mesajları ve XML veri girdileri otomatize olarak test edilmelidir. Kurumlar statik kaynak kod analizi ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) ve dinamik uygulama güvenliği testi araçlarını ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) CI/CD süreçleri içerisinde yeni çıkan enjeksiyon açıklıklarını kurulumdan önce tespit etmek için kullanabilirler.

## Nasıl Önlenir

Enjeksiyon saldırılarını önlemek verinin komutlardan ve sorgulardan uzak tutulmasını gerektirmektedir. 

* Tercih edilen yöntem, yorumlayıcı kullanımından tamamen kaçınan veya parametrik bir arayüz sunan veya ORM araçları kullanan güvenli bir API kullanımıdır. **Not**: Parametrik olsa bile, eğer PL/SQL veya T-SQL veri ile sorguları birleştiriyorsa veya zararlı veriyi EXECUTE IMMEDIATE veya exec() ile çalıştırıyorsa, saklı yordamlar hala SQL enjeksiyonu açıklığına neden olabilmektedir.
* Sunucu taraflı "beyaz liste" girdi denetimi yapılmalıdır. Metin alanları veya mobil uygulama API'leri gibi pek çok uygulama özel karakterler gerektirdiği için bu kesin bir çözüm değildir.
* Herhangi bir şekilde yukarıdaki çözümlerin uygulanamadığı diğer dinamik sorgular için, yorumlayıcıya özel sterilize yöntemleri belirlenerek özel karakterler sterilize edilmelidir. **Not**: Tablo adı, sütun adı gibi SQL yapıları sterilize edilemez, bu yüzden kullanıcı tarafından sağlanan yapısal isimler tehlikeli olmaktadır. Bu durum rapor üreten yazılımlar için yaygın bir problemdir. 
* Sorgular içerisinde LIMIT ve benzeri kontroller kullanılarak, SQL enjeksiyonu durumunda büyük miktarlarda verinin sızdırılması engellenmelidir.

## Örnek Saldırı Senaryosu

**Senaryo #1**: Bir uygulama, aşağıdaki zafiyet içeren SQL çağrısını oluştururken güvenilmeyen bir veri kullanmaktadır.

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Senaryo #2**: Benzer şekilde, bir uygulamanın kullanılan çerçeve yazılımlara olan kayıtsız güveni de bu uygulamaları saldırılara açık bırakmaktadır. (örn. Hibernate Sorgu Dili (HQL))

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

Her iki durumda da, saldırgan id parametresinin değerini ' UNION SELECT SLEEP(10);-- olarak tarayıcısı üzerinden değiştirmektedir. Örneğin:

`http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

Bu değer, her iki sorgunun da anlamını değiştirmekte ve tablodaki tüm kayıtları döndürmektedir. Daha tehlikeli saldırılar veriyi değiştirebilir veya silebilir, hatta saklı yordamları çalıştırabilir.

## Kaynaklar

### OWASP

* [OWASP Proaktif Kontroller: Parametrik Sorgular](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Girdi Doğrulama ve Kodlama](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Test Rehberi: SQL Enjeksiyonu](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Komut Enjeksiyonu](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM enjeksiyonu](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Kopya Kağıdı: Enjeksiyon Önlemleri](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Kopya Kağıdı: SQL Enjeksiyonu Önlemleri](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Kopya Kağıdı: Java için Enjeksiyon Önlemleri](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Kopya Kağıdı: Parametrik Sorgular](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Web Uygulamaları için Otomatize Tehditler – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Dış Kaynaklar

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
