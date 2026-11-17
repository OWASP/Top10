# A05:2025 Enjeksiyon ![simge](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Arka Plan. 

Enjeksiyon, sıralamada iki basamak gerileyerek 3. sıradan 5. sıraya indi; A04:2025-Kriptografik Hatalar ve A06:2025-Güvensiz Tasarım kategorilerine göre konumunu ise korudu. Enjeksiyon en çok test edilen kategorilerden biridir; uygulamaların %100'ü bir tür enjeksiyon açısından test edildi. 37 CWE içeren bu kategori, tüm kategoriler arasında en fazla CVE sayısına sahipti. Enjeksiyon, 30 binden fazla CVE ile Cross-site Scripting'i (yüksek sıklık/düşük etki) ve 14 binden fazla CVE ile SQL Injection'ı (düşük sıklık/yüksek etki) kapsar. CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') için raporlanan çok sayıdaki CVE, bu kategorinin ortalama ağırlıklı etkisini aşağı çeker. 


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
   <td>37
   </td>
   <td>13.77%
   </td>
   <td>3.08%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.15
   </td>
   <td>4.32
   </td>
   <td>1,404,249
   </td>
   <td>62,445
   </td>
  </tr>
</table>



## Açıklama. 

Enjeksiyon güvenlik açığı, güvenilmeyen kullanıcı girdisinin bir yorumlayıcıya (ör. tarayıcı, veritabanı, komut satırı) gönderilmesine izin veren ve yorumlayıcının bu girdinin bazı bölümlerini komut olarak çalıştırmasına neden olan bir uygulama kusurudur. 

Bir uygulama aşağıdaki durumlarda saldırıya açıktır:

* Kullanıcının sağladığı veriler uygulama tarafından doğrulanmıyor, filtrelenmiyor veya temizlenmiyorsa.
* Bağlama duyarlı kaçışlama (context-aware escaping) uygulanmadan dinamik sorgular veya parametrelendirilmemiş çağrılar doğrudan yorumlayıcıda kullanılıyorsa.
* Temizlenmemiş veriler nesne-ilişkisel eşleme (ORM) arama parametrelerinde kullanılıyor ve bu yolla ek, hassas kayıtlar çekilebiliyorsa.
* Potansiyel olarak zararlı veriler doğrudan kullanılıyor veya birleştiriliyorsa. Bu durumda SQL ya da komut, dinamik sorgularda, komutlarda veya saklı yordamlarda hem yapıyı hem de kötü amaçlı veriyi içerir.

En yaygın enjeksiyon türlerinden bazıları SQL, NoSQL, işletim sistemi komutu, Object Relational Mapping (ORM), LDAP ve Expression Language (EL) veya Object Graph Navigation Library (OGNL) enjeksiyonudur. Kavram tüm yorumlayıcılarda aynıdır. Tespitte en iyi sonuç, kaynak kod incelemesinin tüm parametrelerin, başlıkların, URL'lerin, çerezlerin ve JSON, SOAP ve XML veri girdilerinin otomatik testleriyle (fuzzing dahil) birlikte uygulanmasıyla elde edilir. Statik (SAST), dinamik (DAST) ve etkileşimli (IAST) uygulama güvenliği test araçlarının CI/CD pipeline'ına eklenmesi de enjeksiyon kusurlarının üretime dağıtımdan önce tespit edilmesine yardımcı olabilir.

İlişkili bir enjeksiyon güvenlik açığı sınıfı LLM'lerde yaygınlaştı. Bu açıklar [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) içinde, özellikle [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) başlığı altında ayrıca ele alınmaktadır.


## Nasıl Önlenir. 

Enjeksiyonu önlemenin en iyi yolu, verileri komutlardan ve sorgulardan ayrı tutmaktır:

* Tercih edilen seçenek, yorumlayıcı kullanımını tamamen ortadan kaldıran, parametreli bir arayüz sunan veya Object Relational Mapping araçlarına (ORM'ler) geçişi sağlayan güvenli bir API kullanmaktır. 
**Not:** Saklı yordamlar parametreli olsalar bile, PL/SQL veya T-SQL sorguları ve verileri birleştiriyorsa ya da zararlı verileri EXECUTE IMMEDIATE veya exec() ile çalıştırıyorsa yine SQL enjeksiyonuna yol açabilir.

Verileri komutlardan ayırmak mümkün olmadığında, aşağıdaki teknikleri kullanarak tehditleri azaltabilirsiniz. 

* Sunucu tarafında pozitif girdi doğrulaması kullanın. Metin alanları veya mobil uygulamalara yönelik API'ler gibi birçok uygulama özel karakterler gerektirdiğinden bu, tam bir savunma sağlamaz.
* Geriye kalan dinamik sorgularda özel karakterleri, ilgili yorumlayıcıya özgü kaçış sözdizimini kullanarak kaçışlayın (escape). 
**Not:** Tablo adları, sütun adları gibi SQL yapıları kaçışlanamaz; bu nedenle kullanıcı tarafından sağlanan yapı adları tehlikelidir. Bu, raporlama yazılımlarında sık karşılaşılan bir sorundur.

**Uyarı:** Bu teknikler karmaşık dizelerin ayrıştırılmasını ve kaçışlanmasını içerdiğinden hataya açıktır ve altta yatan sistemdeki küçük değişikliklere karşı dayanıklı değildir. 

## Örnek Saldırı Senaryoları.

**Senaryo #1:** Bir uygulama, aşağıdaki savunmasız SQL çağrısını oluştururken güvenilmeyen veriler kullanıyor:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

Saldırgan, tarayıcısında 'id' parametresinin değerini değiştirerek `' OR '1'='1` değerini gönderir. Örneğin:

```
http://example.com/app/accountView?id=' OR '1'='1
```

Bu, sorgunun anlamını değiştirerek accounts tablosundaki tüm kayıtların döndürülmesine yol açar. Daha tehlikeli saldırılar verileri değiştirebilir, silebilir, hatta saklı yordamları çağırabilir.

**Senaryo #2:** Bir uygulamanın framework'lere körü körüne güvenmesi, sorguların yine de savunmasız kalmasına yol açabilir. Örneğin Hibernate Query Language (HQL):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Saldırgan şu değeri gönderir: `' OR custID IS NOT NULL OR custID='`. Bu değer filtreyi atlatır ve tüm hesapları döndürür. HQL, ham SQL'e kıyasla daha az tehlikeli fonksiyona sahip olsa da kullanıcı girdisi sorgulara birleştirilerek eklendiğinde yine yetkisiz veri erişimine olanak tanır.

**Senaryo #3:** Bir uygulama, kullanıcı girdisini doğrudan bir işletim sistemi komutuna aktarıyor:

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

Saldırgan, sunucuda istediği komutları çalıştırmak için `example.com; cat /etc/passwd` değerini gönderir.

## Kaynaklar.

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection) ve [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: fuzzing kaynakları listesi](https://github.com/secfigo/Awesome-Fuzzing) 



## Eşlenen CWE'lerin Listesi

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

* [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)

* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

* [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

* [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)

* [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

* [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

* [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

* [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

* [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

* [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

* [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

* [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

* [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)

* [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)

* [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)

* [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

* [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)

* [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)

* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

* [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)

* [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)

* [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

* [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)

* [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)

* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

* [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

* [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
