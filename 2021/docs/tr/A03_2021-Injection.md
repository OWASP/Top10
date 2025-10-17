# A03:2021 – Injection    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Faktörler

| CWEs Eşleştirildi | Maks Görülme Oranı | Ort. Görülme Oranı | Ort. Ağırlıklı Exploit | Ort. Ağırlıklı Impact | Maks Coverage | Ort. Coverage | Toplam Olay | Toplam CVE |
| :---------------: | :----------------: | :----------------: | :--------------------: | :-------------------: | :-----------: | :-----------: | :---------: | :--------: |
|         33        |       19.09%       |        3.37%       |          7.25          |          7.15         |     94.04%    |     47.90%    |   274,228   |   32,078   |

## Genel Bakış

Injection üçüncü sıraya geriledi. Uygulamaların %94’ü bir tür injection için test edildi; maksimum görülme oranı %19, ortalama görülme oranı %3 ve 274k olay kaydedildi. Dikkate değer Common Weakness Enumeration (CWE) örnekleri arasında *CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection* ve *CWE-73: External Control of File Name or Path* bulunur.

## Açıklama

Bir uygulama şu durumlarda saldırıya açık hale gelir:

* Kullanıcıdan gelen veri uygulama tarafından validate, filter veya sanitize edilmiyorsa.

* Dynamic query’ler veya context-aware escaping olmadan non-parameterized çağrılar doğrudan interpreter’da kullanılıyorsa.

* Hostile data, ek hassas kayıtları çıkarmak için object-relational mapping (ORM) search parametrelerinde kullanılıyorsa.

* Hostile data doğrudan kullanılıyor veya concat ediliyorsa. SQL ya da komut, dynamic query, command veya stored procedure’lerde hem yapı hem de malicious data’yı içeriyorsa.

En yaygın injection türleri arasında SQL, NoSQL, OS command, ORM, LDAP ve Expression Language (EL) ya da Object Graph Navigation Library (OGNL) injection yer alır. Kavram tüm interpreter’larda aynıdır. Source code review, uygulamaların injection’a açık olup olmadığını tespit etmenin en iyi yöntemidir. Tüm parametrelerin, header’ların, URL, cookie’lerin, JSON, SOAP ve XML data input’larının otomatik test edilmesi şiddetle tavsiye edilir. Kuruluşlar, production’a dağıtımdan önce eklenen injection kusurlarını belirlemek için CI/CD pipeline’ına static (SAST), dynamic (DAST) ve interactive (IAST) application security testing tool’larını dahil edebilir.

## Nasıl Önlenir

Injection’ı önlemek, veriyi komut ve query’lerden ayrı tutmayı gerektirir:

* Tercih edilen seçenek, interpreter kullanımını tamamen önleyen, parameterized arayüz sağlayan veya ORM’lere migrate eden güvenli bir API kullanmaktır.<br/>
  **Not:** Parameterized olsalar bile stored procedure’ler, eğer PL/SQL veya T-SQL query ve data’yı concat ediyorsa ya da hostile data’yı `EXECUTE IMMEDIATE` veya `exec()` ile çalıştırıyorsa, yine SQL injection’a yol açabilir.

* Pozitif (allow-list tabanlı) server-side input validation kullanın. Bu, tek başına tam bir savunma değildir; birçok uygulama text area gibi özel karakterler veya mobil uygulamalar için API’ler gerektirir.

* Kalan dynamic query’ler için, ilgili interpreter’ın özel escape syntax’ını kullanarak special character’ları escape edin.<br/>
  **Not:** Tablo adları, kolon adları gibi SQL yapıları escape edilemez; bu nedenle user-supplied yapı adları tehlikelidir. Bu, raporlama yazılımlarında yaygın bir sorundur.

## Örnek Saldırı Senaryoları

**Senaryo #1:** Bir uygulama, güvensiz veriyi aşağıdaki zafiyetli SQL çağrısının oluşturulmasında kullanıyor:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Senaryo #2:** Benzer şekilde, bir uygulamanın framework’lere körü körüne güvenmesi, sorguların yine zafiyetli olmasına yol açabilir (ör. Hibernate Query Language - HQL):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Her iki durumda da saldırgan, tarayıcısında ‘id’ parametre değerini şu şekilde değiştirir: `' UNION SELECT SLEEP(10);--`. Örneğin:

```
http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Bu, her iki sorgunun da anlamını değiştirerek accounts tablosundaki tüm kayıtların döndürülmesine neden olur. Daha tehlikeli saldırılar veriyi değiştirebilir veya silebilir, hatta stored procedure’leri bile tetikleyebilir.


## Referanslar

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Eşleştirilen CWE Listesi

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
