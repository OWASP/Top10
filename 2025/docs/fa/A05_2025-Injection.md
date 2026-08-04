# [A05:2025 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

## پس‌زمینه
Injection در رتبه‌بندی سال ۲۰۲۵ دو پله سقوط کرده و از #3 به #5 رسیده است، و همچنان نسبت به A04:2025-Cryptographic Failures و A06:2025-Insecure Design در جایگاه خود باقی مانده است.  
این دسته یکی از پرآزمایش‌ترین دسته‌هاست، به‌طوری که ۱۰۰٪ برنامه‌ها حداقل برای یک نوع injection بررسی شده‌اند.  
Injection بیشترین تعداد CVE را در بین همه دسته‌ها دارد و شامل ۳۷ CWE است.  
نمونه‌ها شامل Cross-site Scripting (XSS) با فرکانس بالا و تأثیر پایین (بیش از ۳۰k CVE) و SQL Injection با فرکانس پایین و تأثیر بالا (بیش از ۱۴k CVE) هستند.  
تعداد زیاد CVEهای CWE-79 (Improper Neutralization of Input During Web Page Generation – 'Cross-site Scripting') میانگین weighted impact این دسته را کاهش می‌دهد.

## جدول امتیازدهی

| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|-----------------------|-----------------|-----------------|---------------|---------------|----------------------------|----------------------|----------------|
| 37                    | 13.77%          | 3.08%           | 100.00%       | 42.93%        | 7.15                       | 4.32                 | 1,404,249      |

## توضیحات
Injection یک آسیب‌پذیری است که به مهاجم اجازه می‌دهد کد یا دستورات مخرب (مانند SQL یا shell code) را وارد فیلدهای ورودی برنامه کند و سیستم آن‌ها را به‌عنوان بخشی از سیستم اجرا کند. پیامدهای این نوع آسیب‌پذیری می‌تواند شدید باشد.

یک برنامه زمانی آسیب‌پذیر است که:
- داده‌های ورودی کاربر توسط برنامه اعتبارسنجی، فیلتر یا sanitize نشده باشند
- کوئری‌ها یا فراخوانی‌های غیرپارامتری بدون escaping context-aware مستقیماً در interpreter استفاده شوند
- داده‌های unsanitized در پارامترهای ORM برای استخراج رکوردهای حساس استفاده شوند
- داده‌های مخرب مستقیم یا concatenated در query، command یا stored procedure استفاده شوند

### انواع رایج Injection
- SQL, NoSQL, OS command, ORM, LDAP, Expression Language (EL) / OGNL  
- تشخیص آسیب‌پذیری بهترین روش ترکیبی شامل بازبینی کد و تست اتوماتیک (fuzzing) تمام پارامترها، headers، URL، cookies، JSON، SOAP و XML است. ابزارهای SAST، DAST و IAST در CI/CD می‌توانند مفید باشند.  
- Injection مشابهی در LLMها نیز رخ می‌دهد که در [OWASP LLM Top 10](https://genai.owasp.org) به‌ویژه [LLM01:2025 Prompt Injection](https://genai.owasp.org) پوشش داده شده است.

## چگونه جلوگیری کنیم
- از API امن استفاده کنید یا از ORMها بهره ببرید تا داده از دستورات جدا شود.  
- اگر جداسازی ممکن نیست:
  - اعتبارسنجی مثبت سمت سرور انجام دهید  
  - برای کوئری‌های باقی‌مانده، کاراکترهای ویژه را با syntax مخصوص interpreter escape کنید  
  - توجه داشته باشید که ساختار SQL مانند table/column name را نمی‌توان escape کرد  

⚠️ هشدار: این تکنیک‌ها پیچیده هستند و در صورت تغییرات جزئی سیستم خطاپذیر می‌شوند.

## نمونه سناریوهای حمله
**سناریو #1:**
```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
سناریو #2:
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
در هر دو، مهاجم مقدار id را به ' UNION SLEEP(10);-- تغییر می‌دهد:

http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--

این باعث بازگرداندن همه رکوردها می‌شود. حملات خطرناک‌تر می‌توانند داده‌ها را تغییر دهند، حذف کنند یا stored procedure اجرا کنند.

## منابع (References)
- [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/)  
- [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/ASVS/)  
- [OWASP Testing Guide: SQL Injection, Command Injection, and ORM Injection](https://owasp.org/www-project-web-security-testing-guide/)  
- [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_in_Java.html)  
- [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)  
- [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)  
- [PortSwigger: Server-side template injection](https://portswigger.net/web-security/template-injection)  
- [Awesome Fuzzing: a list of fuzzing resources](https://github.com/awesome-fuzzing/awesome-fuzzing)  

## لیست CWEهای مرتبط (List of Mapped CWEs)
- [CWE-20](https://cwe.mitre.org/data/definitions/20.html) Improper Input Validation  
- [CWE-74](https://cwe.mitre.org/data/definitions/74.html) Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')  
- [CWE-76](https://cwe.mitre.org/data/definitions/76.html) Improper Neutralization of Equivalent Special Elements  
- [CWE-77](https://cwe.mitre.org/data/definitions/77.html) Improper Neutralization of Special Elements used in a Command ('Command Injection')  
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html) Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')  
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')  
- [CWE-80](https://cwe.mitre.org/data/definitions/80.html) Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)  
- [CWE-83](https://cwe.mitre.org/data/definitions/83.html) Improper Neutralization of Script in Attributes in a Web Page  
- [CWE-86](https://cwe.mitre.org/data/definitions/86.html) Improper Neutralization of Invalid Characters in Identifiers in Web Pages  
- [CWE-88](https://cwe.mitre.org/data/definitions/88.html) Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')  
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')  
- [CWE-90](https://cwe.mitre.org/data/definitions/90.html) Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')  
- [CWE-91](https://cwe.mitre.org/data/definitions/91.html) XML Injection (aka Blind XPath Injection)  
- [CWE-93](https://cwe.mitre.org/data/definitions/93.html) Improper Neutralization of CRLF Sequences ('CRLF Injection')  
- [CWE-94](https://cwe.mitre.org/data/definitions/94.html) Improper Control of Generation of Code ('Code Injection')  
- [CWE-95](https://cwe.mitre.org/data/definitions/95.html) Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')  
- [CWE-96](https://cwe.mitre.org/data/definitions/96.html) Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')  
- [CWE-97](https://cwe.mitre.org/data/definitions/97.html) Improper Neutralization of Server-Side Includes (SSI) Within a Web Page  
- [CWE-98](https://cwe.mitre.org/data/definitions/98.html) Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')  
- [CWE-99](https://cwe.mitre.org/data/definitions/99.html) Improper Control of Resource Identifiers ('Resource Injection')  
- [CWE-103](https://cwe.mitre.org/data/definitions/103.html) Struts: Incomplete validate() Method Definition  
- [CWE-104](https://cwe.mitre.org/data/definitions/104.html) Struts: Form Bean Does Not Extend Validation Class  
- [CWE-112](https://cwe.mitre.org/data/definitions/112.html) Missing XML Validation  
- [CWE-113](https://cwe.mitre.org/data/definitions/113.html) Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')  
- [CWE-114](https://cwe.mitre.org/data/definitions/114.html) Process Control  
- [CWE-115](https://cwe.mitre.org/data/definitions/115.html) Misinterpretation of Output  
- [CWE-116](https://cwe.mitre.org/data/definitions/116.html) Improper Encoding or Escaping of Output  
- [CWE-129](https://cwe.mitre.org/data/definitions/129.html) Improper Validation of Array Index  
- [CWE-159](https://cwe.mitre.org/data/definitions/159.html) Improper Handling of Invalid Use of Special Elements  
- [CWE-470](https://cwe.mitre.org/data/definitions/470.html) Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')  
- [CWE-493](https://cwe.mitre.org/data/definitions/493.html) Critical Public Variable Without Final Modifier  
- [CWE-500](https://cwe.mitre.org/data/definitions/500.html) Public Static Field Not Marked Final  
- [CWE-564](https://cwe.mitre.org/data/definitions/564.html) SQL Injection: Hibernate  
- [CWE-610](https://cwe.mitre.org/data/definitions/610.html) Externally Controlled Reference to a Resource in Another Sphere  
- [CWE-643](https://cwe.mitre.org/data/definitions/643.html) Improper Neutralization of Data within XPath Expressions ('XPath Injection')  
- [CWE-644](https://cwe.mitre.org/data/definitions/644.html) Improper Neutralization of HTTP Headers for Scripting Syntax  
- [CWE-917](https://cwe.mitre.org/data/definitions/917.html) Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')
