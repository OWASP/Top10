# A03:2021 – الحقن

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 33            | 19.09%             | 3.37%             | 94.04%         | 47.90%             | 7.25                  | 7.15          | 274,228        | 32,078                 |



## نظرة عامة


هجمات الحقن تحتل المركز الثالث، حيث أن 94٪ من التطبيقات التي تم فحصها مهدّدة بصنف واحد أو أكثر من هجمات الحقن المرتبطة مع CWE-79، CWE-89، CWE-73


## الوصف 

يكون  البرنامج معرض للإصابة بهذه الهجمات عندما: 

-  إذا كانت المدخلات المزوّدة من المستخدم غير مُتحقّق منها أو غير موثوقة، أو لم يتم تصفيتها من قِبل البرنامج. 

-  تمرير طلبات الاستعلامات الديناميكية أو استدعاء بيانات غير محدّدة المعاملات (Non-Parameterized) بشكل مباشر إلى مترجم الأوامر بدون استخدام آلية واعية تضمن تهرب المدخلات من التفاعل مع مترجم الأوامر "Context-aware escaping".

-   المدخلات الضَّارة التي يتم استخدامها والبحث عنها في (Object-relational mapping ORM) والتي قد تقوم بتسريب بيانات إضافية غير مطلوبة أو بيانات حساسة.


-  تمرير المدخلات الضَّارة بشكل مباشر أو بشكل متسلسل غير مباشر، قواعد البيانات العلائقية "SQL" أو الأوامر التي تحتوي على هياكل وبيانات مشبوهة في طلبات الاستعلام الديناميكية "dynamic queries” أو الأوامر أو الإجراءات المخزّنة

من أشهر أنواع الحقن   : الـ SQL، NoSQL، سطر الأوامر في أنظمة التشغيل، خرائط ربط الكائنات بقواعد البيانات العلائقية "Object-relational mapping”، LDAP، ولغات البرمجة التعبيرية "EL"، مكتبات التنقّل خلال مخططات الكائنات"OGNL". مبدأ "الحقن" مُتطابق في جميع لغات البرمجة    وفي جميع المفسّرات، مراجعة مصدر الشّفرة المصدرية هي أفضل طريقة لاكتشاف ما إذا كان التطبيق البرمجي عُرضة للإصابة بثغرة الحقن. يوصَّى بشدّة بالفحص التلقائي لكل المعاملات تروسيات صفحات الويب، الروابط التشعبيّة "URL"، وملفات تعريف الارتباط "Cookies"، و JSONو الـ SOAP ومدخلات معطيات الـ XML. المنظمات بإمكانها إضافة أدوات الفحص ثابتة المصدر"SAST" وأدوات الفحص الديناميكية للتطبيقات البرمجية "DAST"واستخدامها في مسارات CI/CD، لتحديد العيوب الموجودة من قبل عملية طرح المنتج للاستخدام. 


## كيفية الحماية منها 

-   لتفادي هجمات الحقن يجب الفصل والتفّريق بين كل من البيانات والأوامر والاستعلامات. 

-   ُفضّل استخدام **واجهات برمجة تطبيقات (API) ** آمنة، وذلك لتفادي استخدام ** مفسّر الأوامر** كُلّيًا، و توفير واجهة إدخال ذات معاملات " Parametrized Interface " أو الانتقال إلى استخدام كائنات الـ "Relational Mapping Tools (ORMs)".

-   ملاحظة: حتى في حال استخدام المعاملات" Parameterized” الإجراءات المخزّنة قد لا تزال قاعدة البيانات مُعرّضة لهجمات الحقن في حال كانت الـ PL/SQL أو T-SQL قابلة لتنفيذ الاستعلامات المتسلسلة "الغير مباشرة " أو تنفيذ تعليمات برمجية ضارّة من خلال EXECUTE IMMEDIATE أو exec (). 

-   استخدام عمليات التحقّق من المدخلات الإيجابية و المرتبطة ب "قوائم السماح/القوائم البيضاء" من طرف الخادم. لكن هذه لا تعتبر حماية متكاملة حيث أن هناك العديد من البرامج تتطّلب رموز خاصة "Special Characters" مثل حقل النص (TextArea) أو واجهات تطبيقات البرامج (APIs) لتطبيقات الهواتف. 

-   في حال وجود استعلامات ديناميكية متبقية، قم بتصفية الاستعلام من الرموز الخاصة من خلال استخدام صيغة برمجية "Syntax " لتصفية المدخلات المحددة إلى مفسّر الأوامر.   

-   ملاحظة: هيكلة SQL مثل أسماء الجداول أو الأعمدة وغيرها، لا يمكن إجراء عوامل التصفية عليها، لذلك يجب الحذر من هياكل البيانات القادمة من المستخدم حيث أنها تعتبر خطرة. وهذا خطأ شائع عند كتابة-تقارير البرمجيات.  

-   ضع حدودا و أو ضوابط تحكّم أخرى عند استخدام الاستعلامات داخل SQL، لتجنّب كشف السجلات الحساسة في حال وجود هجمات حقن الـ SQL


## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** برنامج يستخدم بيانات غير موثقة في بناء الاستعلام في قاعدة بيانات الSQL  والتي قد يعرضها للحقن: 

String query = "SELECT \* FROM accounts WHERE custID='" +
request.getParameter("id") + "'";

**سيناريو #2:** الثقة العمياء للبرنامج في إطار العمل (Framework)  وقد تؤدي تلك الاستعلامات إلى ثغرات الحقن مثل Hibernate Query Language (HQL):  

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" +
> request.getParameter("id") + "'");

في كلتا الحالتين السابقتين، المُخترق قام بتعديل قيمة متغيّر الـ id في المتصفح لإرسال ‘ UNION SELECT SLEEP(10);-- . مثلاً:

http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--

وهذا ينتج تغيير في معنى الاستعلام للحصول على جميع السجلات من جدول الحسابات. وقد يستغلّها المُخترق بشكل آخر لتعديل أو حذف أو حتى استدعاء العمليات المخزّنة. 


## المصادر

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

## قائمة الربط مع إطار CWEs



 [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

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

