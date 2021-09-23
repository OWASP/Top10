# A03:2021 – الحقن

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 33            | 19.09%             | 3.37%             | 94.04%         | 47.90%             | 7.25                  | 7.15          | 274,228        | 32,078                 |



## نظرة عامة


هجمات الحقن تحتل المركز الثالث، حيث ان ٩٤٪ من التطبيقات التي تم فحصها تحتوي على صنف او أكثر من هجمات الحقن ومرتبطه مع CWE-79، CWE-89، CWE-73


## الوصف 

يكون البرنامج معرض للإصابة بهذه الهجمات عندما: 

-   البيانات المزودة من المستخدم، غير مُوثقة، او لم يتم تصفيتها، او فلترتها من قِبل البرنامج. 

-  طلبات الاستعلامات الديناميكية او البيانات (non-parameterized)، بدون استخدام  (Context-aware escaping) والتي تكون مستخدمة بشكل مباشر في مترجم الأوامر.

-   المدخلات الضارة التي يتم استخدامها والبحث عنها في (Object-relational mapping ORM) والتي قد تقوم بتسريب بيانات اضافية غير مطلوبة او بيانات حساسة


-   استخدام المدخلات الضارة بشكل مباشر او بشكل مجدول، والتي يتم استخدام بعض الاوامر في لغة SQL والتي قد تعتبر ضارة عند تشغيلها بشكل آلي.

بعض أشهر انواع الحقن مثل، ال SQL و NoSQL و أوامر التي تعمل على انظمة التشغيل، و (Object-relational mapping ORM) و LDAP، ولغة التعبير (Expression Language  (EL او حقن المكتبات Object Graph Navigation (OGNL). المفهوم مرتبط بجميع تلك اللغات والمفسرات لها، مراجعة مصدر الشفرة المصدرية هي افضل وسيلة لتحقق ما إذا كان البرنامج عُرضة للحقن، أتمتة اختبار المداخل، والعناوين، وفحص الروابط (URL)، و ملفات الإرتباط (Cookies)، و JASO و الSOAP ومدخلات معطيات الXML، مهم جداً. المنظمات بإمكانها إضافة أدوات ثوابت المصدر (static source (SAST او الاختبارات الديناميكية للبرامج (Dynamic application testing (DAST واستخدامها في مسارات CI/CD ، لتحديد العيوب الموجودة قبل عملية استخدام المنتج. 


## كيفية الحماية منها 

-   لتفادي هجمات الحقن يتطلب فصل البيانات عن الأوامر والاستعلامات. 

-   يفضل استخدام واجهة التطبيق البرمجية (API) آمنة، وذلك لتفادي استخدام مفسر الأوامر بشكل كلي، او الترقية واستخدام (Object Relational Mapping Tools (ORMs))

-   ملاحظة: حتى في حال استخدام المَعْلمات (Parametrized)، العمليات المخزنة لا تزال مُعرضة لهجمات حقن كانت  الSQL في حال الPL/SQL او T-SQL عندما يقوم بربط البيانات بالاستعلامات، او تنفيذ تعليمات برمجية ضارة من خلال EXECUTE IMMEDIATE او exec(). 

-   استخدام المدخلات الموافق عليها والمدرجة في “القوائم البيضاء”  المُوثقة من جانب الخادم. لكن هذه لا تعتبر حماية متكاملة حيث ان عديد من البرامج تتطلب حروف خاصة، مثل حقل النص (TextArea) او واجهات تطبيق البرامج (APIs) لتطبيقات الهواتف. 

-   في حال وجود استعلامات ديناميكية متبقية، استخدم حالة التصفية من الحروف الخاصة من خلال استخدام الأمر المحدد لتصفيته في مفسر الأوامر.  


-   ملاحظة: هيكلة SQL مثل اسماء الجداول او الأعمدة وغيرها، لايمكن اجراء عوامل التصفيه عليها، لذلك يجب الحذر من الهيكلة-المزودة من المستخدم حيث تعتبر خطرة. وهذا خطأ شائع عند كتابة-تقارير البرمجيات. 


-   استخدم الحد او ضوابط اخرى عند استخدام الاستعلامات داخل SQL، لتجنب كشف للسجلات الحساسة في حال وجود هجمات حقن الSQL


## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** برنامج يستخدم بيانات غير موثقة في بناء الاستعلام في قاعدة بيانات الSQL  والتي قد يعرضها للحقن: 

String query = "SELECT \* FROM accounts WHERE custID='" +
request.getParameter("id") + "'";

**سيناريو #2:** الثقة العمياء للبرنامج في اطر العمل (Framework) والتي قد تؤدي تلك الاستعلامات الى ثغرات الحقن مثل Hibernate Query Language (HQL): 

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" +
> request.getParameter("id") + "'");

في كلا الحالتين السابقتين، المُخترق قام بتعديل قيمة متغير الid في المتصفح لإرسال ‘ or ‘1’=’1. مثلاً:

http://example.com/app/accountView?id=' or '1'='1

وهذا يُنتج تغيير في معنى الاستعلام للحصول على جميع السجلات من جدول الحسابات. وقد يستغلها المخترق بشكل اخطر لتعديل و حذف او حتى استدعاء العمليات المخزنة. 


## المصادر

-   [OWASP Proactive Controls: Secure Database
    Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and
    Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL
    Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in
    Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query
    Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications –
    OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template
    injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## قائمة الربط مع إطار CWEs

CWE-20 Improper Input Validation

CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')

CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)

CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')

CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')

CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')

CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)

CWE-83 Improper Neutralization of Script in Attributes in a Web Page

CWE-87 Improper Neutralization of Alternate XSS Syntax

CWE-88 Improper Neutralization of Argument Delimiters in a Command
('Argument Injection')

CWE-89 Improper Neutralization of Special Elements used in an SQL
Command ('SQL Injection')

CWE-90 Improper Neutralization of Special Elements used in an LDAP Query
('LDAP Injection')

CWE-91 XML Injection (aka Blind XPath Injection)

CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')

CWE-94 Improper Control of Generation of Code ('Code Injection')

CWE-95 Improper Neutralization of Directives in Dynamically Evaluated
Code ('Eval Injection')

CWE-96 Improper Neutralization of Directives in Statically Saved Code
('Static Code Injection')

CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a
Web Page

CWE-98 Improper Control of Filename for Include/Require Statement in PHP
Program ('PHP Remote File Inclusion')

CWE-99 Improper Control of Resource Identifiers ('Resource Injection')

CWE-100 Deprecated: Was catch-all for input validation issues

CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP
Response Splitting')

CWE-116 Improper Encoding or Escaping of Output

CWE-138 Improper Neutralization of Special Elements

CWE-184 Incomplete List of Disallowed Inputs

CWE-470 Use of Externally-Controlled Input to Select Classes or Code
('Unsafe Reflection')

CWE-471 Modification of Assumed-Immutable Data (MAID)

CWE-564 SQL Injection: Hibernate

CWE-610 Externally Controlled Reference to a Resource in Another Sphere

CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath
Injection')

CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax

CWE-652 Improper Neutralization of Data within XQuery Expressions
('XQuery Injection')

CWE-917 Improper Neutralization of Special Elements used in an
Expression Language Statement ('Expression Language Injection')
