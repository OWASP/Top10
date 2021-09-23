# A05:2021 –  الإعدادات الأمنية الخاطئة 

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 20            | 19.84%             | 4.51%             | 89.58%         | 44.84%             | 8.12                  | 6.56          | 208,387        | 789                    |



## نظرة عامة

بعد أن كان الخطر السادس في الإصدار السابق لعام 2017 الأن نراه في المرتبة الخامسة، حيث أنه تم اجراء اختبار %90 من البرامج والتطبيقات للتأكد إن كانت تحتوي على أية أخطاء في طريقة الإعدادات والتكوين الصحيحة، فليس من المستغرب انتقال هذا الخطر من المرتبة السادسة إلى الخامسة. كذلك تم ضم "XML External Entities XXE" لهذا النوع من الإعدادات والتكوين الخاطئة. تضمن الـ CWEs التالية CWE-16 (Configuration), CWE-611 (Improper Restriction of XML External Entity).

## الوصف 

من المحتمل ان يكون التطبيق ضعيف امنياً إذا احتوى على النقاط التالية:

-   عند عدم مراجعة عملية التكوين والضبط الأمن لإعدادات التطبيق او في أي جزء من أجزاء التطبيق أو تكوين أذونات خاطئة في الخدمات السحابية.

-   تثبيت وإتاحة خدمات وميزات غير الضرورية (منافذ غير ضرورية، والخدمات، والصفحات، والحسابات، والصلاحيات).

-   تفعيل أو عدم تغيير الحسابات الافتراضية وكلمات المرور الخاصة بها.

-   كشف رسائل معالجة الأخطاء (error handling) عن تتبعات (stack traces) أو عرض بعض رسائل الخطأ التي تحتوي على معلومات تفصيلية يمكن أن تُستغل من قبل المستخدم.

-   في الأنظمة التي تمت ترقيتها، تكون الميزات الأمنية الأحدث معطلة أو لم يتم تكوينها بشكل آمن. 

-   لم يتم تعيين إعدادات الأمان في خوادم التطبيقات وأطر التطبيقات على سبيل المثال (Struts, Spring, ASP.NET) والمكتبات وقواعد البيانات وما إلى ذلك الى قيم آمنة.

-   الخادم لا يرسل أو يستخدم عناوين "headers" عند نقل البيانات الحساسة للمتصفح أو عند تقديمها من قبل المتصفح.

-   البرنامج لم يعد مدعوماً من قبل مزودي الخدمات  أو ضعيف أمنياً لاحتوائه على الثغرات الأمنية (انظر إلى - A06:2021 الثغرات و الانظمة الغير قابلة للتحديثات).

من دون امتلاك آلية مخططة وقابلة للتكرار للإعدادات الأمنية لتكوين البرنامج بما يتوافق مع الضوابط الأمنية، تكون الأنظمة في خطر عالي.

## كيفية الحماية منها 

يجب تطبيق آلية آمنة لتكوين البرامج أو الأجهزة، متضمنة:

-   تكرار عملية مراجعة التكوين الأمن والتي سوف تؤدي الى تسريع وتسهيل من مهمة إنشاء بيئة جديدة مكونة بشكل آمن. كما يجب ان يتم تكوين بيئات التطوير وضمان الجودة وبيئة الإنتاج بشكل مطابق، مع استخدام كلمات مرور مختلفة في كل بيئة. ايضاً يجب أن تكون هذه العملية آلية للتقليل من الجهد المتطلب عند إعداد بيئة جديدة وآمنة.

-   الحد الأدنى من النظام الأساسي بدون تفعيل ميزات، أو مكونات، أو وثائق، أو عينات غير ضرورية، مع حذف وإبطال الميزات والأطر غير المستخدمة أو عدم تثبيتها.

-   مراجعة وتحديث الاعدادات بما يواكب ويتناسب مع كافة ملاحظات الأمان والتحديثات والإصلاحات كجزء من عملية إدارة حزم الإصلاحات والتحديثات. (انظر الى- A06:2021 الثغرات و الانظمة الغير قابلة للتحديثات). بالإضافة إلى مراجعة أذونات التخزين السحابي على سبيل المثال (S3 bucket permissions).

-   تتيح بنية التطبيق المقسمة فصلًا فعالًا وآمنًا بين المكونات، مع التجزئة في مجموعات أمان السحابة (ACLs).

-   إرسال توجيهات الأمان إلى المستخدمين على سبيل المثال Security Headers.

-   أتمتة عملية التحقق من التحديثات الأمن للتحقق من فعالية التكوينات والإعدادات في جميع البيئات.

-   تشغيل أدوات الفحص للتحقق من فعالية التكوينات والإعدادات في جميع البيئات للكشف عن الإعدادات الخاطئة.

## أمثلة على سيناريوهات الهجوم

**Scenario #1:** عند احتواء خادم التطبيق على عينة تطبيق لم يتم حذفه من خادم الإنتاج. هذه العينات من التطبيق قد تحتوي على أخطاء أمنية يمكن أن يستخدمها المهاجم في اختراق الخادم، وبافتراض أن أحد هذه البرامج هي وحدة تحكم لإدارة الخادم ولم تُغير في هذه الحالة، المهاجم سوف يسجل الدخول باستخدام الرقم السري الافتراضي ويتحكم بالخادم.

**Scenario #2:** عندما تكون قائمة الدليل "Directory Listing" غير معطلة في الخادم الخاص بك، قد يكتشف المهاجم أن بإمكانه سرد الأدلة ببساطة للعثور على أي ملف. وبعد ذلك بإمكانه العثور وتثبيت جميع فئات جافا (compiled Java classes) ومن ثم يقوم بفكها وتطبيق الهندسة العكسية لعرض الشفرة المصدرية. وبعد ذلك يحاول المهاجم إيجاد خطأ أمنى للتحكم في الوصول إلى الخادم.

**Scenario #3:** عندما تقوم إعدادات خادم التطبيق بإرجاع رسائل خطأ تفصيلية، على سبيل المثال stack traces إلى المستخدم. ومن المحتمل أن يؤدي هذا إلى الكشف عن معلومات حساسة أو ثغرات أمنية أخرى أو معلومات مثل إصدارات المكونات المعروفة بإنها قابلة للاستغلال. 

**Scenario #4:** أن يكون مقدم الخدمة السحابية لديه أذونات مشاركة افتراضية مفتوحة على الإنترنت من قبل مستخدمي CSP الآخرين. يسمح هذا بالوصول إلى البيانات الحساسة المخزنة في سحابة التخزين.

## المصادر

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   OWASP Testing Guide: Testing for Error Codes

-   Application Security Verification Standard V19 Configuration

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## قائمة الربط مع إطار CWEs

CWE-2 Configuration

CWE-11 ASP.NET Misconfiguration: Creating Debug Binary

CWE-13 ASP.NET Misconfiguration: Password in Configuration File

CWE-15 External Control of System or Configuration Setting

CWE-16 Configuration

CWE-260 Password in Configuration File

CWE-315 Cleartext Storage of Sensitive Information in a Cookie

CWE-520 .NET Misconfiguration: Use of Impersonation

CWE-526 Exposure of Sensitive Information Through Environmental
Variables

CWE-537 Java Runtime Error Message Containing Sensitive Information

CWE-541 Inclusion of Sensitive Information in an Include File

CWE-547 Use of Hard-coded, Security-relevant Constants

CWE-611 Improper Restriction of XML External Entity Reference

CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

CWE-756 Missing Custom Error Page

CWE-776 Improper Restriction of Recursive Entity References in DTDs
('XML Entity Expansion')

CWE-942 Overly Permissive Cross-domain Whitelist

CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration

CWE-1174 ASP.NET Misconfiguration: Improper Model Validation
