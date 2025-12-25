# A05:2021 –  الإعدادات الأمنية الخاطئة 

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 20            | 19.84%             | 4.51%             | 89.58%         | 44.84%             | 8.12                  | 6.56          | 208,387        | 789                    |



## نظرة عامة

بعد أن كان هذا التهديد   في المرتبة السادسة في الإصدار السابق لعام 2017 الآن نجده في المرتبة الخامسة، حيث أنه تم إجراء اختبار على %90 من البرامج والتطبيقات للتأكد إن كانت تحتوي على أيّة أخطاء في طريقة الإعدادات والتكوين الصحيحة، فليس من المُستغرب انتقال هذا التهديد من المرتبة السادسة إلى الخامسة. كذلك تم ضم "XML External Entities XXE" لهذا النوع من الإعدادات والتكوين الخاطئة. تضمن الـ CWEs التالية CWE-16 (Configuration), CWE-611 (Improper Restriction of XML External Entity).

## الوصف 

من المحتمل ان يكون التطبيق ضعيف امنياً إذا احتوى على النقاط التالية:

-   عدم مراجعة التكوين والضبط الآمن لإعدادات التطبيق أو في أي جزء من أجزاء التطبيق أو تكوين أذونات خاطئة في الخدمات السحابيّة.

-   تثبيت وإتاحة خدمات ومِيزات غير ضرورية (منافذ غير ضرورية، الخدمات، الصفحات، الحسابات، والصلاحيات).

-   تفعيل الحسابات الافتراضية أو عدم تغييرها أو عدم تغيير كلمات المرور الخاصة بها.

-   كشف رسائل معالجة الأخطاء (Error Handling) عن معلومات قابلة للتتبّع (Stack Traces) أو عرض رسائل الخطأ التي تحتوي على معلومات تفصيلية يمكن أن تُستغل من قِبل المستخدم.

-   تكون الميزات الأمنية الأحدث مُعطّلة أو لم يتم تكوينها بشكل آمن في الأنظمة التي تمت ترقيتها. 

-   عدم تعيين إعدادات الأمان في خوادم التطبيقات وإطار التطبيقات على سبيل المثال (Struts, Spring, ASP.NET) والمكتبات وقواعد البيانات وما إلى ذلك إلى قيم آمنة.

-   لا يرسل أو يستخدم الخادم عناوين "Headers" عند نقل البيانات الحساسة للمتصفح أو عند تقديمها من قِبل المتصفح.

-  لم يعد البرنامج مدعومًا من قبل مزوّدي الخدمات أو ضعيف أمنيًا لاحتوائه على ثغرات أمنية (انظر إلى link:https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/[A06:2021 الثغرات والأنظمة الغير قابلة للتحديث]).

من دون امتلاك إجراءات مفهومة وقابلة للتكّرار للإعدادات الأمنية لتكوين البرنامج بما يتوافق مع الضوابط الأمنية، تُصبح الأنظمة في خطر عالي.

## كيفية الحماية منها 

يجب تطبيق آلية آمنة لتكوين البرامج أو الأجهزة، تشمل على:

-   تكرار عملية مراجعة التكوين الآمن، والذي سيؤدي إلى تسريع وتسهيل   مهمة إنشاء بيئة جديدة مكوّنة بشكل آمن. كما يجب أن يتم تكوين بيئات التطوير وضمان جودة وبيئة الإنتاج بشكل يتطابق مع استخدام كلمات مرور مختلفة في كل بيئة. أيضًا يجب أن تكون هذه العملية آلية للتقليل من الجهد المتطلّب عند إعداد بيئة جديدة وآمنة.

-   الاكتفاء بالحد الأدنى الأساسي من النظام أو المنصّة بدون تفعيل مِيزات، أو مكونات، أو وثائق، أو عيّنات غير ضرورية، مع حذف وإبطال الميزات وإطار الغير مستخدمة أو عدم تثبيتها.

-  مراجعة وتحديث الإعدادات بما يتناسب مع كافة ملاحظات الأمان والتحديثات والإصلاحات كجزء من عملية إدارة حِزم الإصلاحات والترقيات. (انظر إلى link:https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/[A06:2021 الثغرات والأنظمة الغير قابلة للتحديثات]). بالإضافة إلى مراجعة أذونات التخزين السحابيّة على سبيل المثال (S3 Bucket Permissions).


-   تتيح بنية التطبيق المقسّمة فصلًا فعّالًا وآمنًا بين المكونات، مع التجزئة في مجموعات أمان السحابة (ACLs).

-   إرسال توجيهات الأمان إلى المستخدمين على سبيل المثال Security Headers.

-   أتمتة عملية التحقق من التحديثات الآمنة للتحقّق من فعاليّة التكوينات والإعدادات في جميع البيئات.

-   تشغيل أدوات الفحص للتحقّق من فعاليّة التكوينات والإعدادات في جميع البيئات للكشف عن الإعدادات الخاطئة.

## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** عندما يحتوي احد الخوادم على تطبيق من التطبيقات غير محدث وما يزال يُستخدم    في بيئة الإنتاج "Production Server" هذه العيّنات من التطبيقات قد تحتوي على ثغرات أمنية يمكن أن يستخدمها المهاجم في اختراق الخادم ، وبافتراض أن أحد هذه البرامج هي وحدة تحكّم لإدارة الخادم وتحتوي على الاعدادات الافتراضية والرقم السري الافتراضي، في هذه الحالة فإن المهاجم سوف يُسجّل الدخول باستخدام الرقم السري الافتراضي ويتحكّم بالخادم.

**سيناريو #2:** عندما تكون قائمة الدليل "Directory Listing" غير معطّلة في الخادم الخاص بك، قد يكتشف المهاجم أن بإمكانه سرد قائمة الملفات المخزنة على الخادم وبعد ذلك بإمكانه العثور وتثبيت جميع فئات جافا (Compiled Java Classes) ومن ثم يقوم بفكّها وتطبيق الهندسة العكسية لعرض الشّفرة المصدرية، سوف يحاول المهاجم بعد ذلك إيجاد خطأ أمني للتحكّم في الوصول إلى الخادم.

**سيناريو #3:** عندما تقوم إعدادات خادم التطبيق بإرجاع رسائل خاطئة تفصيليّة، على سبيل المثال Stack Traces إلى المستخدم، ومن المُحتمل أن يؤدي هذا إلى الكشف عن معلومات حساسة أو ثغرات أمنية أخرى أو معلومات مثل إصدارات المكونات المعروفة بأنها قابلة للاستغلال.  

**سيناريو #4:** أن يكون مقدّم الخدمة السحابيّة لديه أذونات مشاركة افتراضية مفتوحة على الإنترنت من قِبل مستخدمي CSP الآخرين، يسمح هذا بالوصول إلى البيانات الحساسة المخزّنة في سحابة التخزين.

## المصادر

-   [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   Application Security Verification Standard V19 Configuration

-   [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## قائمة الربط مع إطار CWEs

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
