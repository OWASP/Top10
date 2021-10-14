# A01:2021 –  تخطي صلاحيات الوصول  


## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 34            | 55.97%             | 3.81%             | 94.55%         | 47.72%             | 6.92                  | 5.93          | 318,487        | 19,013                 |



## نظرة عامة

صعد هذا المعيار من المركز الخامس في الإصدار السابق إلى الأول في هذا الإصدار بعد اختبار ثغرات "تخطي صلاحيات التحكم بالوصول" على 94% من التطبيقات وقد لوحظ أنها تعاني من نقاط الضعف الشائعة "CWEs” تشمل : CWE-200 و CWE-201 و CWE-352

## الوصف 

تفرض صلاحيات التحكم بالوصول سياسات وقوانين مثل ان المستخدم لا يمكنه التصرف خارج نطاق الأذونات الممنوحة له. عادة ما تؤدي هذه الاخطاء الى كشف معلومات غير مصرح بها او التعديل عليها، او تخريب جميع البيانات أو حتى تنفيذ إجراءات خارج صلاحيات المستخدم المسموحة. تتضمن نقاط الضعف الشائعة لصلاحيات التحكم بالوصول:

-   تجاوز إجراءات **التحقق من التحكم في الوصول** من خلال تعديل محدد فيURL، او تعديل الكائنات “objects” المرتبطة بالبرنامج داخل الذاكرة أو تعديل صفحة الـ HTML، أو ببساطة استخدام أداة هجوم مخصصة لمهاجمة API 

-   السماح بالتبديل بين مفتاح رئيسي “primary key” وسجلات مستخدم آخر “users record”، مما قد يسمح باستعراض أو التعديل على حسابات أخرى   

-   تصعيد الصلاحيات: التصرف كمستخدم من دون تسجيل الدخول او التصرف كمدير عند تسجيل الدخول بصلاحيات كمستخدم.

-   التلاعب في البيانات الوصفية "meta data” كإعادة إدخال أو التلاعب برمز التوثيق "JSON Web Token (JWT)،" أو التلاعب في ملفات الارتباط أو الحقول المخفية لغرض تصعيد الصلاحيات أو إساءة استخدام الـ JWT 

-   التهيئة الغير صحيحة لـ CORS تسمح بالدخول الغير مصرح به لواجهة برمجة التطبيقات API.

-   استعراض صفحات "تستلزم المصادقة" عبر مستخدمين "غير مصادق عليهم" أو الوصول الى صفحات ذات امتيازات عليا باستخدام صلاحيات “حساب مستخدم “، أو الوصول الى واجهة برمجة التطبيقات "API” بوجود قصور في "التحكم في صلاحيات الوصول" مما يؤدي الى تنفيذ طلباتPOST، PUT، DELETE.

## كيفية الحماية منها 

يكون "التحكم بصلاحيات الوصول" فعالا فقط عندما عند تطبيقه على **الشفرة المصدرية** من جهة الخوادم الموثوقة- trusted server-side code، أو الخوادم التي لا تملك واجهة برمجة تطبيقات والتي يطلق عليها (server-less API)، حيث لا يستطيع المهاجم تعديل "صلاحيات التحكم بالوصول" أو التلاعب في البيانات الوصفية.

-   باستثناء طلبات الوصول "للموارد المتاحة للعامة" يتم حظر جميع الطلبات بشكل افتراضي.

-   وضع الأليات التي تتحكم بالوصول لمرة واحدة في البرنامج/التطبيق مع إعادة استخدامها -هي نفسها- عند الحاجة، وأيضا تقليل استخدام CORS. 

-   نموذج التحكم بالوصول يجب أن يفرض مُلكية السجل " record ownership" بدلًا من الموافقة على أن المستخدم يستطيع إنشاء، قراءة، تحديث، أو حذف أي سجل.

-    متطلّبات حدود تطبيقات الأعمال الفريدة من نوعها "Unique application business limit" يجب أن يتم فرضها خلال استخدام نماذج المجال (domain models).

-   تعطيل استعراض مجلدات خادم الويب والتأكد بأن ملف البيانات الوصفية "Meta Data” وملفات النسخ الاحتياطي لا يتم الوصول اليها من خلال مجلد المسار الرئيسي "Root".

-   توثيق سجلات فشل التحكم في صلاحيات الوصول وتنبيه المسؤولين عند وقوع هذه الأخطاء.

-   تقييم حد الوصول إلى واجهة برمجة التطبيقات API ووضع حد لمعدّل الطلبات لتقليل الضرر الناجم عن أدوات الهجوم الآلي.

-   يجب التخلص من رموز JWT على الخادم بعد تسجيل الخروج.

يجب على فرق المطوّرين وموظفين قسم ضمان الجودة "QA" أن تتضمّن  وحدة  فعالة للتحكم في الوصول وإجراء اختبارات التكامل .

## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** يستخدم التطبيق بيانات لم يتم التحقق منها في استدعاء SQL التي بدورها تصل الى معلومات الحساب:

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

ببساطة يقوم المهاجم بتعديل browser's 'acct' parameter لأرسال أي رقم حساب يريده. وإذا لم يتم التحقق منه بشكل صحيح، يستطيع المهاجم الوصول لأي حساب مستخدم.

https://example.com/app/accountInfo?acct=notmyacct

**سيناريو #2:** : ببساطة يجبر المهاجم المتصفحات على زيارة العناوين الـ URLsالمستهدفة. والتي لا يستطيع الوصول اليها الا بصلاحيات المسؤول.

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

يعتبر خللا اذا كان يمكن للمستخدم غير المصرح له الوصول الى اي من الصفحتين. يعتبر خللا اذا كان يمكن لغير المسؤول الوصول لصفحة المسؤول.

## المصادر

-   [OWASP Proactive Controls: Enforce Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## قائمة الربط مع إطار CWEs




[CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
