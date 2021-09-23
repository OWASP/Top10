# A01:2021 –  تخطي صلاحيات الوصول 

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 34            | 55.97%             | 3.81%             | 94.55%         | 47.72%             | 6.92                  | 5.93          | 318,487        | 19,013                 |



## نظرة عامة

انتقالا من المركز الخامس الى الأول ، تم اختبار بعض انواع تخطي صلاحيات التحكم بالوصول لـ 94% من التطبيقات ان CWEs المرتبطة به هي. CWEs وهي: CWE-200، CWE-201 ، CWE-352 

## الوصف 

تفرض صلاحيات التحكم بالوصول سياسات و قوانين مثل ان المستخدم  لا يمكنه التصرف خارج نطاق الأذونات الممنوحة له. عادة ما تؤدي هذه الاخطاء الى كشف المعلومات الغير مصرح به ، او التعديل، او تخريب جميع البيانات أو حتى تنفيذ أعمال خارج حدود صلاحيات المستخدم المسموحة له.تتضمن نقاط الضعف الشائعة لصلاحيات التحكم بالوصول:

-   تجاوز عمليات التحقق من التحكم في الوصول من خلال تعديل محدد فيURL ، او في الحالة الداخلية للبرنامج،أو صفحة الـ HTML  ،أو ببساطة استخدام أداة هجوم مخصصة لمهاجمة API. 

-   السماح بتغيير المفتاح الرئيسي إلى سجل مسخدم آخر، السماح بعرض والتي تؤدي الى تعديل بعض الحسابات الأخرى.

-   تصعيد الصلاحيات التصرف كمستخدم من دون تسجيل الدخول او التصرف كمدير عند تسجيل الدخول كمستخدم.

-   معالجة مجموعة البيانات الوصفية، كإعادة التشغيل او التلاعب برمز التحكم بصلاحيات الدخول JSON Web Token (JWT)، أو معالجة ملفات الإرتباط او الحقول المخفية لغرض تصعيد الصلاحيات أو إساءة استخدام الـ JWT .

-   التهيئة الغير صحيحة لـ CORS تسمح بالدخول الغير مصرح به لواجهة برمجة التطبيقات API. 

-   اجبار المتصفحات على إتمام عملية المصادقة للمستخدمين او بعض الصفحات التي تتطلب ان تكون مستخدم قبل الوصول لها، وضبط صلاحيات الوصول الى واجهة برمجة التطبيقات API وحتى صلاحيات الوصول لطلبات على الموقع من (POST, PUT ، DELETE.) 

## كيفية الحماية منها 

يكون التحكم بالوصول فعالا فقط في -الشفرة المصدرية الموثوق بها من جهة الخادم- trusted server-side code او واجهة برمجة التطبيقات  API التي تسمى (server-less API)، حيث لا يستطيع المهاجم تعديل صلاحيات التحكم بالوصول أو البيانات الوصفية.

-   في وجود أي طلبات على الموارد غير العامة يتم رفضها بشكل تلقائي.

-   تنفيذ آليات التحكم بصلاحيات الوصول لمرة واحدة و اعادة استخدامها من خلال التطبيق، مع تقليل استخدام CORS  

-   نموذج التحكم بالوصول يجب أن يفرض ملكية السجلات بدلا من الموافقة على ان المستخدم يستطيع انشاء، قراءة، تحديث، او حذف أي سجل.

-   يجب أن يتم فرض حد لمتطلبات عمل التطبيقات المميزة من خلال استخدام نماذج المجال (domain models).

-   تعطيل عرض مجلدات خادم الويب و التأكد بأن ملف مجموعة البيانات الوصفية و ملفات النسخ الاحتياطي لا يتم عرضها مع مجلد الموقع الرئيسي.

-   تسجيل وتنبيه المسؤولين عند وقوع أخطاء في سجل صلاحيات التحكم بالوصول.

-   حد معدل الوصول لواجهة برمجة التطبيقات  API وحد معدل الطلبات لتقليل الضرر الناجم عن أدوات الهجوم الآلي.

-   يجب انهاء  رموز JWT على الخادم بعد تسجيل الخروج.

يجب على المطورين و موظفي الجودة تضمين اختبارات وظيفية لوحدة التحكم في الوصول والتكامل. 

## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** يستخدم التطبيق بيانات لم يتم التحقق منها في استدعاء  SQL التي بدورها تصل الى معلومات الحساب: 

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

ببساطة يقوم المهاجم بتعديل browser's 'acct' parameter لارسال أي رقم حساب يريده. واذا لم يتم التحقق منه بشكل صحيح، يستطيع المهاجم الوصول لأي حساب مستخدم.

https://example.com/app/accountInfo?acct=notmyacct

**سيناريو #2:** : ببساطة يجبر المهاجم المتصفحات على زيارة العناوين الـURLs المستهدفة. والتي تتطلب صلاحيات المسؤوول للدخول على صفحة.

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

يعتبر خللا اذا كان يمكن للمستخدم غير المصرح له الوصول الى اي من الصفحتين. يعتبر خللا اذا كان يمكن لغير المسؤول الوصول لصفحة المسؤول.

## المصادر

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control]()

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## قائمة الربط مع إطار CWEs

CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')

CWE-23 Relative Path Traversal

CWE-35 Path Traversal: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

CWE-201 Exposure of Sensitive Information Through Sent Data

CWE-219 Storage of File with Sensitive Data Under Web Root

CWE-264 Permissions, Privileges, and Access Controls (should no longer
be used)

CWE-275 Permission Issues

CWE-276 Incorrect Default Permissions

CWE-284 Improper Access Control

CWE-285 Improper Authorization

CWE-352 Cross-Site Request Forgery (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized
Actor

CWE-377 Insecure Temporary File

CWE-402 Transmission of Private Resources into a New Sphere ('Resource
Leak')

CWE-425 Direct Request ('Forced Browsing')

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

CWE-497 Exposure of Sensitive System Information to an Unauthorized
Control Sphere

CWE-538 Insertion of Sensitive Information into Externally-Accessible
File or Directory

CWE-540 Inclusion of Sensitive Information in Source Code

CWE-548 Exposure of Information Through Directory Listing

CWE-552 Files or Directories Accessible to External Parties

CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key

CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

CWE-639 Authorization Bypass Through User-Controlled Key

CWE-651 Exposure of WSDL File Containing Sensitive Information

CWE-668 Exposure of Resource to Wrong Sphere

CWE-706 Use of Incorrectly-Resolved Name or Reference

CWE-862 Missing Authorization

CWE-863 Incorrect Authorization

CWE-913 Improper Control of Dynamically-Managed Code Resources

CWE-922 Insecure Storage of Sensitive Information

CWE-1275 Sensitive Cookie with Improper SameSite Attribute
