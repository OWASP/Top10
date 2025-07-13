# A07:2021 –  الهوية و فشل عملية التحقق 

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 22            | 14.84%             | 2.55%             | 79.51%         | 45.72%             | 7.40                  | 6.50          | 132,195        | 3,897                  |



## نظرة عامة

هذ التصنيف يُعرف سابقًا باسم ضعف التحقّق من الهوية (Broken Authentication) وكانت هي الخطر رقم #2 في الإصدار السابق. وحاليًا تشمل على العديد من CWEs المتعلقة بفشل عملية التحقّق. يتضمّن هذا التصنيف كل من (CWE-384,CWE-297,CWE-287).

## الوصف 

يُعد تأكيد هوية المستخدم والمصادقة وإدارة الجلسة أمرًا بالغ الأهمية وذلك للحماية من الهجمات المتعلقة بالمصادقة. قد يكون هناك ضعف في المصادقة إذا كان التطبيق:

-   يسمح بالهجمات الآلية مثل هجمات بيانات الاعتماد (Credential Stuffing)، حيث يكون لدى المهاجم قائمة بأسماء المستخدمين وكلمات المرور.

-   يسمح باستغلال هجوم كسر كلمات المرور (Brute Force) أو الهجمات الآلية الأخرى.  

-   يسمح بهجمات كلمات المرور الافتراضية أو الضعيفة أو المعروفة ، مثل "Password1" أو " Admin / Admin".

-   يستخدم عوامل ضعيفة وغير فعّالة لاستعادة كلمات المرور واسترجاع بيانات الاعتماد والتي يجعلها آمنة، مثل "الأجوبة المستندِة على المعرفة".

-   يستخدم كلمات مرور غير مشفّرة، أو مشفّرة بشكل مُجزّأ أو بشكل ضعيف (راجع A3:2017- البيانات الحساسة الغير محميّة أو المكشوفة).

-   عدم تفعيل التحقّق الثنائي أو تكون غير فعّالة.

-   يعرض معرّفات الجلسة (Session IDs) في عنوان URL

-   لا يقوم بإعادة إنشاء معرّفات الجلسة بعد تسجيل الدخول بنجاح.

-   لا ينهي معرّفات الجلسة بشكل صحيح. لا يتم إنهاء جلسات المستخدم أو رموز المصادقة (Authentication Tokens) وخاصة رموز الدخول الموحّد (SSO) بشكل صحيح خلال تسجيل الخروج أو في فترة الخمول.


## كيفية الحماية منها 

-   حيثما أمكن ذلك، قم بتفعيل التحقّق الثنائي لمنع الهجمات الآلية لبيانات الاعتماد(Credential Stuffing)، وهجوم كسر كلمات المرور (Brute Force) وهجمات إعادة استخدام بيانات الاعتماد المسروقة.

-   لا ترسل أو تضع بيانات اعتماد افتراضية، خاصة بالنسبة لمدراء النظام (المسؤولين)

-   نفِّذ عمليات التحقّق من كلمات المرور الضعيفة، مثل اختبار كلمات المرور الجديدة أو التي تم تغييرها ومقارنتها بقائمة أسوأ 10,000 كلمة مرور.

-   اضبط طول كلمة المرور وصعوبتها وقم باتباع السياسات والإرشادات الواردة في NIST 800-63b في القسم 5.1.1 "تذكّر كلمات السر المحفوظة أو سياسات كلمة المرور".

-   تأكد من أن مسارات كُلًا من التسجيل واستعادة بيانات الاعتماد وواجهة برمجة التطبيقات (API) محميّة ضد هجمات فحص الحسابات (Account Enumeration) ، قم بإظهار نفس رسائل الخطأ لجميع عمليات تسجيل الدخول.

-   الحد من محاولات تسجيل الدخول الفاشلة. وقم بتسجيل جميع حالات فشل عملية تسجيل الدخول وقم بتنبيه المسؤولين عند اكتشاف محاولة هجمات كسر بيانات الاعتماد (Credential Stuffing) أو هجوم كسر كلمات المرور (Brute Force) أو أي هجمات أخرى.

-   استخدم مدير جلسة مُدمج وآمن من جانب الخادم، يقوم بإنشاء معرّف جلسة عشوائية جديدة مع (Entropy) عالية بعد تسجيل الدخول، معرّفات الجلسات يجب ألا تكون موجودة في عنوان URL، ويجب تخزينها بشكل آمن و إنهاء صلاحيتها بعد تسجيل الخروج، أو الخمول، والانتهاء المُطلق (انتهاء أو نفاذ الوقت).


## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** هجمات بيانات الاعتماد وهي عبارة عن استخدام قوائم معروفة سابقًا لمجموعة من كلمات المرور وتُعتبر من أكثر الهجمات شيوعًا، و لنفرض أن أحد التطبيقات لم يُطبّق الحماية التلقائية والكافية للحد من التهديدات أو هجمات بيانات الاعتماد،  في هذه الحالة، يمكن استخدام رسائل الخطأ الصادرة من التطبيق كمعيار لتحديد ما إذا كانت بيانات الاعتماد صالحة.

**سيناريو #2:** تحدث معظم هجمات المصادقة بسبب الاستخدام المستمر لكلمات المرور كعامل وحيد لتسجيل الدخول حتى وإن تم اعتماد أفضل الممارسات والتغيير المستمر لكلمات المرور حيث جعل سياسة كلمة المرور معقّدة، يُشجّع المستخدمين على إعادة استخدام كلمة المرور. لذلك ننصح المؤسسات بإيقاف هذه المُمارسات وفقًا لـ NIST 800-63 واستخدام التحقّق الثنائي.

**سيناريو #3:** لا يتم تعيين مدة انتهاء الجلسة (Timeouts) للتطبيق بشكل صحيح، يقوم المستخدم باستخدام أحد الأجهزة الموجودة في الأماكن العامة للوصول إلى أحد التطبيقات بدلًا من اختيار "تسجيل الخروج"، يقوم المستخدم ببساطة بإغلاق علامة تبويب المتصفح، فيقوم المهاجم باستخدام  نفس المتصفح بعد ساعات قليلة ليجد أنه لا يزال المستخدم قيد تسجيل الدخول (Authenticated).



## المصادر

-   [OWASP Proactive Controls: Implement Digital Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2 authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session Management](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Authentication](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

-   [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

-   [OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets


## قائمة الربط مع إطار CWEs



[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)
