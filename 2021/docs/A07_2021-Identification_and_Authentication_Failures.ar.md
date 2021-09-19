# A07:2021 –  الهوية و فشل عملية التحقق 

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 22            | 14.84%             | 2.55%             | 79.51%         | 45.72%             | 7.40                  | 6.50          | 132,195        | 3,897                  |



## نظرة عامة

هذه الفئة تُعرف سابقًا باسم فشل المصادقة (Broken Authentication) وكانت هي الخطر رقم#2 في الاصدار السابق. وحاليًا تشمل CWEs المتعلقة بفشل عملية التحقق. يتضمن هذا التصنيف كل من (CWE-384,CWE-297,CWE-287).

## الوصف 

يعد تأكيد هوية المستخدم والمصادقة وإدارة الجلسة أمرًا بالغ الأهمية وذلك للحماية من الهجمات المتعلقة بالمصادقة. قد يكون هناك ضعف في المصادقة إذا كان التطبيق:

-   يسمح بالهجمات الآلية مثل هجمات بيانات الاعتماد (credential stuffing)، حيث يكون لدى المهاجم قائمة بأسماء المستخدمين وكلمات مرورهم.

-   يسمح باستخدام هجوم كسر كلمات المرور (brute force) أو الهجمات الآلية الأخرى. 

-   يسمح بكلمات المرور الافتراضية أو الضعيفة أو المعروفة ، مثل "Password1" أو " admin / admin".

-   يستخدم عمليات ضعيفة وغير فعالة لاستعادة كلمات المرور واسترجاع بيانات الاعتماد والتي لا يمكن جعلها آمنة، مثل "الأجوبة المستندة على المعرفة".

-   يستخدم كلمات مرور غير مشفرة، أو مشفرة أو مجزأة بشكل ضعيف (راجع A3:2017-البيانات الحساسة الغير محمية أو المكشوفة).

-   لا يستخدم مصادقة متعددة العوامل أو تكون غير فعالة.

-   يعرض معرفات الجلسة (session IDs) في عنوان URL

-   لا يقوم بإعادة تدوير معرفات الجلسة بعد تسجيل الدخول بنجاح.

-   لا ينهي معرفات الجلسة بشكل صحيح.  لا يتم إبطال جلسات المستخدم أو رموز المصادقة (authentication tokens) وخاصة رموز الدخول الموحد (SSO) بشكل صحيح خلال تسجيل الخروج أو في فترة الخمول.

## كيفية الحماية منها 

-   حيثما أمكن ذلك، قم بتنفيذ المصادقة متعددة العوامل لمنع الهمات الآلية لبيانات الاعتماد(credential stuffing)، وهجوم كسر كلمات المرور (brute force) وهجمات إعادة استخدام بيانات الاعتماد المسروقة.

-   لا ترسل أو تضع بيانات اعتماد افتراضية، خاصة بالنسبة للمستخدمين المشرفين (المسؤولين)

-   نفِّذ عمليات التحقق من كلمات المرور الضعيفة، مثل اختبار كلمات المرور الجديدة أو التي تم تغييرها ومقارنتها.  بقائمة أسوأ 10,000 كلمة مرور.

-   أضبط طول كلمة المرور، وصعوبتها وسياسة الإرشادات في NIST 800-63b في القسم 5.1.1 تذكر كلمات السر المحفوظة أو سياسات كلمة المرور المبنية على الأدلة الحديثة الأخرى

-   تأكد من أن مسارات كلا من التسجيل واستعادة بيانات الاعتماد وواجهة برمجة التطبيقات (API) محمية ضد هجمات فحص الحسابات (account enumeration)  باستخدام نفس رسائل الخطاء لجميع النتائج.

-   الحد من محاولات تسجيل الدخول الفاشلة. سجل جميع حالات الفشل و قم بتنبيه المسؤولين عند اكتشاف هجمات بيانات الاعتماد (credential stuffing) أو هجوم كسر كلمات المرور (brute force) أو أي هجمات أخرى.

-   استخدم مدير جلسة مدمج وآمن من جانب الخادم يقوم بإنشاء معرف جلسة عشوائي جديد مع (entropy) عالية بعد تسجيل الدخول. معرفات الجلسات يجب ألا تكون موجودة في عنوان URL، ويجب تخزينها بشكل آمن، وإبطال مفعولها بعد تسجيل الخروج، والخمول، والانتهاء المطلق. (انتهاء أو نفاذ الوقت)

## أمثلة على سيناريوهات الهجوم

**سيناريو #1:** هجمات بيانات الاعتماد وهو استخدام قوائم معروفة لكلمات المرور، هو هجوم شائع. لنفترض أن أحد التطبيقات لا ينفذ الحماية التلقائية من التهديدات أو هجمات بيانات الاعتماد. في هذه الحالة، يمكن استخدام التطبيق كمعيار لتحديد ما إذا كانت بيانات الاعتماد صالحة

**سيناريو #2:** تحدث معظم هجمات المصادقة بسبب الاستخدام المستمر لكلمات المرور كعامل وحيد. اعتماد أفضل الممارسات والتغير المستمر لكلمات المرور، ان جعل السياسات معقدة يشجع المستخدمين على استخدام كلمات المرور الضعيفة او إعادة استخدامها. تُنصح المؤسسات بإيقاف هذه الممارسات وفقًا لـ NIST 800-63 واستخدام المصادقة متعددة العوامل.

**سيناريو #3:** لا يتم تعيين مدة انتهاء الجلسة (timeouts) للتطبيق بشكل صحيح. يستخدم المستخدم جهاز كمبيوتر عام للوصول إلى أحد التطبيقات. بدلاً من اختيار "تسجيل الخروج"، المستخدم ببساطة يغلق علامة تبويب المتصفح. يستخدم المهاجم نفس المتصفح بعد ساعة، ولا يزال المستخدم قيد تسجيل الدخول (authenticated).



## المصادر

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   OWASP Testing Guide: Identity, Authentication

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Credential Stuffing

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Session Management

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## قائمة الربط مع إطار CWEs

CWE-255 Credentials Management Errors

CWE-259 Use of Hard-coded Password

CWE-287 Improper Authentication

CWE-288 Authentication Bypass Using an Alternate Path or Channel

CWE-290 Authentication Bypass by Spoofing

CWE-294 Authentication Bypass by Capture-replay

CWE-295 Improper Certificate Validation

CWE-297 Improper Validation of Certificate with Host Mismatch

CWE-300 Channel Accessible by Non-Endpoint

CWE-302 Authentication Bypass by Assumed-Immutable Data

CWE-304 Missing Critical Step in Authentication

CWE-306 Missing Authentication for Critical Function

CWE-307 Improper Restriction of Excessive Authentication Attempts

CWE-346 Origin Validation Error

CWE-384 Session Fixation

CWE-521 Weak Password Requirements

CWE-613 Insufficient Session Expiration

CWE-620 Unverified Password Change

CWE-640 Weak Password Recovery Mechanism for Forgotten Password

CWE-798 Use of Hard-coded Credentials

CWE-940 Improper Verification of Source of a Communication Channel

CWE-1216 Lockout Mechanism Errors
