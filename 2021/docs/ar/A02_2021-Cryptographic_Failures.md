# A02:2021 –  فشل آلية التشفير 

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 29            | 46.44%             | 4.49%             | 79.33%         | 34.85%             | 7.29                  | 6.81          | 233,788        | 3,075                  |



## نظرة عامة

يأتي فشل آلية التشفير في المرتبة رقم #2 والتي كانت تعرف “بالبيانات الحساسة الغير محمية أو المكشوفة" والتي قد تكون أسبابها متعدّدة أكثر من كونها ناتجة عن سبب جذري واحد، ويأتي التركيز هنا على حالات الفشل في التشفير والتي غالبًا ما تؤدي إلى كشف غير مصرّح به للبيانات الحساسة. تم ملاحظة أن نقاط الضعف الشائعة CWEs تشمل: CWE-259: استخدام كلمة المرور المضمنة مسبقًا ""  ، CWE-327: خوارزمية تشفير مُعطّلة أو محفوفة بالمخاطر، و CWE-331 التشتت الغير فعّال أو بعبارة أخرى -عشوائية بشكل غير كافي-” Insufficient Entropy”.

## الوصف 

أولًا، تحديد احتياجات حماية **البيانات أثناء النقل** (Data in transit) وأثناء التخزين (Data at rest). على سبيل المثال، تتطلّب كل من (كلمات المرور وأرقام بطاقات الائتمان والسجلات الصحيّة والمعلومات الشخصية وأسرار العمل) تتطلّب حماية إضافية ولا سيّما إذا كانت تلك البيانات تندرج تحت قوانين الخصوصية مثل اللائحة العامة لحماية البيانات في الاتحاد الأوروبي (GDPR)، أو التنظيمات، و على سبيل المثال تنظيمات حماية البيانات المالية مثل معيار PCI لأمان البيانات أو معيار (PCI DSS) لجميع البيانات المالية.

-   هل يتم نقل أي بيانات من غير تشفير؟ يعتمد هذا على البروتوكولات مثل HTTP وSMTP وFTP. كذلك لابد من التحقق من مسار تدفّق البيانات و حركتها داخل الشبكة الداخلية، على سبيل المثال، حركة البيانات بين **موازنات التحميل**"load balancers" أو خوادم الويب أو الأنظمة الخلفية "Back-end systems" .

-   هل يتم استخدام أي خوارزميات تشفير قديمة أو ضعيفة إما بشكل افتراضي أو في التعليمات البرمجية القديمة؟

-   هل مفاتيح التشفير الافتراضية قيد الاستخدام؟ هل يتم توليد مفاتيح تشفير ضعيفة  أو يتم إعادة استخدام مفاتيح من شفرة مصدرية افتراضية  أو من شفرة مصدرية  قديمة؟  هل تتم إدارة المفاتيح و إعادة  تدويرها بشكل جيد؟ (rotation missing)؟

-   هل التشفير غير مفروض؟ على سبيل المثال، هل يتم إرسال واستخدام عناوين "Headers" الصحيحة والمطلوبة فقط عند إرسال البيانات الحساسة أو عند استقبالها من قِبل المتصفّح؟

-   هل وكيل المستخدم (مثل المتصفّح أو برمجية استخدام البريد الإلكتروني) لا يتحقّق ما إذا كانت شهادة الخادم المستلمة صالحة وفعّالة؟

هناك الكثير من المشاكل التي يجب تجنّبها، انظر ASVS Crypto (V7) , Data Protection (V9), and SSL/TLS (V10)

## كيفية الحماية منها 

يجب عمل ما يلي على الأقل لحماية البيانات الحساسة:

-   تصنيف البيانات التي تتم معالجتها أو تخزينها أو إرسالها بواسطة تطبيق ما. تحديد البيانات الحساسة وفقًا لقوانين الخصوصية أو المتطلبات التنظيمية أو احتياجات العمل.

-   تطبيق الضوابط بناءً على التصنيف.

-   لا تقم بتخزين بيانات حساسة غير مطلوبة، قم بتجاهلها والتخلّص منها في أقرب وقت ممكن لأن البيانات التي لا تملكها لا يمكن سرقتها.

-   تأكّد من تشفير جميع البيانات الحساسة المخزنة.

-   ضمان استخدام خوارزميات وبروتوكولات ومفاتيح تشفير محدّثة وذات معايير صارمة كذلك إدارة المفاتيح بشكل جيد ومناسب.

-   قم بتشفير جميع البيانات أثناء النقل باستخدام بروتوكولات آمنة مثل TLS مع شفرة الـ Perfect Forward Secrecy (PFS)، وتحديد أولويات التشفير والمعطيات الآمنة بواسطة الخادم و كذلك فرض التشفير باستخدام التوجيهات مثل HTTP Strict Transport Security (HSTS).

-   تعطيل خاصية التخزين المؤقت في الصفحات "caching" للردود التي تحتوي على بيانات حساسة.

-   قم بتخزين كلمات المرور باستخدام دوال اختزال متكيّفة وقوية  **مع بيانات عشوائية إضافية** " salted  " ، مثل Argon2 أو scrypt أو bcrypt أو PBKDF2.

-   تحقق بشكل مستقل من فعالية التكوين والإعدادات.

## أمثلة على سيناريوهات الهجوم

**سيناريو #1**: تطبيق يقوم بتشفير أرقام البطاقات الائتمانية باستخدام التشفير الآلي المتوفر مع قاعدة البيانات. لكن هذا يعني أنه بإمكان قاعدة البيانات فكّ التشفير آليًا عند طلب البيانات منها، مما قد يُعرّض أرقام البطاقات الائتمانية للسّرقة عند استغلال ثغرة حقن "SQL”، لذلك، يجب تشفير أرقام البطاقات الائتمانية باستخدام مفتاح عام "Public Key" والسماح فقط للبنية التحتية للتطبيق بفكّ التشفير باستخدام المفتاح الخاص "Private Key".

**سيناريو #2**:الموقع الذي لا يستخدم بروتوكول TLS لكافة الصفحات أو أن الموقع يدعم التشفير الضعيف، حيث يراقب المهاجم حركة مرور البيانات في الشبكة (على سبيل المثال، في الشبكات اللاسلكية الغير آمنة) ينخفض مستوى الاتصال من HTTPS إلى HTTP، ويعترض الطلبات و يستطيع السطو على **بيانات جلسات الاتصالات** "Session Cookie" للمستخدم، ثم يعيد المهاجم إرسال واستخدام بيانات جلسة اتصال المستخدم ( التي سبق و تم المصادقة عليها) فيتمكن من الوصول إلى بيانات المستخدم الخاصة أو تعديلها و يمكن استبدالها مما يؤدي إلى تغيير أي من البيانات المنقولة، مثل الجهة المتلقية لتحويل الأموال.

**سيناريو #3**: قاعدة بيانات كلمات المرور لا تستخدم بيانات عشوائية إضافية "salted “أو إضافة بيانات عشوائية ذات نمط بسيط غير عشوائي بالقدر الكافي  استخدام **دوال اختزال غير مُضاف لها بيانات عشوائية** "unsalted hashes " لتخزين كلمات مرور جميع المستخدمين. عندما توجد ثغرة في خاصية رفع الملفات والتي تسمح للمهاجم باستعادة وتحميل قاعدة بيانات كلمات المرور. و بالتالي تتعرّض جميع كلمات المرور التي تم الكشف عنها لكسر حماية خوارزمياتها باستخدام جداول تحتوي على كلمات سرية مُعدّة مسبقًا "rainbow table of pre-calculated hashes". قد يتم كسر الـ"hashes" التي تم إنشاؤها بشكل بسيط وسريع، في حال استخدمت بطاقات المعالجة الرسومية"GPUs" حتى وإن تم إضافة بيانات عشوائية "salt".




## المصادر

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Password and Cryptographic Storage

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   OWASP Testing Guide: Testing for weak cryptography


## قائمة الربط مع إطار CWEs

CWE-261 Weak Encoding for Password

CWE-296 Improper Following of a Certificate's Chain of Trust

CWE-310 Cryptographic Issues

CWE-319 Cleartext Transmission of Sensitive Information

CWE-321 Use of Hard-coded Cryptographic Key

CWE-322 Key Exchange without Entity Authentication

CWE-323 Reusing a Nonce, Key Pair in Encryption

CWE-324 Use of a Key Past its Expiration Date

CWE-325 Missing Required Cryptographic Step

CWE-326 Inadequate Encryption Strength

CWE-327 Use of a Broken or Risky Cryptographic Algorithm

CWE-328 Reversible One-Way Hash

CWE-329 Not Using a Random IV with CBC Mode

CWE-330 Use of Insufficiently Random Values

CWE-331 Insufficient Entropy

CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator
(PRNG)

CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)

CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)

CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator
(PRNG)

CWE-340 Generation of Predictable Numbers or Identifiers

CWE-347 Improper Verification of Cryptographic Signature

CWE-523 Unprotected Transport of Credentials

CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications

CWE-757 Selection of Less-Secure Algorithm During Negotiation
('Algorithm Downgrade')

CWE-759 Use of a One-Way Hash without a Salt

CWE-760 Use of a One-Way Hash with a Predictable Salt

CWE-780 Use of RSA Algorithm without OAEP

CWE-818 Insufficient Transport Layer Protection

CWE-916 Use of Password Hash With Insufficient Computational Effort
