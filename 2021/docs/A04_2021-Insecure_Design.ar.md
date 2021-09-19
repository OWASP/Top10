# A04:2021 – التصميم الغير آمن

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 40            | 24.19%             | 3.00%             | 77.25%         | 42.51%             | 6.46                  | 6.78          | 262,407        | 2,691                  |



## نظرة عامة

هو تصنيف جديد تم اضافته في هذه النسخة لعام ٢٠٢١ والذي يركز على المخاطر المتعلقة بعيوب وأخطاء التصميم، مما يدعو الى مزيد من الاستخدام لنمذجة التهديدات، أنماط التصميم الآمنة وبنية تحتية مبنية على أفضل الامتثالات. الجدير بالذكر أن إطار CWE تضمن ال CWEs التالية: CWE-209، CWE-256، CWE-501، CWE-522.

## الوصف 
التصميم الغير آمن تصنيف واسع تمثل العديد من نقاط الضعف المختلفة، يوصف على انه" تصميم يفتقد لعنصر تحكم او يحتوي على عنصر تحكم غير فعال"، التصميم الغير آمن هو المكان الذي يكون فيه عنصر التحكم غائبا. 
على سبيل المثال، افترض انه يجب أن يكون هنالك تشفير للبيانات الحساسة في الشفرة المصدرية، ولكن لا توجد طريقة لتطبيق التشفير. التصميم الغير آمن والغير فعال هو المكان الذي يمكن ان يحدث فيه التهديد، لكن التحقق الغير كافي من صحة منطق المجال (الأعمال) يمنع تنفيذ الإجراء. على سبيل المثال افترض ان هنالك مجال يجب ان يقوم بمعالجة الاعفاء الضريبي للجائحة بناءً على فئات الدخل لكنه لا يقوم بالتحقق فيما إذا كانت المدخلات موقعة بشكل صحيح أو لا فيوفر فائدة أكثر مما ينبغي منحه. 


التصميم الآمن عبارة عن ثقافة ومنهجية تقوم بتقييم التهديدات باستمرار وتضمن ان الشفرة المصدرية مصممة بشكل قوي ومختبرة ضد طرق الهجوم المعروفة. يتطلب التصميم الآمن دورة حياة تطوير آمنة، البعض من أنماط التصميم الآمنة أو مكتبة مكونات أو أدوات مسبقة وجاهزة للاستخدام، ونمذجة للتهديدات. 

## كيفية الحماية منها

-   انشاء واستخدام دورة حياة تطوير آمنة مع الاستعانة بأخصائي أمن تطبيقات لتقييم وتصميم عناصر التحكم المتعلقة بالأمان والخصوصية.

-   انشاء واستخدام مكتبة تحتوي على أنماط التصميم الآمن او مكونات مسبقة وجاهزة للاستخدام. 

-   استخدام نمذجة التهديدات لعمليات المصادقة (التحقق من الهوية) الحرجة، التحكم في الوصول، منطق التطبيق، المسارات الأساسية للتطبيق.

-   كتابة اختبارات والوحدة وتكامل للتحقق من أن جميع المسارات الحرجة مقاومة لنموذج التهديد المتوقع.

## أمثلة على سيناريوهات الهجوم

**سيناريو #1:**  قد يتضمن مسار عملية استرداد عناصر اعتماد المصداقية" أسئلة وإجابات"، الذي يحظره اطار NIST 800-63b وOWASP ASVS وOWASP Top 10، فلا يمكن الوثوق في الأسئلة والإجابات كأدلة على صحة هوية المستخدم حيث يمكن لأكثر من شخص معرفة الإجابات، وهذا هو سبب حظرهم. يجب إزالة الشفرة المصدرية تلك واستبدالها بتصميم أكثر أماناً.

**سيناريو #2:** تقوم دور سينما بعمل خصومات لعمليات الحجز الجماعي ل١٥ شخص كحد أقصى قبل الدفع. هذا المسار قد يشكل خطرا ويسمح للمهاجم باختبار ما إذا كان بإمكانه حجز ٦٠٠ مقعد دفعة واحدة من خلال طلبات قليلة، مما يتسبب في خسارة هائلة للدخل.

**سيناريو #3:** لا تتمتع مواقع التجارة الإلكترونية من الحماية ضد الروبوتات التي يديرها مستثمرون يقومون بشراء قطع كروت الفيديو المطورة لإعادة بيعها لاحقاً في مواقع المزادات بأسعار اعلى. هذا يجعل من صانعي كروت الفيديو وكذلك متاجر البيع بالتجزئة في موقف حرج، قد يؤدي التصميم الامن لتقليل ومنع وحماية ضد الروبوت كذلك اضافة القواعد التي تحد من الروبوتات التي تتصل بالنطاق، مثل عمليات الشراء التي تتم في غضون ثوان معدودة من تحديد عمليات الشراء الغير مصادق عليها ورفضها. 

## المصادر

-   [OWASP Cheat Sheet: Secure Design Principles](TBD)

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/system/files/documents/2021/07/09/Developer%20Verification%20of%20Software.pdf)

## قائمة الربط مع إطار CWEs

CWE-73 External Control of File Name or Path

CWE-183 Permissive List of Allowed Inputs

CWE-209 Generation of Error Message Containing Sensitive Information

CWE-213 Exposure of Sensitive Information Due to Incompatible Policies

CWE-235 Improper Handling of Extra Parameters

CWE-256 Unprotected Storage of Credentials

CWE-257 Storing Passwords in a Recoverable Format

CWE-266 Incorrect Privilege Assignment

CWE-269 Improper Privilege Management

CWE-280 Improper Handling of Insufficient Permissions or Privileges

CWE-311 Missing Encryption of Sensitive Data

CWE-312 Cleartext Storage of Sensitive Information

CWE-313 Cleartext Storage in a File or on Disk

CWE-316 Cleartext Storage of Sensitive Information in Memory

CWE-419 Unprotected Primary Channel

CWE-430 Deployment of Wrong Handler

CWE-434 Unrestricted Upload of File with Dangerous Type

CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request
Smuggling')

CWE-451 User Interface (UI) Misrepresentation of Critical Information

CWE-472 External Control of Assumed-Immutable Web Parameter

CWE-501 Trust Boundary Violation

CWE-522 Insufficiently Protected Credentials

CWE-525 Use of Web Browser Cache Containing Sensitive Information

CWE-539 Use of Persistent Cookies Containing Sensitive Information

CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session

CWE-598 Use of GET Request Method With Sensitive Query Strings

CWE-602 Client-Side Enforcement of Server-Side Security

CWE-642 External Control of Critical State Data

CWE-646 Reliance on File Name or Extension of Externally-Supplied File

CWE-650 Trusting HTTP Permission Methods on the Server Side

CWE-653 Insufficient Compartmentalization

CWE-656 Reliance on Security Through Obscurity

CWE-657 Violation of Secure Design Principles

CWE-799 Improper Control of Interaction Frequency

CWE-807 Reliance on Untrusted Inputs in a Security Decision

CWE-840 Business Logic Errors

CWE-841 Improper Enforcement of Behavioral Workflow

CWE-927 Use of Implicit Intent for Sensitive Communication

CWE-1021 Improper Restriction of Rendered UI Layers or Frames

CWE-1173 Improper Use of Validation Framework
