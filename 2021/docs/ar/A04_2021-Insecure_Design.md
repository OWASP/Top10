# A04:2021 – التصميم الغير آمن

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 40            | 24.19%             | 3.00%             | 77.25%         | 42.51%             | 6.46                  | 6.78          | 262,407        | 2,691                  |



## نظرة عامة

هو تصنيف جديد تمت إضافته في هذه النسخة لعام 2021 والذي يركّز على المخاطر المتعلقة بعيوب وأخطاء التصميم، مما يدعو إلى المزيد من استخدام نمذجة التهديدات، وأنماط التصميم الآمنة وبنية تحتية مبنيّة على أفضل الامتثالات. الجدير بالذكر أن إطار CWE تضمن الـ CWEs التالية: CWE-209، CWE-256، CWE-501، CWE-522.

## الوصف 
التصميم الغير آمن تصنيف واسع يشمل العديد من نقاط الضعف المختلفة، ويُعرف على أنه " تصميم ذو عنصر تحكم " Control “مفقود أو غير فعّال، التصميم الغير آمن هو المكان الذي يكون فيه عنصر التحكم غائبًا، على سبيل المثال، لنفرض أن هناك **شفّرة مصدرية** يجب أن تُراعي تشفير البيانات الحساسة ولكن لا توجد طريقة لتطبيق التشّفير.
 التصميم الغير آمن والغير فعّال هو: المكان حينما يمكن إدراك وجود التهديد، لكن التحقّق المنطقي الغير فعّال من فضاء العمل (الأعمال) يمنع تنفيذ الإجراء. على سبيل المثال لنفرض أن هناك فضاء عمل يجب أن يقوم بمعالجة الإعفاء الضريبي للجائحة بناءً على فئات الدخل لكنه لا يقوم بالتحقّق فيما إذا كانت البيانات المدخلة موقعة بشكل صحيح أو لا، مما قد يؤدي إلى فائدة أكثر مما ينبغي     . 
التصميم الآمن عبارة عن ثقافة ومنهجيّة تقوم بتقييم التهديدات باستمرار وتضمن أن **الشّفرة المصدرية** مصمّمة بشكل قوي ومختبرة ضد طرق الهجوم المعروفة. يتطلّب التصميم الآمن دورة حياة تطوير آمنة، والبعض من أنماط التصميم الآمنة أو مكتبات المكونات المجهزة مُسبقًا أو الأدوات ونمذجة التهديدات. 


## كيفية الحماية منها

-   إنشاء واستخدام دورة حياة تطوير آمنة مع الاستعانة بأخصائي أمن تطبيقات لتقييم وتصميم عناصر التحكّم المتعلقة بالأمان والخصوصية.

-   إنشاء واستخدام مكتبة تحتوي على أنماط التصميم الآمن ومكونات مُسبقة وجاهزة للاستخدام. 

-   نمذجة التهديدات لعمليات المصادقة "التحقّق من الهوية" الحساسة، والتحكّم في الوصول، والتسلسل المنطقي التطبيق، والمسارات الأساسية للتطبيق.

-   وحدة للكتابة ولاختبارات التكامل للتحقّق من أن جميع المسارات الحرجة مقاومة لنموذج التهديد المتوقّع.

## أمثلة على سيناريوهات الهجوم

**سيناريو #1:**  قد يتضمّن مسار عملية استرداد عناصر اعتماد المصداقية" أسئلة وإجابات"، الذي يحظره إطار NIST 800-63b وOWASP ASVS وOWASP Top 10، فلا يمكن الوثوق في الأسئلة والإجابات كأدلّة على صحة هوية المستخدم حيث يمكن لأكثر من شخص معرفة الإجابات، وهذا هو سبب حظره. يجب إزالة الشّفرة المصدرية تلك واستبدالها بتصميم أكثر أمانًا.

**سيناريو #2:** تقوم دور سينما بعمل خصومات لعمليات الحجز الجماعي لـ١٥ شخص كحد أقصى قبل الدفع. هذا المسار قد يُشكّل خطرًا ويسمح للمهاجم باختبار ما إذا كان بإمكانه حجز ٦٠٠ مقعد دفعة واحدة من خلال طلبات قليلة، مما يتسبّب في خسارة هائلة للدخل.

**سيناريو #3:** لا تتمتّع مواقع التجارة الإلكترونية من الحماية ضد الروبوتات التي يُديرها مستثمرون يقومون بشراء بطاقات المعالجة الرسومية المطوّرة لإعادة بيعها لاحقًا في مواقع المزادات بأسعار أعلى. هذا يضع صانعيّ كروت الفيديو وكذلك متاجر البيع بالتجزئة في موقف حرج، التصاميم اليقظة ضد الروبوتات وإضافة قواعد تصميم النطاق المعتمدة على المنطق " مثل رصد عمليات الشراء التي تتم في غضون ثوانٍ معدودة "قد ترصد عمليات الشراء الغير طبيعية وتقوم برفضها.

## المصادر

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## قائمة الربط مع إطار CWEs

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)
