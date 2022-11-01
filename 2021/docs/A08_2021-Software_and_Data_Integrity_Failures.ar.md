# A08:2021 – فشل سلامة البرامج والبيانات

## العوامل

| ربطها مع CWEs | الحد الأقصى للحدوث | متوسط معدل الحدوث | التغطية القصوى | متوسط معدل التغطية | متوسط استغلال الثغرات | متوسط التأثير | إجمالي التكرار | إجمالي نقاط الضعف CVEs |
|---------------|--------------------|-------------------|----------------|--------------------|-----------------------|---------------|----------------|------------------------|
| 10            | 16.67%             | 2.05%             | 75.04%         | 45.35%             | 6.94                  | 7.94          | 47,972         | 1,152                  |



## نظرة عامة

تمت إضافة هذا التصنيف في عام 2021 حيث يُركّز على وضع افتراضات تتعلّق بتحديثات البرامج والبيانات الحساسة أو تطبيق معايير CI/CD pipeline من دون التحقّق من سلامتها. إن أحد أكبر التأثيرات الكبيرة والموجودة في قواعد بيانات الثغرات CVE /CVSS والمرتبطة مع إطار CWEs وهم: CWE-502، CWE-829، CWE-494.

## الوصف 

فشل سلامة البيانات والبرامج تتعلّق بالشّفرة المصدرية والبنية التحتيّة الغير محميّة من الانتهاكات التي تتعّلق بسلامتها. على سبيل المثال: حين يتم ترميز الكائنات أو البيانات بطريقة تُمكّن المهاجم أن يطّلع أو يقوم بإجراء التعديلات الغير مُصرّح بها. مثال آخر: عندما يعتمد التطبيق على إضافات أخرى أو مكتبات أو بعض الأنماط الغير موثوقة أو من خلال استخدام شبكات توصيل المحتوى CDNs الغير موثوق بها، ويمكن أن يؤدي CI / CIC الغير آمن إلى إمكانية الوصول الغير مُصرّح به أو تنزيل برمجية خبيثة أو اختراق النظام. أخيرًا، تتضمّن العديد من التطبيقات الآن وظيفة التحديث التلقائي، حيث يتم تنزيل التحديثات دون التحقّق من السلامة بشكل كافي وتثبيتها على التطبيقات التي تم الوثوق بها سابقًا. مما يُمكّن المهاجمين أن يقوموا بتحميل تحديثاتهم الخاصة ليتم تثبيتها وتشغيلها على جميع الأجهزة.  

##  كيفية الحماية منها 

-   تأكد من عدم إرسال البيانات الغير مشفّرة أو الغير موقّعة إلى عملاء غير موثوقين بدون شكل من أشكال التحقق من سلامة أو وجود توقيع رقمي وذلك من أجل اكتشاف التلاعب بالبيانات.

-   التحقّق من سلامة البرامج أو البيانات من المصادر الرسمية والمتوقعة، عبر التأكد من وجود التواقيع أو آليات مُشابهة لضمان سلامة البيانات

-   تأكد من أن المكتبات والمكونات، مثل Npm أو Maven، تستخدم مصادر موثوقة.

-   تأكد من استخدام أدوات الحماية عند استخدام برمجيات الطرف الثالث، مثل OWASP Dependency Check أو OWASP CycloneDX ، والتي تقوم بالتأكد من عدم وجود أي ثغرات أمنية 

-   تأكد من أن   CI / CD لديه الإعدادات المناسبة والتحكّم المناسب للوصول للبرامج والبيانات للتأكد من سلامتها خلال آلية الإنشاء والنشر.


## أمثلة على سيناريوهات الهجوم

**سيناريو #1 إلغاء التسلسل الغير آمن:** يستدعي تطبيق React مجموعة من الخدمات المصغّرة لـ Spring Boot. فقد حاول المبرمجين بالتأكد من أن الشّفرة المصدرية الخاصة بهم غير قابلة للتغيير. والحل الذي توصلوا إليه هو إجراء تسلسل لحالة المستخدم وتمريرها ذهابًا وإيابًا مع كل طلب. فقد لاحظ المهاجم توقيع كائن جافا R00 يمكنه من استخدام أداة Java Serial Killer للحصول على إمكانية التنفيذ عن بعد. 

**سيناريو #2 التحديث بدون التأكد من التواقيع:** العديد من أجهزة الموجّهات المنزلية والبرامج الثابتة Firmware وغيرها لا تتحقّق من صحة التواقيع الرقمية عند إجراء التحديثات. حيث تُعد البرامج الثابتة الغير موقعة هدفًا سهلًا للمهاجمين. فالخطر هنا أنه لا توجد آلية لإصلاحه، بل في انتظار الإصلاح في الإصدارات القادمة

**سيناريو #3 التحديثات التي استهدفت SolarWinds**: يقوم المهاجمون المتقدمون باستهداف آلية التحديث للأنظمة. ومن خلال ملاحظة الهجمة الحديثة التي استهدفت SolarWinds Orion. حيث قامت الشركة بتطوير آلية وسياسة للتأكد من سلامة عملية التحديث وأمنها. ومع ذلك فقد يستطيع المهاجمون استغلالها، وقد حدث ذلك واستغلوا المهاجمين تلك الآلية ولمدة أشهر، حيث قاموا بحقن برمجيات التحديثات للأنظمة التي أثّرت على أكثر من 18,000 نظام لأكثر من 100 منظمة حول العالم. حيث يُعتبر هذا الهجوم من أخطر الهجمات التي حدثت حتى يومنا هذا. 

## المصادر

-   OWASP Cheat Sheet: Software Supply Chain Security (Coming Soon)

-   OWASP Cheat Sheet: Secure build and deployment (Coming Soon)

-    [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) 
 
-   [OWASP Cheat Sheet: Deserialization](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)

-   [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## قائمة الربط مع إطار CWEs



[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
