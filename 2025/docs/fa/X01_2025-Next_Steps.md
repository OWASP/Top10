# Next Steps

OWASP Top 10 طراحی‌شده تا ۱۰ ریسک مهم‌ترین و فراگیرترین تهدیدها را برجسته کند. با این حال، همیشه تعدادی ریسک "در لبه" وجود دارند که بررسی و شناسایی آنها ارزشمند است، اما در نهایت به دلیل کمبود فراوانی یا تأثیر کمتر در لیست ۱۰ ریسک اصلی قرار نگرفتند.  

دو مورد زیر برای سازمان‌هایی که به بلوغ در برنامه امنیت نرم‌افزار (AppSec) می‌رسند، مشاوران امنیتی، یا ابزارهای امنیتی که می‌خواهند پوشش خود را گسترش دهند، اهمیت ویژه دارند:

---

## X01:2025 Lack of Application Resilience

### پس‌زمینه  
این دسته‌بندی بازنامی از 2021’s Denial of Service است. تمرکز آن روی ضعف‌هایی است که به مشکلات مقاومت (resilience) نرم‌افزار مربوط می‌شوند. امتیازدهی این دسته‌بندی با A10:2025 Mishandling of Exceptional Conditions نزدیک بوده است. :contentReference[oaicite:1]{index=1}

### CWEهای شاخص  
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Uncontrolled Resource Consumption  
- [CWE-409](https://cwe.mitre.org/data/definitions/409.html) Improper Handling of Highly Compressed Data (Data Amplification)  
- [CWE-674](https://cwe.mitre.org/data/definitions/674.html) Uncontrolled Recursion  
- [CWE-835](https://cwe.mitre.org/data/definitions/835.html) Loop with Unreachable Exit Condition ('Infinite Loop')  

### جدول امتیازدهی

| تعداد CWEها | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین وزن بهره‌برداری | میانگین وزن اثر | کل رخدادها |
|------------|------------------|------------------|----------------|----------------|--------------------------|------------------|--------------|
| 16         | 20.05%           | 4.55%            | 86.01%         | 41.47%         | 7.92                     | 3.49             | 865,066      |

### توضیحات  
ضعف در مقاومت نرم‌افزار زمانی رخ می‌دهد که برنامه نتواند تحت فشار، خطاها یا شرایط غیرمنتظره، به درستی عمل کند یا از آن‌ها بازیابی شود. نتایج معمول شامل:

- اختلال در دسترسی (Availability)  
- فساد داده‌ها  
- افشای اطلاعات حساس  
- اثرات زنجیره‌ای روی سیستم‌ها  
- دور زدن کنترل‌های امنیتی :contentReference[oaicite:2]{index=2}

### راهکارهای پیشگیری  
- اعمال محدودیت‌ها، quotaها و قابلیت failover  
- شناسایی عملیات پرمصرف و محدود کردن دسترسی کاربران ناشناس  
- اعتبارسنجی دقیق ورودی‌ها با allow-list و محدودیت اندازه  
- محدود کردن پاسخ‌ها و عدم ارسال داده‌های خام به کاربر  
- پیش‌فرض‌های امن و rollback تراکنش‌ها در صورت خطا  
- استفاده از asynchronous/non‑blocking calls، اعمال timeout و محدودیت concurrency  
- تست عملکرد، load testing و حتی chaos engineering  
- پیاده‌سازی الگوهای resilience مانند circuit breaker، bulkheads و graceful degradation  
- نظارت و observability فعال همراه با تعریف alert  
- و در صورت لزوم، Proof‑of‑Work برای عملیات پرمصرف کاربران مشکوک  
- محدودیت مدت زمان session و اطلاعات ذخیره شده در session  

### نمونه حملات  
- مصرف عمدی منابع برای ایجاد Denial of Service  
- Fuzzing ورودی‌ها برای شکست منطق (logic)  
- حمله به وابستگی‌های خارجی و از کار افتادن APIها  

### منابع  
- [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)  
- [OWASP MASVS‑RESILIENCE](https://owasp.org/)  
- [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/)  
- [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://parser.com/)  
- [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/)  
- [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)  

### List of Mapped CWEs  
- [CWE-73](https://cwe.mitre.org/data/definitions/73.html) External Control of File Name or Path  
- [CWE-183](https://cwe.mitre.org/data/definitions/183.html) Permissive List of Allowed Inputs  
- [CWE-256](https://cwe.mitre.org/data/definitions/256.html) Plaintext Storage of a Password  
- [CWE-266](https://cwe.mitre.org/data/definitions/266.html) Incorrect Privilege Assignment  
- [CWE-269](https://cwe.mitre.org/data/definitions/269.html) Improper Privilege Management  
- [CWE-286](https://cwe.mitre.org/data/definitions/286.html) Incorrect User Management  
- [CWE-311](https://cwe.mitre.org/data/definitions/311.html) Missing Encryption of Sensitive Data  
- [CWE-312](https://cwe.mitre.org/data/definitions/312.html) Cleartext Storage of Sensitive Information  
- [CWE-313](https://cwe.mitre.org/data/definitions/313.html) Cleartext Storage in a File or on Disk  
- [CWE-316](https://cwe.mitre.org/data/definitions/316.html) Cleartext Storage of Sensitive Information in Memory  
- [CWE-362](https://cwe.mitre.org/data/definitions/362.html) Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')  
- [CWE-382](https://cwe.mitre.org/data/definitions/382.html) J2EE Bad Practices: Use of System.exit()  
- [CWE-419](https://cwe.mitre.org/data/definitions/419.html) Unprotected Primary Channel  
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html) Unrestricted Upload of File with Dangerous Type  
- [CWE-436](https://cwe.mitre.org/data/definitions/436.html) Interpretation Conflict  
- [CWE-444](https://cwe.mitre.org/data/definitions/444.html) Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')  
- [CWE-451](https://cwe.mitre.org/data/definitions/451.html) UI Misrepresentation of Critical Information  
- [CWE-454](https://cwe.mitre.org/data/definitions/454.html) External Initialization of Trusted Variables or Data Stores  
- [CWE-472](https://cwe.mitre.org/data/definitions/472.html) External Control of Assumed-Immutable Web Parameter  
- [CWE-501](https://cwe.mitre.org/data/definitions/501.html) Trust Boundary Violation  
- [CWE-522](https://cwe.mitre.org/data/definitions/522.html) Insufficiently Protected Credentials  
- [CWE-525](https://cwe.mitre.org/data/definitions/525.html) Use of Web Browser Cache Containing Sensitive Information  
- [CWE-539](https://cwe.mitre.org/data/definitions/539.html) Use of Persistent Cookies Containing Sensitive Information  
- [CWE-598](https://cwe.mitre.org/data/definitions/598.html) Use of GET Request Method With Sensitive Query Strings  
- [CWE-602](https://cwe.mitre.org/data/definitions/602.html) Client‑Side Enforcement of Server‑Side Security  
- [CWE-628](https://cwe.mitre.org/data/definitions/628.html) Function Call with Incorrectly Specified Arguments  
- [CWE-642](https://cwe.mitre.org/data/definitions/642.html) External Control of Critical State Data  
- [CWE-646](https://cwe.mitre.org/data/definitions/646.html) Reliance on File Name or Extension of Externally‑Supplied File  
- [CWE-653](https://cwe.mitre.org/data/definitions/653.html) Improper Isolation or Compartmentalization  
- [CWE-656](https://cwe.mitre.org/data/definitions/656.html) Reliance on Security Through Obscurity  
- [CWE-657](https://cwe.mitre.org/data/definitions/657.html) Violation of Secure Design Principles  
- [CWE-676](https://cwe.mitre.org/data/definitions/676.html) Use of Potentially Dangerous Function  
- [CWE-693](https://cwe.mitre.org/data/definitions/693.html) Protection Mechanism Failure  
- [CWE-799](https://cwe.mitre.org/data/definitions/799.html) Improper Control of Interaction Frequency  
- [CWE-807](https://cwe.mitre.org/data/definitions/807.html) Reliance on Untrusted Inputs in a Security Decision  
- [CWE-841](https://cwe.mitre.org/data/definitions/841.html) Improper Enforcement of Behavioral Workflow  
- [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) Improper Restriction of Rendered UI Layers or Frames  
- [CWE-1022](https://cwe.mitre.org/data/definitions/1022.html) Use of Web Link to Untrusted Target with window.opener Access  
- [CWE-1125](https://cwe.mitre.org/data/definitions/1125.html) Excessive Attack Surface  

---

## X02:2025 Memory Management Failures

### زمینه  
زبان‌هایی مانند Java, C#, JavaScript/TypeScript (Node.js), Go و Rust memory‑safe هستند. مشکلات مدیریت حافظه بیشتر در زبان‌های غیر memory‑safe مانند C و C++ رخ می‌دهد. این دسته کمترین امتیاز را در نظرسنجی جامعه داشت ولی سومین تعداد CVE مرتبط را دارد. ضعف‌های حافظه معمولاً بالاترین CVSS را دارند. :contentReference[oaicite:3]{index=3}

### جدول امتیازدهی
| تعداد CWEهای مرتبط | بیشترین نرخ وقوع | میانگین نرخ وقوع | بیشترین پوشش | میانگین پوشش | میانگین وزن بهره‌برداری | میانگین وزن تأثیر | کل رخدادها |
|--------------------|------------------|------------------|----------------|----------------|--------------------------|--------------------|-------------|
| 24                 | 2.96%             | 1.13%            | 55.62%         | 28.45%         | 6.75                     | 4.82               | 220,414     |

### توضیحات  
وقتی برنامه مجبور باشد خود حافظه را مدیریت کند، احتمال اشتباه زیاد است. اگرچه زبان‌های memory‑safe بیشتر استفاده می‌شوند، هنوز سیستم‌های legacy، سیستم‌های low‑level جدید و وب اپلیکیشن‌هایی که با mainframe، IoT، firmware تعامل دارند، از این مشکلات رنج می‌برند.  

نمونه CWEهای مرتبط: [CWE-120](https://cwe.mitre.org/data/definitions/120.html) Buffer Copy without Checking Size of Input، [CWE-121](https://cwe.mitre.org/data/definitions/121.html) Stack‑based Buffer Overflow.  

#### شرایط ایجاد خطا در مدیریت حافظه  
- تخصیص ناکافی حافظه  
- عدم اعتبارسنجی ورودی و overflow روی heap، stack یا buffer  
- ذخیره مقدار بزرگ‌تر از ظرفیت نوع متغیر  
- استفاده از حافظه تخصیص‌نیافته  
- خطای off‑by‑one  
- دسترسی به آبجکت پس از آزاد شدن  
- استفاده از متغیرهای بدون مقداردهی اولیه  
- نشت حافظه یا مصرف کامل حافظه تا شکست برنامه  

### راهکارهای پیشگیری  
- استفاده از زبان‌های memory‑safe (Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript)  
- در صورت اجبار به زبان غیر memory‑safe:  
  - فعال کردن ویژگی‌های سرور: ASLR, DEP, SEHOP  
  - پایش نشت حافظه  
  - اعتبارسنجی دقیق ورودی‌ها  
  - شناسایی توابع امن و ناامن زبان و اشتراک با تیم  
  - استفاده از کتابخانه‌های حافظه امن مانند SafeStringLib  
  - استفاده از managed buffers و strings به جای raw arrays/pointers  
  - آموزش secure coding و بررسی کد و تحلیل استاتیک  
  - استفاده از ابزارهای compiler مانند StackShield, StackGuard, Libsafe  
  - fuzzing تمامی ورودی‌ها  
  - توجه به warnings و errors کامپایلر  
  - پایش و patch زیرساخت  

### نمونه سناریوهای حمله  
- Buffer overflow: وارد کردن داده بیشتر از ظرفیت buffer و overwrite کردن stack pointer برای اجرای کد مخرب  
- Use‑After‑Free: استفاده از reference به حافظه آزاد شده و جایگذاری داده مهاجم  
- Format string vulnerability: ارسال ورودی با format specifier برای خواندن/نوشتن حافظه حساس  

### منابع  
- [OWASP community pages: Memory leak, Doubly freeing memory, & Buffer Overflow](https://owasp.org/)  
- [Awesome Fuzzing](https://github.com/dsl/awesome-fuzzing)  
- [Project Zero Blog](https://googleprojectzero.blogspot.com/)  
- [Microsoft MSRC Blog](https://msrc.microsoft.com/)  

### فهرست CWEهای مرتبط  
- [CWE-14](https://cwe.mitre.org/data/definitions/14.html) Compiler Removal of Code to Clear Buffers  
- [CWE-119](https://cwe.mitre.org/data/definitions/119.html) Improper Restriction of Operations within the Bounds of a Memory Buffer  
- [CWE-120](https://cwe.mitre.org/data/definitions/120.html) Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')  
- [CWE-121](https://cwe.mitre.org/data/definitions/121.html) Stack‑based Buffer Overflow  
- [CWE-122](https://cwe.mitre.org/data/definitions/122.html) Heap‑based Buffer Overflow  
- [CWE-124](https://cwe.mitre.org/data/definitions/124.html) Buffer Underwrite ('Buffer Underflow')  
- [CWE-125](https://cwe.mitre.org/data/definitions/125.html) Out‑of‑bounds Read  
- [CWE-126](https://cwe.mitre.org/data/definitions/126.html) Buffer Over‑read  
- [CWE-190](https://cwe.mitre.org/data/definitions/190.html) Integer Overflow or Wraparound  
- [CWE-191](https://cwe.mitre.org/data/definitions/191.html) Integer Underflow (Wrap or Wraparound)  
- [CWE-196](https://cwe.mitre.org/data/definitions/196.html) Unsigned to Signed Conversion Error  
- [CWE-367](https://cwe.mitre.org/data/definitions/367.html) Time‑of‑check Time‑of‑use (TOCTOU) Race Condition  
- [CWE-415](https://cwe.mitre.org/data/definitions/415.html) Double Free  
- [CWE-416](https://cwe.mitre.org/data/definitions/416.html) Use After Free  
- [CWE-457](https://cwe.mitre.org/data/definitions/457.html) Use of Uninitialized Variable  
- [CWE-459](https://cwe.mitre.org/data/definitions/459.html) Incomplete Cleanup  
- [CWE-467](https://cwe.mitre.org/data/definitions/467.html) Use of sizeof() on a Pointer Type  
- [CWE-787](https://cwe.mitre.org/data/definitions/787.html) Out‑of‑bounds Write  
- [CWE-788](https://cwe.mitre.org/data/definitions/788.html) Access of Memory Location After End of Buffer  
- [CWE-824](https://cwe.mitre.org/data/definitions/824.html) Access of Uninitialized Pointer  
