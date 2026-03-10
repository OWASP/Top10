# A06:2025 Insecure Design

## پس‌زمینه
Insecure Design دو پله سقوط کرده و از #4 به #6 رسیده است، چرا که A02:2025-Security Misconfiguration و A03:2025-Software Supply Chain Failures از آن عبور کرده‌اند. این دسته در سال ۲۰۲۱ معرفی شد و پیشرفت‌های قابل توجهی در صنعت از نظر threat modeling و تمرکز بر طراحی امن مشاهده شده است.

این دسته بر ریسک‌های مرتبط با طراحی و معماری نرم‌افزار تمرکز دارد، از جمله نقص در منطق کسب‌وکار برنامه، مثل عدم تعریف تغییرات وضعیت ناخواسته یا غیرمنتظره در برنامه. دسته‌بندی CWEها شامل CWE-256: Unprotected Storage of Credentials، CWE-269: Improper Privilege Management، CWE-434: Unrestricted Upload of File with Dangerous Type، CWE-501: Trust Boundary Violation، و CWE-522: Insufficiently Protected Credentials می‌شود.

## جدول امتیازدهی
| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|------------------------|----------------|-----------------|----------------|----------------|---------------------------|--------------------|----------------|
| 39                     | 22.18%         | 1.86%           | 88.76%         | 35.18%         | 6.96                      | 4.05               | 729,882        |

## توضیحات
Insecure Design یک دسته گسترده است که ضعف‌های مختلف را در قالب “کنترل‌های طراحی ناقص یا ناکارآمد” نشان می‌دهد. توجه داشته باشید که بین Insecure Design و Insecure Implementation تفاوت وجود دارد:

- طراحی امن ممکن است با باگ‌های پیاده‌سازی منجر به آسیب‌پذیری شود.  
- طراحی ناامن با بهترین پیاده‌سازی هم قابل اصلاح نیست، زیرا کنترل‌های امنیتی مورد نیاز اصلاً ایجاد نشده‌اند.  

یکی از عوامل Insecure Design، نبود پروفایل ریسک کسب‌وکار در نرم‌افزار است و عدم تعیین سطح امنیت مورد نیاز برای طراحی.

### سه بخش کلیدی طراحی امن
1. **Requirements and Resource Management:** جمع‌آوری و مذاکره بر سر نیازمندی‌های کسب‌وکار و امنیتی، مدیریت منابع و بودجه.  
2. **Secure Design:** فرهنگ و روش‌شناسی که تهدیدها را ارزیابی و اطمینان از طراحی مقاوم کد فراهم می‌کند. استفاده از threat modeling در جلسات refinement و تحلیل assumptions و failure states.  
3. **Secure Development Lifecycle:** شامل طراحی امن، الگوهای طراحی امن، کتابخانه کامپوننت‌های امن، ابزارهای مناسب، threat modeling، و post-mortem حوادث.

## چگونه جلوگیری کنیم
- ایجاد و استفاده از Secure Development Lifecycle با همکاری AppSec  
- استفاده از کتابخانه الگوهای طراحی امن یا paved-road components  
- انجام Threat Modeling برای بخش‌های حیاتی برنامه (احراز هویت، access control، business logic)  
- ادغام security language و controls در user stories  
- اعتبارسنجی plausibility در هر tier برنامه (frontend تا backend)  
- نوشتن unit و integration tests برای تمام critical flows  
- جدا کردن tierها در لایه سیستم و شبکه بر اساس نیازهای محافظتی  
- جداسازی robust tenants در تمام tiers  

## نمونه سناریوهای حمله
**سناریو #1:**  
یک workflow بازیابی credential با “questions and answers” که طبق NIST 800-63b، OWASP ASVS و OWASP Top 10 ممنوع است. پاسخ‌ها قابل اعتماد نیستند و باید با طراحی امن‌تر جایگزین شوند.

**سناریو #2:**  
یک زنجیره سینمایی اجازه تخفیف گروهی می‌دهد و حداکثر ۱۵ نفر را قبل از نیاز به پیش‌پرداخت قبول می‌کند. مهاجم می‌تواند با بررسی منطق کسب‌وکار، ۶۰۰ صندلی و تمام سینماها را با چند درخواست رزرو کند و خسارت مالی ایجاد کند.

**سناریو #3:**  
وب‌سایت e-commerce یک خرده‌فروش، محافظت در برابر botها ندارد. scalperها کارت‌های گرافیک را خریداری و در سایت‌های مزایده می‌فروشند. طراحی ضد-bot و قوانین domain logic می‌توانند خریدهای غیرمجاز را شناسایی و رد کنند.

## منابع (References)
- [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Design_Principles_Cheat_Sheet.html)  
- [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/)  
- [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/)  
- [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://csrc.nist.gov/publications)  
- [The Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)  
- [Awesome Threat Modeling](https://github.com/irony/awesome-threat-modeling)  

## لیست CWEهای مرتبط (List of Mapped CWEs)
- [CWE-73](https://cwe.mitre.org/data/definitions/73.html) External Control of File Name or Path  
- [CWE-183](https://cwe.mitre.org/data/definitions/183.html) Permissive List of Allowed Inputs  
- [CWE-256](https://cwe.mitre.org/data/definitions/256.html) Unprotected Storage of Credentials  
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
- [CWE-444](https://cwe.mitre.org/data/definitions/444.html) Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')  
- [CWE-451](https://cwe.mitre.org/data/definitions/451.html) User Interface (UI) Misrepresentation of Critical Information  
- [CWE-454](https://cwe.mitre.org/data/definitions/454.html) External Initialization of Trusted Variables or Data Stores  
- [CWE-472](https://cwe.mitre.org/data/definitions/472.html) External Control of Assumed-Immutable Web Parameter  
- [CWE-501](https://cwe.mitre.org/data/definitions/501.html) Trust Boundary Violation  
- [CWE-522](https://cwe.mitre.org/data/definitions/522.html) Insufficiently Protected Credentials  
- [CWE-525](https://cwe.mitre.org/data/definitions/525.html) Use of Web Browser Cache Containing Sensitive Information  
- [CWE-539](https://cwe.mitre.org/data/definitions/539.html) Use of Persistent Cookies Containing Sensitive Information  
- [CWE-598](https://cwe.mitre.org/data/definitions/598.html) Use of GET Request Method With Sensitive Query Strings  
- [CWE-602](https://cwe.mitre.org/data/definitions/602.html) Client-Side Enforcement of Server-Side Security  
- [CWE-628](https://cwe.mitre.org/data/definitions/628.html) Function Call with Incorrectly Specified Arguments  
- [CWE-642](https://cwe.mitre.org/data/definitions/642.html) External Control of Critical State Data  
- [CWE-646](https://cwe.mitre.org/data/definitions/646.html) Reliance on File Name or Extension of Externally-Supplied File  
- [CWE-653](https://cwe.mitre.org/data/definitions/653.html) Insufficient Compartmentalization  
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
