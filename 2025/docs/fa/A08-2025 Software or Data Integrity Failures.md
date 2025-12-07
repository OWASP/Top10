# A08:2025 Software or Data Integrity Failures

## پس‌زمینه
Software or Data Integrity Failures در رتبه #8 باقی مانده و نام آن کمی تغییر کرده تا دقیق‌تر از قبل منعکس‌کننده تمرکز روی integrity نرم‌افزار و داده باشد. این دسته روی بررسی و حفظ trust boundaries و صحت نرم‌افزار، کد و داده‌ها در سطح پایین‌تر از Software Supply Chain Failures تمرکز دارد. ضعف‌های رایج شامل فرضیات اشتباه درباره بروزرسانی نرم‌افزار و داده‌های حساس بدون اعتبارسنجی integrity آن‌ها است.

CWEهای مهم شامل CWE-829: Inclusion of Functionality from Untrusted Control Sphere، CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes و CWE-502: Deserialization of Untrusted Data می‌شوند.

## جدول امتیازدهی
| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|------------------------|----------------|-----------------|----------------|----------------|---------------------------|--------------------|----------------|
| 14                     | 8.98%          | 2.75%           | 78.52%         | 45.49%         | 7.11                      | 4.79               | 501,327        |

## توضیحات
این دسته مربوط به نرم‌افزار و زیرساخت‌هایی است که نمی‌توانند از اجرای کد یا دریافت داده‌ی غیرمعتبر یا غیرقابل اعتماد جلوگیری کنند.

### نمونه‌ها
- برنامه‌ای که به پلاگین‌ها، کتابخانه‌ها یا ماژول‌های ناشناس از منابع غیرقابل اعتماد، repositoryها یا CDNها اعتماد می‌کند.  
- CI/CD pipeline ناامن که صحت کد و artifacts را قبل از اجرا یا انتشار بررسی نمی‌کند.  
- قابلیت auto-update که بروزرسانی‌ها را بدون بررسی integrity دانلود و اعمال می‌کند.  
- داده‌هایی که سریالایز شده‌اند و attacker می‌تواند آن‌ها را تغییر دهد (insecure deserialization).  

## چگونه جلوگیری کنیم
- از digital signature یا مکانیسم مشابه برای اطمینان از صحت و منبع نرم‌افزار و داده استفاده کنید.  
- اطمینان حاصل کنید که کتابخانه‌ها و dependencyها فقط از repositoryهای قابل اعتماد مصرف می‌شوند. در محیط‌های پرریسک، internal known-good repository ایجاد کنید.  
- یک فرآیند بررسی (review) برای تغییرات کد و پیکربندی داشته باشید تا از وارد شدن کد مخرب جلوگیری شود.  
- CI/CD pipeline را با segregation، پیکربندی و کنترل دسترسی مناسب مدیریت کنید تا integrity کد حفظ شود.  
- داده‌های سریالایز نشده یا بدون encryption از clients غیرقابل اعتماد دریافت نشود و در صورت دریافت، بررسی integrity انجام شود.  

## نمونه سناریوهای حمله
**سناریو #1: Inclusion of Web Functionality from an Untrusted Source**  
یک شرکت از سرویس‌دهنده خارجی برای functionality پشتیبانی استفاده می‌کند و DNS mapping می‌زند تا `support.myCompany.com` را به `myCompany.SupportProvider.com` وصل کند. این باعث می‌شود تمام cookies، از جمله authentication cookies، به سرویس‌دهنده خارجی ارسال شود و مهاجم بتواند نشست کاربران را hijack کند.

**سناریو #2: Update بدون امضا**  
مودم‌ها، ست‌تاپ‌باکس‌ها و firmware دستگاه‌ها ممکن است بروزرسانی‌های unsigned دریافت کنند. مهاجم می‌تواند firmware مخرب را توزیع کند.

**سناریو #3: دانلود package از منبع غیرمعتبر**  
یک توسعه‌دهنده package مورد نیاز خود را از سایت آنلاین دانلود می‌کند، package unsigned و شامل کد مخرب است.

**سناریو #4: Insecure Deserialization**  
یک اپ React داده‌های user state را سریالایز می‌کند و بین microserviceها رد و بدل می‌کند. مهاجم signature object را تشخیص داده و با ابزار Java Deserialization Scanner کد از راه دور اجرا می‌کند.

## منابع (References)
- [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)  
- [SAFECode Software Integrity Controls](https://safecode.org/)  
- [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.solarwinds.com/securityadvisory)  
- [CodeCov Bash Uploader Compromise](https://about.codecov.com/security-update/)  
- [Securing DevOps by Julien Vehent](https://www.amazon.com/Securing-DevOps-Security-Continuous-Delivery/dp/1492054386)  
- [Insecure Deserialization by Tenendo](https://www.tenendo.com/blog/insecure-deserialization/)  

## لیست CWEهای مرتبط (List of Mapped CWEs)
- [CWE-345](https://cwe.mitre.org/data/definitions/345.html) Insufficient Verification of Data Authenticity  
- [CWE-353](https://cwe.mitre.org/data/definitions/353.html) Missing Support for Integrity Check  
- [CWE-426](https://cwe.mitre.org/data/definitions/426.html) Untrusted Search Path  
- [CWE-427](https://cwe.mitre.org/data/definitions/427.html) Uncontrolled Search Path Element  
- [CWE-494](https://cwe.mitre.org/data/definitions/494.html) Download of Code Without Integrity Check  
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html) Deserialization of Untrusted Data  
- [CWE-506](https://cwe.mitre.org/data/definitions/506.html) Embedded Malicious Code  
- [CWE-509](https://cwe.mitre.org/data/definitions/509.html) Replicating Malicious Code (Virus or Worm)  
- [CWE-565](https://cwe.mitre.org/data/definitions/565.html) Reliance on Cookies without Validation and Integrity Checking  
- [CWE-784](https://cwe.mitre.org/data/definitions/784.html) Reliance on Cookies without Validation and Integrity Checking in a Security Decision  
- [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Inclusion of Functionality from Untrusted Control Sphere  
- [CWE-830](https://cwe.mitre.org/data/definitions/830.html) Inclusion of Web Functionality from an Untrusted Source  
- [CWE-915](https://cwe.mitre.org/data/definitions/915.html) Improperly Controlled Modification of Dynamically-Determined Object Attributes  
- [CWE-926](https://cwe.mitre.org/data/definitions/926.html) Improper Export of Android Application Components
