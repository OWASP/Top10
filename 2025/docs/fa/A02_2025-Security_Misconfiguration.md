# A02:2025 خطا در پیکربندی امنیتی (Security Misconfiguration)

این ریسک در نسخه جدید از رتبه ۵ به رتبه ۲ صعود کرده است، چرا که در بررسی‌ها مشخص شد ۱۰۰٪ برنامه‌های آزمایش‌شده حداقل یک نوع پیکربندی نادرست داشته‌اند. میانگین نرخ بروز این ضعف ۳٪ بوده و بیش از ۷۱۹,۰۰۰ مورد از ضعف‌های مرتبط با CWE در این دسته شناسایی شده است.

مهم‌ترین CWEهای مرتبط شامل [CWE-16](https://cwe.mitre.org/data/definitions/16.html) (Configuration) و [CWE-611](https://cwe.mitre.org/data/definitions/611.html) (Improper Restriction of XML External Entity Reference – XXE) هستند.

## جدول امتیازدهی

| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|------------------------|----------------|-----------------|---------------|---------------|----------------------------|----------------------|-----------------|
| 16                     | 27.70%         | 3.00%           | 100%          | 52.35%        | 7.96                       | 3.97                 | 719,084         |

## توضیحات

پیکربندی نادرست امنیتی زمانی رخ می‌دهد که سیستم، برنامه یا سرویس ابری از نظر امنیتی به‌درستی تنظیم نشده باشد و این مسئله باعث ایجاد آسیب‌پذیری شود.

### موارد شایع
- فقدان تقویت امنیتی مناسب (Security Hardening) در بخش‌های مختلف یا مجوزهای نادرست سرویس‌های ابری
- فعال یا نصب بودن ویژگی‌ها و قابلیت‌های غیرضروری (پورت‌ها، سرویس‌ها، حساب‌ها، ابزارهای تست و…)
- استفاده از حساب‌ها و رمزهای عبور پیش‌فرض بدون تغییر
- عدم وجود پیکربندی مرکزی برای جلوگیری از نمایش پیام‌های خطای بیش از حد (Stack Trace یا پیام‌های اطلاعاتی)
- غیرفعال بودن یا پیکربندی نادرست ویژگی‌های امنیتی جدید در سیستم‌های ارتقا یافته
- اولویت بیش از حد به سازگاری با نسخه‌های قدیمی، ایجاد پیکربندی‌های ناامن
- سرور و فریم‌ورک‌ها، کتابخانه‌ها و دیتابیس‌ها روی مقادیر امن تنظیم نشده باشند
- عدم ارسال هدرها یا دستورات امنیتی یا پیکربندی نادرست آن‌ها

### روش‌های پیشگیری
- پیاده‌سازی فرآیند سخت‌سازی تکرارپذیر برای محیط‌های Development، QA و Production با اعتبارنامه‌های متفاوت و ترجیحاً خودکار
- استفاده از پلتفرم حداقلی بدون ویژگی‌ها یا نمونه‌های غیرضروری
- بازبینی و به‌روزرسانی پیکربندی‌ها مطابق با security notes، patchها و به‌روزرسانی‌ها
- بررسی سطح دسترسی ذخیره‌سازهای ابری (مثل S3 Bucket)
- طراحی معماری بخش‌بندی‌شده (segmented) شامل segmentation، containerization و cloud security groups
- ارسال security directives به سمت کلاینت‌ها، مانند Security Headers
- پیاده‌سازی فرآیند خودکار یا حداقل سالی یک‌بار بررسی دستی اثربخشی تنظیمات امنیتی
- افزودن پیکربندی مرکزی برای جلوگیری از نمایش پیام‌های خطای بیش‌ازحد

### مثال سناریوهای حمله
1. نمونه‌اپلیکیشن‌های حذف‌نشده از محیط تولید با ضعف‌های امنیتی شناخته‌شده. مهاجم می‌تواند از حساب‌ها و رمزهای پیش‌فرض برای کنترل سیستم استفاده کند.
2. Directory Listing غیرفعال نشده، مهاجم می‌تواند فایل‌ها را دانلود و با مهندسی معکوس کد را مشاهده کند.
3. پیام‌های خطای دقیق مانند stack trace به کاربر نمایش داده شود که اطلاعات حساس فاش شود.
4. ارائه‌دهنده خدمات ابری (CSP) سطح دسترسی پیش‌فرض را روی اینترنت باز گذاشته باشد، داده‌های حساس بدون محدودیت قابل دسترسی باشند.

### لیست CWEهای مرتبط
- [CWE-5](https://cwe.mitre.org/data/definitions/5.html) J2EE Misconfiguration: Data Transmission Without Encryption  
- [CWE-11](https://cwe.mitre.org/data/definitions/11.html) ASP.NET Misconfiguration: Creating Debug Binary  
- [CWE-13](https://cwe.mitre.org/data/definitions/13.html) ASP.NET Misconfiguration: Password in Configuration File  
- [CWE-15](https://cwe.mitre.org/data/definitions/15.html) External Control of System or Configuration Setting  
- [CWE-16](https://cwe.mitre.org/data/definitions/16.html) Configuration  
- [CWE-260](https://cwe.mitre.org/data/definitions/260.html) Password in Configuration File  
- [CWE-315](https://cwe.mitre.org/data/definitions/315.html) Cleartext Storage of Sensitive Information in a Cookie  
- [CWE-489](https://cwe.mitre.org/data/definitions/489.html) Active Debug Code  
- [CWE-526](https://cwe.mitre.org/data/definitions/526.html) Exposure of Sensitive Information Through Environmental Variables  
- [CWE-547](https://cwe.mitre.org/data/definitions/547.html) Use of Hard-coded, Security-relevant Constants  
- [CWE-611](https://cwe.mitre.org/data/definitions/611.html) Improper Restriction of XML External Entity Reference  
- [CWE-614](https://cwe.mitre.org/data/definitions/614.html) Sensitive Cookie in HTTPS Session Without 'Secure' Attribute  
- [CWE-776](https://cwe.mitre.org/data/definitions/776.html) Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)  
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html) Permissive Cross-domain Policy with Untrusted Domains  
- [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) Sensitive Cookie Without 'HttpOnly' Flag  
- [CWE-1174](https://cwe.mitre.org/data/definitions/1174.html) ASP.NET Misconfiguration: Improper Model Validation  

### منابع
- [OWASP Top 10:2025 - A02 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)  
- [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/)  
- [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/)  
- [Application Security Verification Standard 5.0.0](https://owasp.org/www-project-application-security-verification-standard/)  
- [NIST Guide to General Server Hardening](https://nvlpubs.nist.gov/)  
- [CIS Security Configuration Guides / Benchmarks](https://www.cisecurity.org/cis-benchmarks/)  
- [Amazon S3 Bucket Discovery and Enumeration](https://aws.amazon.com/)  
- [ScienceDirect: Security Misconfiguration](https://www.sciencedirect.com/)
