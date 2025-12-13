# A03:2025 خطاهای زنجیره تأمین نرم‌افزار (Software Supply Chain Failures)

این دسته در آخرین نظرسنجی جامعه Top 10 در جایگاه اول قرار گرفت، به‌طوری که ۵۰٪ پاسخ‌دهندگان آن را رتبه 1 اعلام کردند. از زمان ورود این مورد به Top 10 سال ۲۰۱۳ با عنوان A9 – استفاده از مؤلفه‌های دارای آسیب‌پذیری شناخته‌شده، دامنه آن گسترش یافته و اکنون شامل تمام خطاهای زنجیره تأمین نرم‌افزار می‌شود، نه فقط مؤلفه‌های آسیب‌پذیر شناخته‌شده.

با وجود این گسترش، شناسایی خطاهای زنجیره تأمین همچنان دشوار است و تنها ۱۱ عدد CVE مرتبط با CWEهای این دسته ثبت شده‌اند. داده‌های آزمایشی نشان می‌دهند که این دسته بالاترین نرخ وقوع متوسط را با ۵٫۱۹٪ دارد.

## جدول امتیازدهی

| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها | کل CVEها |
|------------------------|----------------|-----------------|---------------|---------------|----------------------------|----------------------|-----------------|-----------|
| 5                      | 8.81%          | 5.19%           | 65.42%        | 28.93%        | 8.17                       | 5.23                 | 215,248         | 11        |

## توضیحات

شکست‌های زنجیره تأمین نرم‌افزار زمانی رخ می‌دهند که فرآیند ساخت، توزیع یا به‌روزرسانی نرم‌افزار دچار نقص شود. این مشکلات معمولاً ناشی از آسیب‌پذیری‌ها یا تغییرات مخرب در کدها، ابزارها یا وابستگی‌های شخص ثالثی است که سیستم به آن‌ها متکی است.

### احتمال بروز مشکل
- ردیابی نسخه همه اجزا (مستقیم یا تو در تو) به دقت انجام نشود.
- نرم‌افزار آسیب‌پذیر، قدیمی یا پشتیبانی‌نشده باشد.
- اسکن آسیب‌پذیری و عضویت در خبرنامه‌های امنیتی مرتبط انجام نشود.
- فرآیند مدیریت تغییر و ردیابی تغییرات در زنجیره تأمین وجود نداشته باشد.
- سخت‌سازی سیستم‌ها و کنترل دسترسی اعمال نشده باشد.
- جداسازی وظایف (Separation of Duties) رعایت نشده باشد.
- توسعه‌دهندگان از منابع غیرقابل اعتماد در محیط تولید استفاده کنند.
- پلتفرم‌ها، فریم‌ورک‌ها و وابستگی‌ها به موقع و مبتنی بر ریسک به‌روزرسانی نشوند.
- تنظیمات سیستم‌ها امن نباشند ([رجوع شود به A02:2025-Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
- Pipelineهای CI/CD پیچیده بدون سخت‌سازی و پایش باشند.
- SBOM به‌صورت متمرکز مدیریت نشود و وابستگی‌های تو در تو ردیابی نشوند.
- اجزای غیرضروری حذف نشوند و موجودی نسخه‌ها پایش نشود.
- اجزا تنها از منابع معتبر و امن دریافت نشوند و نسخه‌ها بدون بررسی به‌روزرسانی شوند.

### مدیریت تغییرات و سخت‌سازی سیستم‌ها
- فرآیند مدیریت تغییر باید شامل ثبت و پیگیری تغییرات در تنظیمات CI/CD، مخازن کد و نواحی Sandbox، محیط توسعه‌دهنده (IDE)، ابزارهای SBOM و آثار تولید شده، سیستم‌ها و لاگ‌های ثبت‌شده و یکپارچه‌سازی‌های شخص ثالث باشد.
- سیستم‌ها و منابع باید سخت‌افزاری و نرم‌افزاری تقویت شوند، شامل فعال کردن MFA و محدود کردن IAM:
  - مخازن کد (عدم ذخیره اسرار در کد، محافظت از شاخه‌ها، پشتیبان‌گیری)
  - ایستگاه‌های کاری توسعه‌دهندگان (به‌روزرسانی منظم، MFA، پایش)
  - سرورهای ساخت و CI/CD (تفکیک وظایف، کنترل دسترسی، ساخت‌های امضا شده، لاگ‌های غیرقابل تغییر)
  - آثار تولیدی (اثبات منبع، امضا، ارتقاء به جای بازسازی)
  - مدیریت زیرساخت به‌عنوان کد (IaC)
- برنامه‌ای مداوم برای پایش، اولویت‌بندی و اعمال تغییرات پیکربندی داشته باشد.

### مثال‌های سناریو حمله
1. فروشنده معتبر با بدافزار آلوده شده (مثل حمله SolarWinds 2019).  
2. فروشنده معتبر تنها در شرایط خاص رفتار مخرب نشان می‌دهد (مثال: سرقت Bybit 2025).  
3. حمله زنجیره تأمین GlassWorm 2025 علیه مارکت‌پلیس VS Code.  
4. اجرای کامپوننت‌ها با همان سطح دسترسی برنامه، مثال‌ها: CVE‑2017‑5638، چالش‌های پچ‌کردن IoT، شناسایی با Shodan IoT.

### لیست CWEهای مرتبط
- [CWE-477](https://cwe.mitre.org/data/definitions/477.html) Use of a Deprecated Function  
- [CWE-1035](https://cwe.mitre.org/data/definitions/1035.html) Using Components with Known Vulnerabilities  
- [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) Use of a Third-Party Component Without Maintainers  
- [CWE-1329](https://cwe.mitre.org/data/definitions/1329.html) Dependence on Component with No Update Capability  
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) Dependence on Vulnerable Third-Party Component  

### منابع
- [OWASP Top 10:2025 - A03 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)  
- [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)  
- [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/)  
- [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/)  
- [OWASP Dependency-Track](https://dependencytrack.org/)  
- [OWASP CycloneDX](https://cyclonedx.org/)  
- [OWASP Application Security Verification Standard: V1 Architecture, Design and Threat Modelling](https://owasp.org/www-project-application-security-verification-standard/)  
- [OWASP Dependency Check (Java & .NET)](https://owasp.org/www-project-dependency-check/)  
- [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://owasp.org/www-project-web-security-testing-guide/)  
- [OWASP Virtual Patching Best Practices](https://owasp.org/)  
- [MITRE CVE search](https://cve.mitre.org/)  
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)  
- [Retire.js (JavaScript)](https://retirejs.github.io/)  
- [GitHub Advisory Database](https://github.com/advisories)  
- [Ruby Libraries Security Advisory Database](https://rubysec.com/)  
- [SAFECode Software Integrity Controls](https://safecode.org/)  
- Glassworm & PhantomRaven supply chain attacks
