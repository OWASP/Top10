# A10:2025 Mishandling of Exceptional Conditions

## پس‌زمینه
Mishandling of Exceptional Conditions یک دسته‌بندی جدید در سال ۲۰۲۵ است. این دسته شامل ۲۴ CWE است و تمرکز آن روی مدیریت نامناسب خطاها، اشتباهات منطقی، «fail open» و سناریوهای مشابه ناشی از شرایط غیرمعمول در سیستم است. برخی از CWEهای این دسته قبلاً با کیفیت پایین کد مرتبط بودند، اما این دسته‌بندی جدید راهنمایی دقیق‌تری ارائه می‌دهد.

### CWEهای شاخص
- CWE-209: Generation of Error Message Containing Sensitive Information  
- CWE-234: Failure to Handle Missing Parameter  
- CWE-274: Improper Handling of Insufficient Privileges  
- CWE-476: NULL Pointer Dereference  
- CWE-636: Not Failing Securely ('Failing Open')  

## جدول امتیازدهی
| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|------------------------|----------------|-----------------|----------------|----------------|---------------------------|--------------------|----------------|
| 24                     | 20.67%         | 2.95%           | 100.00%        | 37.95%         | 7.11                      | 3.81               | 769,581        |

## توضیحات
Mishandling exceptional conditions زمانی رخ می‌دهد که برنامه‌ها نتوانند شرایط غیرمعمول یا غیرقابل پیش‌بینی را پیش‌بینی، شناسایی یا پاسخ دهند. این موضوع می‌تواند باعث crash، رفتار غیرمنتظره و ایجاد آسیب‌پذیری شود.

### دلایل شایع mishandling
- اعتبارسنجی ناقص یا دیرهنگام ورودی‌ها  
- مدیریت خطا در سطح بالا به جای محل وقوع خطا  
- شرایط محیطی غیرمنتظره (مثل حافظه، دسترسی‌ها، شبکه)  
- استثناهای مدیریت‌نشده یا inconsistent handling  

این ضعف می‌تواند منجر به آسیب‌پذیری‌های مختلف امنیتی شود، از جمله:  
- باگ‌های منطقی  
- overflowها  
- race condition  
- مشکلات تراکنشی، حافظه، state، منابع، زمان‌بندی، احراز هویت و مجوز  

## چگونه جلوگیری کنیم
- برای هر خطا یا استثنا، مدیریت مستقیم در محل وقوع آن ایجاد کنید.  
- مدیریت خطا باید شامل موارد زیر باشد:  
  - ارائه پیام خطای قابل فهم برای کاربر  
  - ثبت log  
  - ایجاد alert در صورت لزوم  
- از global exception handler برای مدیریت موارد از دست رفته استفاده کنید.  
- از ابزارهای نظارت و observability برای شناسایی الگوهای تکرارشونده استفاده کنید.  
- تراکنش‌ها در صورت بروز خطا باید rollback شوند (Fail Closed).  
- محدودیت‌های منابع، rate limiting و throttling را اعمال کنید تا از وقوع exceptional conditions جلوگیری شود.  
- اعتبارسنجی دقیق ورودی‌ها، sanitization و escaping برای کاراکترهای خطرناک را اعمال کنید.  
- مدیریت خطا و استثناها باید به صورت متمرکز و یکسان در کل سازمان انجام شود.  
- در طول طراحی پروژه، از secure design review و threat modeling استفاده کنید.  
- بررسی کد، تحلیل ایستا، تست فشار، تست عملکرد و تست نفوذ را اجرا کنید.  

## نمونه سناریوهای حمله
**سناریو #1: Resource Exhaustion / DoS**  
اگر فایل‌ها هنگام upload استثناء تولید کنند اما منابع آزاد نشوند، هر خطا باعث قفل شدن منابع می‌شود تا همه منابع مصرف شوند.

**سناریو #2: Sensitive Data Exposure**  
پیام خطای کامل پایگاه داده به کاربر نشان داده شود و مهاجم با ادامه تولید خطا، اطلاعات حساس سیستم را جمع‌آوری کرده و از آن برای حمله SQL Injection استفاده کند.

**سناریو #3: State Corruption در تراکنش‌های مالی**  
یک تراکنش چندمرحله‌ای شامل debit، credit و log است. اگر خطایی در وسط تراکنش رخ دهد و rollback کامل انجام نشود، مهاجم می‌تواند حساب کاربر را خالی کند یا تراکنش را چندباره ارسال کند.

## منابع (References)
- [OWASP MASVS‑RESILIENCE](https://owasp.org/)  
- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)  
- [OWASP ASVS: V16.5 Error Handling](https://owasp.org/www-project-application-security-verification-standard/)  
- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/)  
- [Best Practices for Exceptions (Microsoft, .Net)](https://learn.microsoft.com/)  
- [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/)  
- [General Error Handling Rules (Google for Developers)](https://developers.google.com/)  

## لیست CWEهای مرتبط (List of Mapped CWEs)
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html) Generation of Error Message Containing Sensitive Information  
- [CWE-215](https://cwe.mitre.org/data/definitions/215.html) Insertion of Sensitive Information Into Debugging Code  
- [CWE-234](https://cwe.mitre.org/data/definitions/234.html) Failure to Handle Missing Parameter  
- [CWE-235](https://cwe.mitre.org/data/definitions/235.html) Improper Handling of Extra Parameters  
- [CWE-248](https://cwe.mitre.org/data/definitions/248.html) Uncaught Exception  
- [CWE-252](https://cwe.mitre.org/data/definitions/252.html) Unchecked Return Value  
- [CWE-274](https://cwe.mitre.org/data/definitions/274.html) Improper Handling of Insufficient Privileges  
- [CWE-280](https://cwe.mitre.org/data/definitions/280.html) Improper Handling of Insufficient Permissions or Privileges  
- [CWE-369](https://cwe.mitre.org/data/definitions/369.html) Divide By Zero  
- [CWE-390](https://cwe.mitre.org/data/definitions/390.html) Detection of Error Condition Without Action  
- [CWE-391](https://cwe.mitre.org/data/definitions/391.html) Unchecked Error Condition  
- [CWE-394](https://cwe.mitre.org/data/definitions/394.html) Unexpected Status Code or Return Value  
- [CWE-396](https://cwe.mitre.org/data/definitions/396.html) Declaration of Catch for Generic Exception  
- [CWE-397](https://cwe.mitre.org/data/definitions/397.html) Declaration of Throws for Generic Exception  
- [CWE-460](https://cwe.mitre.org/data/definitions/460.html) Improper Cleanup on Thrown Exception  
- [CWE-476](https://cwe.mitre.org/data/definitions/476.html) NULL Pointer Dereference  
- [CWE-478](https://cwe.mitre.org/data/definitions/478.html) Missing Default Case in Multiple Condition Expression  
- [CWE-484](https://cwe.mitre.org/data/definitions/484.html) Omitted Break Statement in Switch  
- [CWE-550](https://cwe.mitre.org/data/definitions/550.html) Server-generated Error Message Containing Sensitive Information  
- [CWE-636](https://cwe.mitre.org/data/definitions/636.html) Not Failing Securely ('Failing Open')  
- [CWE-703](https://cwe.mitre.org/data/definitions/703.html) Improper Check or Handling of Exceptional Conditions  
- [CWE-754](https://cwe.mitre.org/data/definitions/754.html) Improper Check for Unusual or Exceptional Conditions  
- [CWE-755](https://cwe.mitre.org/data/definitions/755.html) Improper Handling of Exceptional Conditions  
- [CWE-756](https://cwe.mitre.org/data/definitions/756.html) Missing Custom Error Page
