# A01:2025 نقض کنترل دسترسی (Broken Access Control)

این دسته به دلیل تأثیر شدید و شایع بودن آسیب‌پذیری‌های مرتبط با کنترل دسترسی، همچنان در جایگاه شماره ۱ در Top Ten قرار دارد. تمامی برنامه‌های آزمایش‌شده حداقل یک نوع از مشکلات مرتبط با کنترل دسترسی را داشتند و از نظر تعداد CVEهای مرتبط، این دسته رتبه دوم را بین سایر دسته‌ها دارد.

CWEهای مهم در این دسته عبارتند از:
- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): افشای اطلاعات حساس به کاربران یا نقش‌های غیرمجاز
- [CWE-201](https://cwe.mitre.org/data/definitions/201.html): افشای اطلاعات حساس از طریق داده‌های ارسال‌شده (مثل فرم یا API)
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): جعل درخواست سمت سرور (SSRF)
- [CWE-352](https://cwe.mitre.org/data/definitions/352.html): جعل درخواست بین‌سایتی (CSRF)

## جدول امتیازدهی

| تعداد CWEها | بیشینه نرخ وقوع | میانگین نرخ وقوع | بیشینه پوشش | میانگین پوشش | میانگین امتیاز Exploit | میانگین امتیاز Impact | کل وقوع‌ها |
|-------------|----------------|-----------------|-------------|---------------|------------------------|----------------------|-------------|
| 40          | 20.15%         | 3.74%           | 100%        | 42.93%        | 7.04                   | 3.84                 | 1,839,701   |

## توضیحات

کنترل دسترسی سیاست‌ها را اجرا می‌کند تا کاربران تنها به منابع و عملکردهایی دسترسی داشته باشند که مجاز هستند. شکست در این کنترل‌ها معمولاً منجر به افشای غیرمجاز اطلاعات، تغییر یا حذف داده‌ها، یا اجرای عملکرد کسب‌وکار خارج از مجوز کاربر می‌شود.

### آسیب‌پذیری‌های رایج
- نقض اصل حداقل دسترسی (Deny by Default)
- دور زدن کنترل‌ها با تغییر URL، پارامترها، صفحات HTML یا درخواست‌های API
- اجازه دسترسی یا ویرایش حساب دیگران (IDOR)
- API بدون کنترل دسترسی برای متدهای POST، PUT و DELETE
- افزایش سطح دسترسی بدون مجوز
- دستکاری Metadata (JWT، کوکی‌ها، hidden field)
- تنظیم نادرست CORS
- Force Browsing: حدس URL صفحات احراز هویت‌شده یا صفحات با دسترسی بالا

### روش‌های پیشگیری
- اعمال Deny by default برای تمام منابع به جز بخش‌های عمومی
- پیاده‌سازی کنترل دسترسی متمرکز و قابل استفاده مجدد
- مدل‌سازی دسترسی بر اساس مالکیت رکورد
- اعمال محدودیت‌های منطقی کسب‌وکار از طریق Domain Models
- غیرفعال کردن Directory Listing و حذف فایل‌های متادیتا و پشتیبان
- ثبت Log شکست‌های دسترسی و ارسال هشدار
- اعمال Rate Limit روی APIها
- ابطال شناسه‌های جلسه و تعیین زمان انقضای کوتاه برای JWTهای Stateless
- استفاده از toolkitها یا الگوهای معتبر برای کنترل دسترسی Declarative
- افزودن تست‌های کنترل دسترسی در Unit و Integration Tests

### نمونه سناریوهای حمله
**سناریو ۱:** مهاجم پارامتر acct را تغییر داده و به حساب هر کاربری دسترسی پیدا می‌کند.  
**سناریو ۲:** مهاجم URLهای مدیریتی را هدف قرار می‌دهد. اگر یک کاربر معمولی بتواند صفحات ادمین را ببیند یا بدون احراز هویت وارد شود، نقص امنیتی ایجاد می‌شود.  
**سناریو ۳:** تمام کنترل‌ها در فرانت‌اند پیاده شده‌اند. مهاجم می‌تواند مستقیماً درخواست‌ها را به سرور ارسال کند و کنترل‌های دسترسی را دور بزند.

### لیست CWEهای مرتبط

- [CWE-22](https://cwe.mitre.org/data/definitions/22.html) محدودیت نادرست مسیر به دایرکتوری مجاز (Path Traversal)  
- [CWE-23](https://cwe.mitre.org/data/definitions/23.html) مسیر نسبی نادرست (Relative Path Traversal)  
- [CWE-36](https://cwe.mitre.org/data/definitions/36.html) مسیر مطلق نادرست (Absolute Path Traversal)  
- [CWE-59](https://cwe.mitre.org/data/definitions/59.html) حل لینک نادرست قبل از دسترسی به فایل (Link Following)  
- [CWE-61](https://cwe.mitre.org/data/definitions/61.html) دنبال کردن لینک نمادین UNIX (Symlink)  
- [CWE-65](https://cwe.mitre.org/data/definitions/65.html) لینک سخت Windows  
- [CWE-200](https://cwe.mitre.org/data/definitions/200.html) افشای اطلاعات حساس به کاربران یا نقش‌های غیرمجاز  
- [CWE-201](https://cwe.mitre.org/data/definitions/201.html) افشای اطلاعات حساس از طریق داده‌های ارسال‌شده  
- [CWE-219](https://cwe.mitre.org/data/definitions/219.html) ذخیره فایل با داده حساس زیر Web Root  
- [CWE-276](https://cwe.mitre.org/data/definitions/276.html) مجوزهای پیش‌فرض نادرست  
- [CWE-281](https://cwe.mitre.org/data/definitions/281.html) نگهداری نادرست مجوزها  
- [CWE-282](https://cwe.mitre.org/data/definitions/282.html) مدیریت مالکیت نادرست  
- [CWE-283](https://cwe.mitre.org/data/definitions/283.html) مالکیت تأییدنشده  
- [CWE-284](https://cwe.mitre.org/data/definitions/284.html) کنترل دسترسی نادرست  
- [CWE-285](https://cwe.mitre.org/data/definitions/285.html) مجوزدهی نادرست  
- [CWE-352](https://cwe.mitre.org/data/definitions/352.html) جعل درخواست بین‌سایتی (CSRF)  
- [CWE-359](https://cwe.mitre.org/data/definitions/359.html) افشای اطلاعات شخصی خصوصی به کاربران غیرمجاز  
- [CWE-377](https://cwe.mitre.org/data/definitions/377.html) فایل موقت ناامن  
- [CWE-379](https://cwe.mitre.org/data/definitions/379.html) ایجاد فایل موقت در دایرکتوری با مجوزهای ناامن  
- [CWE-402](https://cwe.mitre.org/data/definitions/402.html) انتقال منابع خصوصی به حوزه جدید (Resource Leak)  
- [CWE-424](https://cwe.mitre.org/data/definitions/424.html) محافظت نادرست مسیر جایگزین  
- [CWE-425](https://cwe.mitre.org/data/definitions/425.html) درخواست مستقیم (Forced Browsing)  
- [CWE-441](https://cwe.mitre.org/data/definitions/441.html) پراکسی یا واسطه ناخواسته (Confused Deputy)  
- [CWE-497](https://cwe.mitre.org/data/definitions/497.html) افشای اطلاعات حساس سیستم به حوزه کنترل غیرمجاز  
- [CWE-538](https://cwe.mitre.org/data/definitions/538.html) وارد کردن اطلاعات حساس به فایل یا دایرکتوری قابل دسترس خارجی  
- [CWE-540](https://cwe.mitre.org/data/definitions/540.html) گنجاندن اطلاعات حساس در کد منبع  
- [CWE-548](https://cwe.mitre.org/data/definitions/548.html) افشای اطلاعات از طریق فهرست‌گذاری دایرکتوری  
- [CWE-552](https://cwe.mitre.org/data/definitions/552.html) فایل‌ها یا دایرکتوری‌های قابل دسترسی به طرف‌های خارجی  
- [CWE-566](https://cwe.mitre.org/data/definitions/566.html) دورزدن مجوز از طریق کلید اولیه SQL کنترل‌شده توسط کاربر  
- [CWE-601](https://cwe.mitre.org/data/definitions/601.html) هدایت URL به سایت غیرقابل اعتماد (Open Redirect)  
- [CWE-615](https://cwe.mitre.org/data/definitions/615.html) گنجاندن اطلاعات حساس در نظرات کد منبع  
- [CWE-639](https://cwe.mitre.org/data/definitions/639.html) دورزدن مجوز از طریق کلید کنترل‌شده توسط کاربر  
- [CWE-668](https://cwe.mitre.org/data/definitions/668.html) افشای منابع به حوزه نادرست  
- [CWE-732](https://cwe.mitre.org/data/definitions/732.html) تخصیص مجوز نادرست برای منابع حیاتی  
- [CWE-749](https://cwe.mitre.org/data/definitions/749.html) متد یا تابع خطرناک افشا شده  
- [CWE-862](https://cwe.mitre.org/data/definitions/862.html) مجوزدهی گم‌شده  
- [CWE-863](https://cwe.mitre.org/data/definitions/863.html) مجوزدهی نادرست  
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html) جعل درخواست سمت سرور (SSRF)  
- [CWE-922](https://cwe.mitre.org/data/definitions/922.html) ذخیره نادرست اطلاعات حساس  
- [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) کوکی حساس با ویژگی SameSite نادرست  

### منابع
- [OWASP Top 10:2025 - A01 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)  
- [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org)  
- [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS)  
- [CWE List](https://cwe.mitre.org/data/index.html)
