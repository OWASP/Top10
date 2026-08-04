# به OWASP Security Top 10 – 2025 خوش آمدید!

از همه‌ی دوستانی که در نظرسنجی مشارکت کردند و داده‌ها و دیدگاه‌های ارزشمندشان را در اختیار ما گذاشتند، صمیمانه تشکر می‌کنیم. بدون حضور و همراهی شما، تهیه‌ی این نسخه ممکن نبود. قدردان‌تان هستیم.

---

## معرفی OWASP Top 10:2025

- **A01:2025 - Broken Access Control**  
- **A02:2025 - Security Misconfiguration**  
- **A03:2025 - Software Supply Chain Failures**  
- **A04:2025 - Cryptographic Failures**  
- **A05:2025 - Injection**  
- **A06:2025 - Insecure Design**  
- **A07:2025 - Authentication Failures**  
- **A08:2025 - Software or Data Integrity Failures**  
- **A09:2025 - Logging & Alerting Failures**  
- **A10:2025 - Mishandling of Exceptional Conditions**

---

## تغییرات Top 10 در نسخه 2025

در نسخه 2025 دو دسته جدید اضافه شده و یک مورد نیز ادغام شده است.  
تلاش شده تمرکز بر ریشه‌های اصلی آسیب‌پذیری‌ها حفظ شود. ایجاد ده دسته کاملاً مجزا و بدون همپوشانی عملاً غیرممکن است.

### نگاشت دسته‌ها

- **A01:2025 Broken Access Control**  
  جایگاه نخست، جدی‌ترین ریسک امنیتی. میانگین ۳.۷۳٪ برنامه‌ها شامل یکی از ۴۰ CWE مرتبط. SSRF نیز در این دسته ادغام شده است.

- **A02:2025 Security Misconfiguration**  
  از رتبه ۵ (۲۰۲۱) به رتبه ۲ (۲۰۲۵) صعود کرده است. ۳٪ برنامه‌ها دست‌کم یکی از ۱۶ CWE این دسته را دارند.

- **A03:2025 Software Supply Chain Failures**  
  توسعه‌یافته از A06:2021. دامنه گسترده ضعف‌ها در اکوسیستم وابستگی‌های نرم‌افزار. اثرگذاری بالا با تعداد CWE کم.

- **A04:2025 Cryptographic Failures**  
  از رتبه ۲ به ۴ سقوط کرده است. ۳.۸٪ برنامه‌ها حداقل یکی از ۳۲ CWE مرتبط را دارند. معمولاً منجر به افشای داده‌های حساس یا نفوذ می‌شود.

- **A05:2025 Injection**  
  دو رتبه کاهش، جایگاه پنجم. شامل Cross-Site Scripting و SQL Injection. XSS شیوع بیشتر، SQL Injection اثرگذاری بالاتر.

- **A06:2025 Insecure Design**  
  از رتبه ۴ به ۶ کاهش. از سال ۲۰۲۱ معرفی شده، تمرکز بر مدل‌سازی تهدید و طراحی امن.

- **A07:2025 Authentication Failures**  
  جایگاه هفتم، نام به‌روزرسانی جزئی. شامل ۳۶ CWE. فریم‌ورک‌های استاندارد باعث کاهش خطاها شده‌اند.

- **A08:2025 Software or Data Integrity Failures**  
  رتبه هشتم، تمرکز بر مرزهای اعتماد و اعتبارسنجی نرم‌افزار، کد و داده‌ها.

- **A09:2025 Logging & Alerting Failures**  
  جایگاه نهم، نام به‌روزرسانی جزئی برای تأکید بر اهمیت هشداردهی.

- **A10:2025 Mishandling of Exceptional Conditions**  
  جدید، شامل ۲۴ CWE، تمرکز بر مدیریت نادرست خطاها، خطاهای منطقی و شرایط غیرعادی سیستم.

---

## متدولوژی (Methodology)

نسخه جدید OWASP Top 10 هنوز بر داده‌ها تکیه دارد، اما نه صرفاً عددمحور.  
۱۲ دسته بر اساس داده‌های جمع‌آوری‌شده رتبه‌بندی شدند و دو دسته بر اساس نتایج نظرسنجی جامعه برجسته شدند.

### نحوه استفاده از داده‌ها برای انتخاب دسته‌ها

- داده‌های CVE برای سنجش Exploitability و Technical Impact استفاده شدند.  
- ابزار OWASP Dependency Check امتیازهای CVSS مرتبط را استخراج و بر اساس CWE گروه‌بندی کرده است.  
- CVEها دارای CVSSv2 و برخی CVSSv3 و CVSSv4 هستند. میانگین Exploit و Impact بر اساس گروه‌بندی CWEها و وزن‌دهی نسخه‌ها محاسبه شده است.

### چرا از نظرسنجی جامعه استفاده می‌کنیم؟

- داده‌ها محدود به مواردی هستند که ابزارهای خودکار می‌توانند آزمایش کنند.  
- برخی ریسک‌ها هنوز در داده‌ها قابل مشاهده نیستند.  
- تنها ۸ دسته بر اساس داده‌ها انتخاب شدند، ۲ دسته دیگر از طریق نظرسنجی جامعه تعیین شدند.

---

## قدردانی از تمامی مشارکت‌کنندگان

سازمان‌های زیر (و چندین اهداکننده ناشناس) داده‌های بیش از ۲.۸ میلیون برنامه را ارائه کردند:

- Accenture (Prague)  
- Anonymous (multiple)  
- Bugcrowd  
- Contrast Security  
- CyptoNet Labs  
- Intuitor SoftTech Services  
- Orca Security  
- Probley  
- Semgrep  
- Sonar  
- usd AG  
- Veracode  
- Wallarm  

---

## نویسندگان اصلی

- Andrew van der Stock — X: @vanderaj  
- Brian Glas — X: @infosecdad  
- Neil Smithline — X: @appsecneil  
- Tanya Janca — X: @shehackspurple  
- Torsten Gigler — Mastodon: @torsten_gigler@infosec.exchange  

نسخه کاندید انتشار (Release Candidate) در تاریخ ۶ نوامبر ۲۰۲۵ منتشر شد.

---

## لینک‌های پروژه

- [Homepage](https://owasp.org/)  
- [GitHub Repository](https://github.com/OWASP)
