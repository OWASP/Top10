# A09:2025 Logging & Alerting Failures

## پس‌زمینه
Logging & Alerting Failures در رتبه #9 باقی مانده است و نام آن کمی تغییر کرده تا عملکرد alerting و نیاز به اقدام در رویدادهای ثبت‌شده را بهتر نشان دهد. این دسته همیشه در داده‌ها کم‌نمایش است و با 723 CVE نمایه بسیار محدودی دارد، اما اهمیت بالایی در دیدپذیری، پاسخ سریع به حوادث و forensic دارد. CWEهای شاخص شامل CWE-117: Improper Output Neutralization for Logs، CWE-532: Insertion of Sensitive Information into Log File و CWE-778: Insufficient Logging می‌شوند.

## جدول امتیازدهی
| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|------------------------|----------------|-----------------|----------------|----------------|---------------------------|--------------------|----------------|
| 5                      | 11.33%         | 3.91%           | 85.96%         | 46.48%         | 7.19                      | 2.65               | 260,288        |

## توضیحات
عدم ثبت و پایش رویدادها، و فقدان alerting مناسب، تشخیص حملات و واکنش به حوادث را دشوار می‌کند. نمونه موارد این ضعف‌ها شامل موارد زیر است:

- رویدادهای قابل audit مانند login، failed login و تراکنش‌های حساس، یا ثبت نمی‌شوند یا ناقص ثبت می‌شوند.  
- پیام‌های خطا و warning ناکافی، مبهم یا غیرقابل استفاده هستند.  
- صحت و یکپارچگی logs محافظت نمی‌شود و ممکن است tamper شود.  
- logs برنامه‌ها و APIها برای فعالیت‌های مشکوک پایش نمی‌شوند.  
- logs فقط به صورت محلی ذخیره شده و backup مناسب ندارند.  
- آستانه‌های مناسب alert و فرآیند escalation موجود نیست یا کارآمد نیست.  
- تست‌های penetration و ابزارهای DAST (مانند Burp یا ZAP) هشدار تولید نمی‌کنند.  
- سیستم قادر به تشخیص و alert به حملات فعال در زمان واقعی یا نزدیک به واقعی نیست.  
- logging و alerting ممکن است اطلاعات حساس (PII/PHI) را به مهاجم یا کاربر نشان دهد.  
- امکان injection یا حمله به سیستم‌های logging در صورت عدم کدگذاری صحیح وجود دارد.  
- خطاها و شرایط استثنایی مدیریت نمی‌شوند و بنابراین سیستم از وقوع مشکل مطلع نمی‌شود.  
- use-caseهای لازم برای alert ناقص یا قدیمی هستند.  
- وجود false positive زیاد باعث می‌شود alertهای مهم نادیده گرفته شوند.

## چگونه جلوگیری کنیم
- تمام شکست‌ها و رویدادهای مربوط به login، access control و server-side validation را ثبت کنید و context کافی برای forensic داشته باشید.  
- همه بخش‌های نرم‌افزار که کنترل امنیتی دارند، چه موفق و چه شکست‌خورده، log شوند.  
- فرمت logها باید قابل استفاده برای log management باشد.  
- داده‌های log به درستی کدگذاری شوند تا از injection جلوگیری شود.  
- تمام تراکنش‌ها باید audit trail با integrity controls داشته باشند، مانند append-only tables.  
- تراکنش‌هایی که خطا می‌دهند باید rollback شوند و always fail closed باشند.  
- در صورت رفتار مشکوک کاربران یا برنامه، alert ایجاد کنید.  
- تیم‌های DevSecOps و امنیت use-case و playbookهای موثر برای alert ایجاد کنند.  
- از honeytokenها برای شناسایی دسترسی غیرمجاز استفاده کنید.  
- تحلیل رفتار و هوش مصنوعی می‌تواند نرخ false positive را کاهش دهد.  
- برنامه incident response و recovery مانند NIST 800-61r2 را ایجاد و آموزش دهید.

## ابزارها و محصولات مفید
- OWASP ModSecurity Core Rule Set  
- ELK Stack (Elasticsearch, Logstash, Kibana)  
- ابزارهای observability تجاری برای پاسخ سریع یا بلوکه کردن حملات  

## نمونه سناریوهای حمله
**سناریو #1:**  
یک ارائه‌دهنده خدمات سلامت کودکان، نفوذ را تشخیص نداد و مهاجم به داده‌های حساس بیش از ۳.۵ میلیون کودک دسترسی پیدا کرد. به دلیل نبود logging و monitoring، این نفوذ می‌توانست از سال ۲۰۱۳ ادامه داشته باشد.

**سناریو #2:**  
یک شرکت هواپیمایی هندی دچار breach داده شد که بیش از ده سال اطلاعات مسافران شامل پاسپورت و کارت اعتباری را تحت تأثیر قرار داد. breach توسط یک cloud provider ثالث کشف شد.

**سناریو #3:**  
یک شرکت هواپیمایی اروپایی به دلیل ضعف‌های امنیتی پرداخت، بیش از ۴۰۰ هزار رکورد مشتری را از دست داد و جریمه ۲۰ میلیون پوندی شد.

## منابع (References)
- [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-logging-monitoring/)  
- [OWASP ASVS: V16 Security Logging and Error Handling](https://owasp.org/www-project-application-security-verification-standard/)  
- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)  
- [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://www.cisecurity.org/)  
- [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://www.cisecurity.org/)  
- [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://www.cisecurity.org/)  

## لیست CWEهای مرتبط (List of Mapped CWEs)
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html) Improper Output Neutralization for Logs  
- [CWE-221](https://cwe.mitre.org/data/definitions/221.html) Information Loss of Omission  
- [CWE-223](https://cwe.mitre.org/data/definitions/223.html) Omission of Security-relevant Information  
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html) Insertion of Sensitive Information into Log File  
- [CWE-778](https://cwe.mitre.org/data/definitions/778.html) Insufficient Logging
