# A07:2025 Authentication Failures

## پس‌زمینه
Authentication Failures موقعیت خود را در رتبه #7 حفظ کرده و نام آن کمی تغییر کرده تا دقیق‌تر منعکس‌کننده ۳۶ CWE در این دسته باشد. با وجود بهره‌مندی از فریم‌ورک‌های استاندارد، این دسته از سال ۲۰۲۱ رتبه خود را حفظ کرده است.

CWEهای مهم شامل CWE-259: Use of Hard-coded Password، CWE-297: Improper Validation of Certificate with Host Mismatch، CWE-287: Improper Authentication، CWE-384: Session Fixation، و CWE-798: Use of Hard-coded Credentials می‌شوند.

## جدول امتیازدهی
| تعداد CWEهای نگاشت‌شده | بیشترین نرخ بروز | میانگین نرخ بروز | بیشترین پوشش | میانگین پوشش | میانگین امتیاز بهره‌برداری | میانگین امتیاز تأثیر | تعداد کل رخدادها |
|------------------------|----------------|-----------------|----------------|----------------|---------------------------|--------------------|----------------|
| 36                     | 15.80%         | 2.92%           | 100.00%        | 37.14%         | 7.69                      | 4.44               | 1,120,673      |

## توضیحات
این آسیب‌پذیری زمانی رخ می‌دهد که مهاجم بتواند سیستم را فریب دهد تا یک کاربر نامعتبر یا اشتباه را به عنوان معتبر بشناسد.

یک برنامه ممکن است آسیب‌پذیری احراز هویت داشته باشد اگر:

- اجازه حملات خودکار مثل credential stuffing را بدهد، جایی که مهاجم از لیست نام‌های کاربری و رمز عبور لو رفته استفاده می‌کند. این حملات اخیراً شامل hybrid password attacks یا password spray attacks نیز شده‌اند.  
- اجازه brute force یا سایر حملات اسکریپتی را بدهد که به سرعت مسدود نمی‌شوند.  
- از رمزهای پیش‌فرض، ضعیف یا شناخته‌شده استفاده کند، مانند "Password1" یا کاربر "admin" با رمز "admin".  
- کاربران بتوانند با credentials قبلاً لو رفته حساب جدید بسازند.  
- فرآیندهای بازیابی رمز ضعیف یا ناکارآمد داشته باشد، مانند پاسخ‌های مبتنی بر دانش (knowledge-based answers).  
- رمزها را به صورت plain text، رمزگذاری شده یا هش ضعیف ذخیره کند.  
- MFA را به درستی پیاده‌سازی نکرده باشد یا fallback ضعیف برای MFA داشته باشد.  
- شناسه نشست (session ID) را در URL، hidden field یا مکان ناامن دیگر افشا کند.  
- همان شناسه نشست را پس از ورود مجدد استفاده کند.  
- نشست کاربر یا توکن‌های احراز هویت (خصوصاً SSO) را هنگام logout یا عدم فعالیت به درستی باطل نکند.

## چگونه جلوگیری کنیم
- MFA را پیاده‌سازی و اجباری کنید تا credential stuffing، brute force و reuse credentials جلوگیری شود.  
- استفاده از password manager را تشویق کنید.  
- هرگز با credentials پیش‌فرض منتشر یا مستقر نکنید، خصوصاً برای کاربران admin.  
- بررسی کنید که رمزها در برابر لیست بدترین رمزها مقاوم باشند (top 10,000 worst passwords).  
- در ایجاد حساب جدید یا تغییر رمز، از لیست credentials لو رفته اعتبارسنجی کنید (مثلاً [haveibeenpwned.com](https://haveibeenpwned.com)).  
- سیاست طول و پیچیدگی رمز را مطابق NIST 800-63b بخش 5.1.1 اعمال کنید.  
- از کاربران نخواهید رمزها را به‌صورت اجباری بچرخانند مگر در صورت شک به نفوذ.  
- مسیرهای ثبت‌نام و بازیابی credential را در برابر account enumeration سخت کنید (استفاده از پیام یکسان برای تمام نتایج).  
- تلاش‌های ورود ناموفق را محدود یا به تدریج تأخیر دهید، اما مراقب نباشید که DoS ایجاد شود.  
- از server-side session manager امن استفاده کنید که پس از login شناسه نشست جدید با entropy بالا ایجاد کند.  
- شناسه نشست در URL نباشد، در cookie امن ذخیره شود و پس از logout یا timeout باطل شود.  
- اگر ممکن است، از سیستم آماده و معتبر برای مدیریت authentication، identity و session استفاده کنید تا ریسک منتقل شود.

## نمونه سناریوهای حمله
**سناریو #1:**  
Credential stuffing: مهاجمان از لیست‌های نام کاربری و رمز استفاده می‌کنند و اخیراً با تغییرات انسانی مانند افزایش اعداد یا تغییر سال‌ها، حملات hybrid credential یا password spray انجام می‌دهند. در صورت نبود defenses، برنامه می‌تواند به oracle رمز تبدیل شود و دسترسی غیرمجاز ایجاد کند.

**سناریو #2:**  
اکثر حملات موفق به دلیل تکیه تنها بر رمز اتفاق می‌افتد. سیاست‌های قدیمی rotation و complexity باعث می‌شود کاربران رمزهای ضعیف یا تکراری استفاده کنند. توصیه می‌شود این روش‌ها متوقف و MFA اجباری شود.

**سناریو #3:**  
Timeout و logout صحیح جلسات پیاده‌سازی نشده است. کاربر روی کامپیوتر عمومی مرورگر را می‌بندد بدون logout. اگر SSO قابل logout نباشد، مهاجم می‌تواند پس از کاربر وارد حساب شود.

## منابع (References)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)  
- [OWASP Secure Coding Practices](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_Practices_Checklist.html)  

## لیست CWEهای مرتبط (List of Mapped CWEs)
- [CWE-258](https://cwe.mitre.org/data/definitions/258.html) Empty Password in Configuration File  
- [CWE-259](https://cwe.mitre.org/data/definitions/259.html) Use of Hard-coded Password  
- [CWE-287](https://cwe.mitre.org/data/definitions/287.html) Improper Authentication  
- [CWE-288](https://cwe.mitre.org/data/definitions/288.html) Authentication Bypass Using an Alternate Path or Channel  
- [CWE-289](https://cwe.mitre.org/data/definitions/289.html) Authentication Bypass by Alternate Name  
- [CWE-290](https://cwe.mitre.org/data/definitions/290.html) Authentication Bypass by Spoofing  
- [CWE-291](https://cwe.mitre.org/data/definitions/291.html) Reliance on IP Address for Authentication  
- [CWE-293](https://cwe.mitre.org/data/definitions/293.html) Using Referer Field for Authentication  
- [CWE-294](https://cwe.mitre.org/data/definitions/294.html) Authentication Bypass by Capture-replay  
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) Improper Certificate Validation  
- [CWE-297](https://cwe.mitre.org/data/definitions/297.html) Improper Validation of Certificate with Host Mismatch  
- [CWE-298](https://cwe.mitre.org/data/definitions/298.html) Improper Validation of Certificate with Host Mismatch  
- [CWE-299](https://cwe.mitre.org/data/definitions/299.html) Improper Validation of Certificate with Host Mismatch  
- [CWE-300](https://cwe.mitre.org/data/definitions/300.html) Channel Accessible by Non-Endpoint  
- [CWE-302](https://cwe.mitre.org/data/definitions/302.html) Authentication Bypass by Assumed-Immutable Data  
- [CWE-303](https://cwe.mitre.org/data/definitions/303.html) Incorrect Implementation of Authentication Algorithm  
- [CWE-304](https://cwe.mitre.org/data/definitions/304.html) Missing Critical Step in Authentication  
- [CWE-305](https://cwe.mitre.org/data/definitions/305.html) Authentication Bypass by Primary Weakness  
- [CWE-306](https://cwe.mitre.org/data/definitions/306.html) Missing Authentication for Critical Function  
- [CWE-307](https://cwe.mitre.org/data/definitions/307.html) Improper Restriction of Excessive Authentication Attempts  
- [CWE-308](https://cwe.mitre.org/data/definitions/308.html) Use of Single-factor Authentication  
- [CWE-309](https://cwe.mitre.org/data/definitions/309.html) Use of Password System for Primary Authentication  
- [CWE-346](https://cwe.mitre.org/data/definitions/346.html) Origin Validation Error  
- [CWE-350](https://cwe.mitre.org/data/definitions/350.html) Reliance on Reverse DNS Resolution for a Security-Critical Action  
- [CWE-384](https://cwe.mitre.org/data/definitions/384.html) Session Fixation  
- [CWE-521](https://cwe.mitre.org/data/definitions/521.html) Weak Password Requirements  
- [CWE-613](https://cwe.mitre.org/data/definitions/613.html) Insufficient Session Expiration  
- [CWE-620](https://cwe.mitre.org/data/definitions/620.html) Unverified Password Change  
- [CWE-640](https://cwe.mitre.org/data/definitions/640.html) Weak Password Recovery Mechanism for Forgotten Password  
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Use of Hard-coded Credentials  
- [CWE-940](https://cwe.mitre.org/data/definitions/940.html) Improper Verification of Source of a Communication Channel  
- [CWE-941](https://cwe.mitre.org/data/definitions/941.html) Incorrectly Specified Destination in a Communication Channel  
- [CWE-1390](https://cwe.mitre.org/data/definitions/1390.html) Weak Authentication  
- [CWE-1391](https://cwe.mitre.org/data/definitions/1391.html) Use of Weak Credentials  
- [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) Use of Default Credentials  
- [CWE-1393](https://cwe.mitre.org/data/definitions/1393.html) Use of Default Password
