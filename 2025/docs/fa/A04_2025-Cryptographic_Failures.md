# A04:2025 Cryptographic Failures (شکست‌های رمزنگاری)

## Background  
این ریسک در سال ۲۰۲۵ دو رتبه سقوط کرده و اکنون در جایگاه **شماره ۴** قرار دارد. این دسته شامل خطاهایی است که به دلیل عدم استفاده از رمزنگاری، استفاده از رمزنگاری ضعیف، نشت کلیدهای رمزنگاری، یا اشتباهات مرتبط با تولید اعداد تصادفی رخ می‌دهند. سه مورد از رایج‌ترین CWEها در این ریسک عبارت‌اند از:  
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm  
- [CWE-331](https://cwe.mitre.org/data/definitions/331.html): Insufficient Entropy  
- [CWE-1241](https://cwe.mitre.org/data/definitions/1241.html): Use of Predictable Algorithm in Random Number Generator  
- [CWE-338](https://cwe.mitre.org/data/definitions/338.html): Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)  

---

## جدول امتیازدهی

| CWEs نگاشت‌شده | بیشترین نرخ وقوع | میانگین نرخ وقوع | بیشترین پوشش | میانگین پوشش | میانگین امتیاز Exploit (وزن‌دار) | میانگین امتیاز Impact (وزن‌دار) | کل وقوع‌ها | کل CVEها |
|---------------|------------------|------------------|----------------|----------------|-------------------------------|-----------------------------|----------------|-----------|
| 32            | 13.77%           | 3.80%            | 100.00%        | 47.74%         | 7.23                          | 3.90                        | 1,665,348     | 2,185 |

---

## توضیحات

رمزنگاری باید برای داده‌های حساس چه در حالت ذخیره (at rest) و چه در حالت انتقال (in transit) به درستی پیاده‌سازی شود. خطاهای رمزنگاری می‌توانند منجر به پیش‌بینی توکن‌ها، جعل نشست‌ها، شکستن رمزگذاری، یا بازیابی کلیدهای خصوصی شوند.

### خطرات و اشتباهات معمول

- استفاده از الگوریتم‌ها یا پروتکل‌های قدیمی یا ضعیف  
- کلیدهای پیش‌فرض، ضعیف، دوباره‌استفاده‌شده یا عدم مدیریت کلید و چرخش  
- ذخیره کلیدها یا داده حساس رمزنگاری‌شده در مخازن کد  
- عدم اجبار رمزنگاری (TLS / HTTPS)  
- نادیده گرفتن یا اشتباه در تولید IV یا nonce  
- استفاده از توابع هش منسوخ یا padding الگوریتمی منسوخ (MD5، SHA‑1، PKCS#1 v1.5)  
- استفاده از PRNG ضعیف یا قابل پیش‌بینی  
- عدم استفاده از رمزنگاری احراز هویت‌شده  
- امکان downgrade یا دور زدن پروتکل رمزنگاری  
- پیام‌های خطای رمزنگاری یا کانال‌های جانبی قابل سوءاستفاده  

---

## چگونه جلوگیری کنیم

- داده‌های حساس را طبقه‌بندی و برچسب‌گذاری کنید  
- کلیدها را در HSM یا سرویس ابری امن ذخیره کنید  
- از پیاده‌سازی‌های معتبر الگوریتم‌های رمزنگاری استفاده کنید  
- داده‌های حساس را فقط در صورت نیاز ذخیره کنید؛ حذف یا توکنیزه نمایید  
- رمزنگاری برای داده در حال انتقال و ذخیره را اعمال کنید  
- از پروتکل‌های بدون رمزگذاری مانند FTP و SMTP استفاده نکنید  
- توابع هش امن با نمک و تطبیقی استفاده شود (Argon2, bcrypt, scrypt, PBKDF2-HMAC-SHA-256)  
- IV/nonce باید صحیح تولید و دوباره استفاده نشود  
- از رمزنگاری احراز هویت‌شده استفاده شود  
- توابع منسوخ یا paddingهای قدیمی استفاده نشود  
- آماده‌سازی برای رمزنگاری پساکوانتومی (PQC)  

---

## مثال‌های سناریو حمله

**سناریو #1**: سایت TLS را برای همه صفحات اعمال نمی‌کند یا TLS ضعیف پیکربندی شده — مهاجم اتصال را downgrade می‌کند، درخواست‌ها را رهگیری و کوکی نشست را دزدی می‌کند ([OWASP](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/))  

**سناریو #2**: پایگاه داده رمزهای عبور هش ساده یا بدون نمک استفاده می‌کند، مهاجم دیتابیس را استخراج و هش‌ها را بازیابی می‌کند ([OWASP](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/))  

---

## لیست CWEهای مرتبط

- [CWE-261](https://cwe.mitre.org/data/definitions/261.html) Weak Encoding for Password  
- [CWE-296](https://cwe.mitre.org/data/definitions/296.html) Improper Following of a Certificate’s Chain of Trust  
- [CWE-319](https://cwe.mitre.org/data/definitions/319.html) Cleartext Transmission of Sensitive Information  
- [CWE-320](https://cwe.mitre.org/data/definitions/320.html) Key Management Errors (Prohibited)  
- [CWE-321](https://cwe.mitre.org/data/definitions/321.html) Use of Hard‑coded Cryptographic Key  
- [CWE-322](https://cwe.mitre.org/data/definitions/322.html) Key Exchange Without Entity Authentication  
- [CWE-323](https://cwe.mitre.org/data/definitions/323.html) Reusing a Nonce or Key Pair in Encryption  
- [CWE-324](https://cwe.mitre.org/data/definitions/324.html) Use of a Key Past its Expiration Date  
- [CWE-325](https://cwe.mitre.org/data/definitions/325.html) Missing Required Cryptographic Step  
- [CWE-326](https://cwe.mitre.org/data/definitions/326.html) Inadequate Encryption Strength  
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Broken or Risky Cryptography  
- [CWE-328](https://cwe.mitre.org/data/definitions/328.html) Reversible One‑Way Hash  
- [CWE-329](https://cwe.mitre.org/data/definitions/329.html) Not Using a Random IV with CBC Mode  
- [CWE-330](https://cwe.mitre.org/data/definitions/330.html) Use of Insufficiently Random Values  
- [CWE-331](https://cwe.mitre.org/data/definitions/331.html) Insufficient Entropy  
- [CWE-332](https://cwe.mitre.org/data/definitions/332.html) Insufficient Entropy in PRNG  
- [CWE-334](https://cwe.mitre.org/data/definitions/334.html) Small Space of Random Values  
- [CWE-335](https://cwe.mitre.org/data/definitions/335.html) Incorrect Usage of Seeds in PRNG  
- [CWE-336](https://cwe.mitre.org/data/definitions/336.html) Same Seed in PRNG  
- [CWE-337](https://cwe.mitre.org/data/definitions/337.html) Predictable Seed in PRNG  
- [CWE-338](https://cwe.mitre.org/data/definitions/338.html) Cryptographically Weak PRNG  
- [CWE-340](https://cwe.mitre.org/data/definitions/340.html) Predictable Numbers or IDs  
- [CWE-342](https://cwe.mitre.org/data/definitions/342.html) Predictable Values Derived from Previous Values  
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html) Improper Verification of Cryptographic Signature  
- [CWE-523](https://cwe.mitre.org/data/definitions/523.html) Unprotected Transport of Credentials  
- [CWE-757](https://cwe.mitre.org/data/definitions/757.html) Weak Algorithm Choice in Negotiation  
- [CWE-759](https://cwe.mitre.org/data/definitions/759.html) One-way Hash Without Salt  
- [CWE-760](https://cwe.mitre.org/data/definitions/760.html) One-way Hash with Predictable Salt  
- [CWE-780](https://cwe.mitre.org/data/definitions/780.html) RSA Without OAEP  
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) Password Hashing With Insufficient Work Factor  
- [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) Cryptographic Primitive with Risky Implementation  
- [CWE-1241](https://cwe.mitre.org/data/definitions/1241.html) Predictable Algorithm in RNG  

---

## منابع

- [OWASP Top 10:2025 – A04 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)  
- [OWASP Proactive Controls: C2 – Use Cryptography to Protect Data](https://owasp.org/www-project-proactive-controls/v4/)  
- [OWASP ASVS – Cryptography & Secure Communication & Data Protection (V11, V12, V14)](https://owasp.org/www-project-application-security-verification-standard/)  
- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: Encrypted Storage](https://cheatsheetseries.owasp.org/cheatsheets/Encrypted_Storage_Cheat_Sheet.html)  
- [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)  
- [OWASP Testing Guide: Weak Cryptography](https://owasp.org/www-project-web-security-testing-guide/)  
- [ENISA: Roadmap for Post-Quantum Cryptography](https://www.enisa.europa.eu/publications/post-quantum-cryptography)  
- [NIST: Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
