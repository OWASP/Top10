# <div dir="rtl" align="right">A3:2017 افشای اطلاعات حساس</div>

| Threat agents/Attack vectors | Security Weakness | Impacts |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۲ | شیوع: ۳ : قابل کشف بودن: ۲ | تکنیکی: ۳ : Business ? |
| <div dir="rtl" align="right">مهاجم ها به جای به صورت مستقیم به خود رمز حمله کند، اقدام به سرقت کلیدها، اجرای حملات مردمیانی، یا سرقت اطلاعات رمز نشده سمت سرور یا کاربر، هنگام انتقال اطلاعات می‌کنند، برای مثال در مروررگر. حمله دستی به طور کلی مورد نیاز است. قبلا بانک های داده رمز عبور بازیابی شده میبایست توسط GPU ها (واحدهای پردازش گرافیکی) مورد حمله بروت فورس قرار می‌گرفت.</div> | <div dir="rtl" align="right"> در طول چند سال گذشته، این شایعترین حمله تأثیرگذار بوده است. شایع ترین اشتباه هم رمز نکردن اطلاعات حساس است. هنگامی‌که از رمزنگاری استفاده می‌شود، تولید و مدیریت کلید ضعیف، و الگوریتم ضعیف، استفاده از پروتکل و رمز مشترک، مخصوصا برای تکنیک های ذخیره سازی هشینگ رمزنگاری ضعیف است. برای اطلاعات در حال انتقال، ضعف های سمت سرور به راحتی قابل تشخیص هستند. اما تشخیص برای داده هایی که در داخل سرور ذخیره شده اند سخت است. </div> | <div dir="rtl" align="right">یک ضعف امنیتی اغلب تمام اطلاعاتی را که باید محافظت شوند را به خطر می‌اندازد. به طور معمول، این اطلاعات شامل اطلاعات شخصی حساس (PII) مانند سوابق بهداشتی، اعتبارنامه ها، اطلاعات شخصی و کارت های اعتباری است که اغلب نیاز به حفاظت بر اساس قوانین یا مقرراتی مانند GDPR اتحادیه اروپا یا قوانین حفظ حریم خصوصی محلی دارند.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب‌پذیر است؟</div>

<p dir="rtl" align="right">اولین نکته این است که نیازهای حفاظت از داده ها در هنگام انتقال و در حالت ذخیره تعیین شود. به عنوان مثال، گذرواژه‌ها، شماره کارت اعتباری، پرونده‌های بهداشتی، اطلاعات شخصی و اسرار تجاری، حفاظت بیشتری نیاز دارند، به ویژه اگر داده‌ها تحت قوانین حریم خصوصی قرار بگیرند، برای مثال مقررات حفاظت کلی اطلاعات اتحادیه اروپا (GDPR)، یا مقررات، مانند حفاظت از اطلاعات مالی مانند PCI Data Security Standard (PCI DSS)  برای چنین اطلاعاتی:</p>

<ul dir="rtl" align="right">
  <li>آیا داده ها بدون رمز شدن ارسال شده اند؟ این مربوط به پروتکل هایی مانند HTTP، SMTP و FTP است. به ویژه ترافیک اینترنتی خارجی خطرناک است. تمام ترافیک داخلی بین load balancer ها، وب سرورها، و یا سیستم هایback-end بایستی بررسی گردد.</li>
  <li>آیا اطلاعات حساس در متن آشکار ذخیره می‌شوند، از جمله در پشتیبان متن‌ها؟</li>
  <li>آیا الگوریتم‌های رمزنگاری قدیمی ‌یا ضعیف از پیش فرض یا کد قدیمی‌تر استفاده می‌کنند؟</li>
  <li>آیا کلید های رمزنگاری پیش فرض در حال استفاده، کلید های رمزنگاری ضعیف تولید شده یا در حال استفاده مجدد هستند، یا اینکه مدیریت کلید مناسب است؟</li>
  <li>آیا رمزگذاری اعمال شده است، به عنوان مثال آیا برای هر عامل کاربر (مرورگر) تمهیدات امنیتی اندیشیده شده است یا headers missing رخ می‌دهد؟ </li>
  <li>اگر عامل کاربر (مثلا برنامه کاربردی، سرویس پست الکترونیکی) گواهی سرور صحیحی را دریافت کند آیا آن را تأیید نمی‌کند؟</li>
</ul>

[Crypto (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [Data Protection (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection) and [SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications) ASVS را ببینید.

## <div dir="rtl" align="right">نحوه پیشگیری از حمله:</div>

<p dir="rtl" align="right">حداقل موارد زیر را دنبال کنید و به مراجع رجوع کنید: </p>

<ul dir="rtl" align="right">
  <li>داده های پردازش شده، ذخیره شده، و یا ارسال شده توسط یک برنامه را طبقه بندی کنیم. بر اساس قوانین حریم خصوصی، با توجه به الزامات قانونی یا نیازهای تجاری داده های حساس را شناسایی کنید. 
 </li>
  <li>طبق طبقه بندی، کنترل ها را اعمال کنید.</li>
  <li>در صورت عدم نیاز داده های حساس را ذخیره نکنید. در اسرع وقت آن را حذف کنید و یا از توافق PCI DSS برای علامتگذاری یا حتی ناقص سازی استفاده کنید. داده هایی که ذخیره نمی‌شوند نمی‌توانند سرقت شوند.</li>
  <li>اطمینان حاصل کنید که همه اطلاعات حساس در حالت ذخیره را رمزگذاری کرده‌اید.</li>
  <li>اطمینان حاصل کنید از الگوریتم های استاندارد، پروتکل ها و کلیدهای استاندارد به روز و قوی در جای خود استفاده می‌شود. از مدیریت کلید مناسب استفاده کنید.</li>
  <li>رمزگذاری تمام داده ها در حال انتقال با پروتکل های امن مانندTLS  با رمزهای محرمانه بدون نقص (PFS)، اولویت بندی رمز توسط سرور و پارامترهای امن انجام گردد. اعمال رمزگذاری را با استفاده از دستورالعمل هایی مانند HTTP Security Transport Strict Security (HSTS) انجام دهید.</li>
  <li>برای پاسخ هایی که حاوی اطلاعات حساس هستند، ذخیره سازی (Caching) غیرفعال شود. </li>
  <li>
    رمزهای عبور را با استفاده از توابع هش قوی قابل انطباق و هش به همراه سلت با یک عامل کار (عامل تاخیر) مانند <a href="https://www.cryptolux.org/index.php/Argon2">Argon2</a> , <a href="https://wikipedia.org/wiki/Scrypt">Scrypt</a> , <a href="https://wikipedia.org/wiki/Bcrypt">bcrypt</a> یا  <a href="https://wikipedia.org/wiki/PBKDF2">PBKDF2</a> ذخیره کنید.

    رمزهای عبور را با استفاده از توابع هش قوی منطبق و هش salting با یک عامل کار (عامل تاخیر) مانند <a href="https://www.cryptolux.org/index.php/Argon2">Argon2</a>،<a href="https://wikipedia.org/wiki/Scrypt">Scrypt</a> ، یا <a href="https://wikipedia.org/wiki/PBKDF2">PBKDF2</a> ذخیره کنید.</li>
  <li>به طور مستقل اثربخشی پیکربندی و تنظیمات را بررسی کنید.</li>
</ul>

## <div dir="rtl" align="right">نمونه‌ سناریوهای حمله</div>

<p dir="rtl" align="right"><strong>سناریو #1 :</strong>یک برنامه کاربردی شماره کارت های اعتباری را در یک پایگاه داده با استفاده از رمزگذاری خودکار پایگاه داده رمز می‌کند. در حالی که، در زمان دریافت، این داده ها به طور خودکار رمزگشایی می‌شوند، و به یک نقص تزریق SQL اجازه می‌هد شماره کارت های اعتباری را در حالت متن آشکار بازیابی کند.</p>

<p dir="rtl" align="right"><strong>سناریو #2 :</strong>یک سایت، TLSرا برای تمام صفحاتش استفاده نمی‌کند و یا از رمزنگاری ضعیف پشتیبانی می‌کند. مهاجم ترافیک شبکه را پایش می‎‌کند (به عنوان مثال در یک شبکه بی سیم نا امن)، اتصالات را از HTTPS  به HTTP تغییر می‌دهد، در‌خواستها را دستکاری می‌کند و کوکی نشست کاربر را سرقت می‌کند. مهاجم پس از آن از این کوکی استفاده می‌کند و نشست کاربر (احراز هویت شده) را دزدیده، به داده های شخصی کاربر دسترسی پیدا میکند یا آنها را تغییر می‌دهد. مهاجم به جای موارد بالا می‌توانند تمام داده های منتقل شده مانند دریافت کننده انتقال مالی را تغییر دهند.</p>

<p dir="rtl" align="right"><strong>سناریو #3 :</strong>پایگاه داده رمز عبور از هش های سلت نشده یا ساده برای ذخیره کلمه عبور همه استفاده می‌کند. یک نقص آپلود فایل به مهاجم اجازه می‌دهد تا پایگاه داده رمزهای عبور را بازیابی کند. تمام هش های سلت نشده را می‌توان با یک جدول رنگین کمان از هش های پیش محاسبه شده شکست. هش های تولید شده توسط توابع هش ساده یا سریع ممکن است توسط GPU ها شکسته شوند، حتی اگر از نوع سلت شده باشند.</p>

## <div dir="rtl" align="right">منابع</div>

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) and [Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
