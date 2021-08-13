# <div dir="rtl" align="right"> A2:2017 احراز هویت ناقص</div>

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۳ | شیوع: ۲ : قابل کشف بودن: ۲ | تکنیکی: ۳ : Business |
| <div dir="rtl" align="right">مهاجمان به صدها میلیون نام کاربری و رمز عبور معتبر جهت تشخیص هویت، به عنوان لیست حساب‌های مدیریتی پیش فرض، حمله جامع خودکار و ابزارهای حمله دیکشنری دسترسی دارند. حملات مدیریت نشست به خوبی درک می‌شود، به خصوص در رابطه با توکن های نشست غیرقابل انتظار.</div> | <div dir="rtl" align="right">رواج این حمله به علت نحوه طراحی و پیاده سازی اکثر کنترل کننده های هویت و دسترسی، بسیار گسترده است. مدیریت نشست، پایه‌ی احراز هویت و کنترل دسترسی است و در همه برنامه های کاربردی stateful وجود دارد.
مهاجمان می‌توانند شکست احراز هویت را با استفاده از راهکار دستی تشخیص دهند و با استفاده از ابزارهای خودکار با لیستی از پسوردها و حمله های دیکشنری از آنها سو استفاده کنند. </div> | <div dir="rtl" align="right">مهاجم تنها می‌تواند به تعداد محدودی از حساب ها یا یک حساب مدیر برای به خطر انداختن سیستم دسترسی پیدا کند. 
بسته به بستر برنامه کاربردی، این ممکن است منجر به پولشویی، کلاهبرداری امنیت اجتماعی و سرقت هویت شده یا اطلاعات محرمانه محافظت شده از نظر قانونی را افشا کند. </div> |

## <div dir="rtl" align="right">آیا برنامه کاربرد آسیب‌پذیر است؟</div>

<p dir="rtl" align="right">تأیید هویت کاربر، احراز هویت و مدیریت نشست برای حفاظت از حملات مرتبط با احراز هویت حیاتی است.</p>

<p dir="rtl" align="right">اگر برنامه کاربردی شامل موارد زیر باشد ضعف های آسیب‎‌پذیری وجود خواهند داشت:</p>

<ul dir="rtl" align="right">
 <li>اجازه حملات خودکار را به مهاجم بدهد. مانند حملات <a href="https://owasp.org/www-community/attacks/Credential_stuffing">جاسازی هویت</a>، که در آن مهاجم ، لیستی از نام‌های کاربری و کلمه عبور معتبر را در اختیار دارد.</li>
 <li>اجازه حملات خودکار رمز عبور یا حملات خودکار دیگر را بدهد. </li>
 <li>اجازه ثبت رمزهای عبور پیش فرض، ضعیف یا شناخته شده مانند "Password1 " یا admin / admin"" را بدهد. </li>
 <li>از فرآیندهای ضعیف یا ناکارآمد بازیابی یا فراموشی احراز هویت رمز، مانند "پاسخهای مبتنی بر دانش"، استفاده کند که امن نیستند.</li>
 <li>با استفاده از متن آشکار، رمزنگاری شده و یا رمزهای هش ضعیف شده استفاده کند <strong>(نگاه کنید به A3: ۲017-Sensitive Data Exposure)</strong>.</li>
 <li>از روش های احراز هویت چند مرحله‌ای جا افتاده یا ناکارآمد استفاده کند.  </li>
 <li>شناسه نشست در URL را افشا کند. (مثل URL Rewriting)  </li>
 <li>شناسه نشست پس از ورود موفق به سیستم، تغییر نکرده باشد. </li>
 <li>شناسه های نشست به درستی بی اعتبار نشوند. نشست های کاربر یا توکن های احراز هویت (به ویژه توکن های (Single sign-on SSO) در زمان خروج از سیستم یا یک دوره غیرفعال بودن به درستی بی اعتبار نشده‌اند.</li>
</ul>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله</div>

<ul dir="rtl" align="right">
  <li>
   در صورت امکان، احراز هویت چند عاملی را برای جلوگیری از حملات خودکار، اعتبارنامه، بروت فورس و حملات مجدد اعتبارنامه ربوده شده پیاده سازی کنید.
  </li>
 <li>
    با هیچ نام کاربری/کلمه عبور پیش فرضی، مخصوصا برای مدیران مدیریت، تنظیم و ارسال و تبادل صورت نگیرد.
  </li>
 <li>
  چک رمزهای عبور ضعیف، مانند بررسی گذرواژه های جدید یا تغییر یافته به کمک <a href="https://github.com/danielmiessler/SecLists/tree/master/Password">لیست ۱۰۰۰۰ تا از بدترین رمزهای عبور</a>. 
  </li>
 <li>
  تعیین سیاست طول رمز عبور، پیچیدگی و چرخش آن با دستورالعملهای <a href="href="https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret"">NIST 800-63 B's guidelines in section 5.1.1 for Memorized Secrets</a>یا سایر سیاستهای جدید و مستند رمز عبور.
  </li>
 <li>
اطمینان از اینکه ثبت نام، بازیابی اعتبارنامه ها و مسیرهایAPI  در برابر حملات شمارش حساب، با استفاده از پیام های مشابه برای تمام نتایج، به خوبی پیکربندی (HARDENING) شده‌اند.
  </li>
 <li>
    محدود کردن یا به طور فزاینده ای تلاشهای ورود به سیستم را تاخیر می دهد. همه خرابی ها را وارد کنید و مدیران را هشدار دهید وقتی که اعتبار نامه ها، نیروی بی رحم یا سایر حملات شناسایی می شوند.
  </li>
 <li>
محدود کردن یا به تاخیر انداختن تلاش‌های ورود ناموفق. نگاشت رویداد تمام شکست‌ها و هشدار به مدیران در زمانی که حملاتی مثل جاسازی هویت، بروت فورس و غیره کشف می‌شوند.
  </li> 
 <li>
استفاده از یک مدیر نشست سمت سرور توکار امن، که یک شناسه جلسه رندم با آنتروپی بالا بعد از ورود ایجاد میکند. شناسه جلسه نباید در نشانی اینترنتی باشد، باید امن ذخیره شود و پس از خروج از سیستم، بیکاری و زمان تایم اوت شدن مطلق، بی اعتبار شود.
  </li> 
</ul>

## <div dir="rtl" align="right">نمونه‌ سناریوهای حمله</div> 

<p dir="rtl" align="right"><strong>سناریو #1: </strong><a href=""> جاسازی هویت </a>، که از لیست های رمزهای عبور شناخته شده استفاده می‌کند، یک حمله رایج است. اگر برنامه کاربردی محافظت از تهدیدات خودکار یا محافظت از جاسازی هویت را اجرا نکند، برنامه کاربردی می‌تواند به عنوان اوراکل رمز عبور برای تعیین اعتبار هویت استفاده شود.</p>

<p dir="rtl" align="right"><strong>سناریو #2: </strong>بیشتر حملات احراز هویت به دلیل استفاده مداوم از کلمات عبور به عنوان یک عامل واحد صورت می‌گیرد. هنگامی‌که بهترین شیوه ها در نظر گرفته می‌شود، چرخش رمز عبور و الزامات پیچیدگی به عنوان استفاده و استفاده مجدد از کلمه عبور ضعیف مورد توجه قرار می‌گیرند. در سازمان ها توصیه می‌شود که این روش ها را در NIST 800-63 متوقف کنند و از احراز هویت چند عامل استفاده کنند.</p>

<p dir="rtl" align="right"><strong>سناریو #3: </strong>مهلت زمانی نشست برنامه کاربردی به درستی تنظیم نشده است. یک کاربر از یک رایانه عمومی ‌برای دسترسی به یک برنامه کاربردی استفاده می‌کند. کاربر به جای انتخاب "خروج از سیستم"،  تنها به بستن مرورگر اکتفا کرده و سیستم را رها می‌کند. مهاجم از این مرورگر یک ساعت بعد استفاده می‌کند و احراز هویت کاربر قربانی هنوز معتبر است.</p>

## <div dir="rtl" align="right">منابع</div> 

### OWASP

- [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)
- [OWASP Application Security Verification Standard: V2 Authentication](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
- [OWASP Application Security Verification Standard: V3 Session Management](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V3-Session-management.md)
- [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README)
 and [Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

### <div dir="rtl" align="right">خارجی</div>

- [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - for thorough, modern, evidence-based advice on authentication. 
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
