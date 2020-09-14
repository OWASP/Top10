# <div dir="rtl" align="right"> A2:2017 احراز هویت ناقص</div>

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۳ | شیوع: ۲ : قابل کشف بودن: ۲ | تکنیکی: ۳ : Business |
| <div dir="rtl" align="right">مهاجمان به صدها میلیون نام کاربری و  رمز عبور معتبر جهت ارائه تشخیص هویت، به عنوان لیست حساب‌های مدیریتی پیش فرض، حمله جامع خودکار و ابزارهای حمله دیکشنری دسترسی دارند. حملات مدیریت نشست به خوبی درک می شود، به خصوص در رابطه با توکن های نشست غیرقابل انتظار.</div> | <div dir="rtl" align="right">رواج این حمله به علت نحوه طراحی و پیاده سازی بیشتر احراز هویت‌ها و کنترل دسترسی بسیار گسترده است. مدیریت نشست، پایه‌ی احراز هویت و کنترل دسترسی است و در همه برنامه های stateful وجود دارد. مهاجمان می توانند شکست احراز هویت را با استفاده از راهکار دستی تشخیص دهند و با استفاده از ابزارهای خودکار با لیستی از پسوردها و حمله های دیکشنری از آنها سو استفاده کنند. </div> | <div dir="rtl" align="right">مهاجم تنها می تواند به چند تا از حساب های  محدود دسترسی پیدا کند، یا تنها می تواند به حساب مدیر برای به خطر انداختن سیستم دسترسی پیدا کند. بسته به حوزه کاربرد، این ممکن است منجر به پولشویی، کلاهبرداری اجتماعی و سرقت هویت یا اطلاعات محرمانه محافظت شده از نظر قانونی را افشا کند. </div> |

## <div dir="rtl" align="right">آیا برنامه کاربرد آسیب‌پذیر است؟</div>

<p dir="rtl" align="right">تأیید هویت کاربر، احراز هویت و مدیریت نشست برای حفاظت از حملات مرتبط با احراز هویت حیاتی است.</p>

<p dir="rtl" align="right">اگر برنامه کاربردی شامل موارد زیر باشد ضعف های آسیب‎‌پذیری وجود خواهند داشت: </p>

<ul dir="rtl" align="right">
 <li>اجازه حملات خودکار را به مهاجم بدهد. مانند حملات <a href="https://www.owasp.org/index.php/Credential_stuffing">جاسازی احراز هویت</a>، که در آن مهاجم دارای لیستی از نام‌های کاربری و کلمه عبور معتبر را در اختیار دارد.</li>
 <li>اجازه حملات خودکار رمز عبور یا حملات خودکار دیگر را بدهد. </li>
 <li>اجازه ثبت رمزهای عبور پیش فرض، ضعیف یا شناخته شده مانند "Password1 " یا admin / admin"" را بدهد.</li>
 <li>از فرآیندهای ضعیف یا ناکارآمد بازیابی یا فراموشی احراز هویت رمز، مانند "پاسخهای مبتنی بر دانش"، استفاده کند که امن نیستند.</li>
 <li>با استفاده از متن آشکار، رمزنگاری شده و یا رمزهای هش ضعیف شده استفاده کند <strong>(نگاه کنید به A3: ۲017-Sensitive Data Exposure)</strong>.</li>
 <li>از روش های احراز هویت چند مرحله ای ناکارآمد استفاده کند. </li>
 <li>شناسه نشست در URL قابل مشاهده باشد. (مثل URL, Rewriting)</li>
 <li>شناسه نشست پس از ورود موفق به سیستم ، تغییر نکرده باشد. </li>
 <li>شناسه های نشست تداوم نداشته باشند. نشست های کاربر یا توکن های احراز هویت (به ویژه توکن های (Single sign-on SSO) ( در زمان خروج از سیستم یا یک دوره غیرفعال بودن به درستی اعتبار ندارند.</li>
</ul>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله</div>

<ul dir="rtl" align="right">
  <li>
    در صورت امکان، احراز هویت چند عامل را برای جلوگیری از حملات خودکار، اعتبارنامه، نیروی بی رحمانه و حملات مجدد اعتبارنامه ربوده شده پیاده سازی کنید.
  </li>
 <li>
    آیا با هیچ مدرک پیش فرض، مخصوصا برای مدیران مدیریت، ارسال و ارسال نمی شود.
  </li>
 <li>
  اجرای چک های ضعیف رمز عبور، مانند تست گذرواژه های جدید یا تغییر یافته در برابر یک <a href="https://github.com/danielmiessler/SecLists/tree/master/Password">لیست از 10000 بدترین رمزهای عبور .</a> 
  </li>
 <li>
  خطاهای رمز عبور، پیچیدگی و چرخش را با <a href="https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret">دستورالعملهای NIST 800-63 B در بخش 5.1.1</a> برای اسرار حفظ شده یا سایر سیاستهای رمز عبور مدرن مبتنی بر شواهد منطبق کنید.
  </li>
 <li>
    اطمینان از ثبت نام، بازیابی اعتبارنامه ها و مسیرهای API در برابر حملات شمارش حساب، با استفاده از پیام های مشابه برای تمام نتایج، تشدید می شود.
  </li>
 <li>
    محدود کردن یا به طور فزاینده ای تلاشهای ورود به سیستم را تاخیر می دهد. همه خرابی ها را وارد کنید و مدیران را هشدار دهید وقتی که اعتبار نامه ها، نیروی بی رحم یا سایر حملات شناسایی می شوند.
  </li>
 <li>
    استفاده از یک مدیر جلسه ای امن، امن، ساخته شده در جلسه که یک شناسه جلسه تصادفی جدید با انتروپی بالا پس از ورود ایجاد می کند. شناسه جلسه نباید در نشانی اینترنتی باشد، پس از خروج از سیستم، بیکار و زمان وقوع مطلق، ایمن ذخیره و نامعتبر باشد.
  </li> 
</ul>

## <div dir="rtl" align="right">نمونه‌ سناریوهای حمله</div> 

<p dir="rtl" align="right"><strong>سناریو #1: </strong><a href=""> Credential stuffing </a>، که از لیست های رمزهای عبور شناخته شده <a href="https://github.com/danielmiessler/SecLists">لیست های رمزهای عبور شناخته شده</a> استفاده می کند، یک حمله رایج است. اگر برنامه کاربردی محافظت از تهدیدات خودکار یا محافظت از Credential stuffing  را اجرا نکند، برنامه را می توان به عنوان اوراکل رمز عبور برای تعیین اعتبار Credentials استفاده کرد.</p>

<p dir="rtl" align="right"><strong>سناریو #2: </strong>بیشتر حملات احراز هویت به دلیل استفاده مداوم از کلمات عبور به عنوان یک عامل واحد صورت می گیرد. هنگامی که بهترین شیوه ها در نظر گرفته می شود، چرخش رمز عبور و الزامات پیچیدگی به عنوان کاربران تشویقی برای استفاده و استفاده مجدد از کلمه عبور ضعیف مورد توجه قرار می گیرند. در سازمان ها توصیه می شود که این روش ها را در NIST 800-63 متوقف کنند و از احراز هویت چند عامل استفاده کنند.</p>

<p dir="rtl" align="right"><strong>سناریو #3: </strong>مهلت زمانی نشست برنامه کاربردی به درستی تنظیم نشده است. یک کاربر از یک رایانه عمومی برای دسترسی به یک برنامه کاربردی استفاده می کند. کاربر به جای انتخاب "خروج از سیستم"،  تنها به بستن مرورگر اکتفا کرده و سیستم را رها می کند. مهاجم از این مرورگر یک ساعت بعد استفاده می کند و  احراز هویت کاربر قربانی هنوز معتبر است.</p>

## <div dir="rtl" align="right">منابع</div> 

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
 and [Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
* [OWASP Automated Threats Handbook](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### <div dir="rtl" align="right">خارجی</div>

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - for thorough, modern, evidence-based advice on authentication. 
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
