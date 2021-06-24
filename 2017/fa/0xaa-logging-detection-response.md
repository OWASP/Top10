# <div dir="rtl" align="right">A10:2017 رویدادنگاری و پایش نا کارآمد </div>

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl قابلیت بهره‌برداری: ۲ | شیوع: ۳ قابل کشف بودن: ۱ | تکنیکی: ۲ Business ? |
| <div dir="rtl" align="right">اکسپلویت کردن رویدادنگاری و پایش نا کارآمد، تقریباً بستر اصلی هر حادثه مهم است.مهاجمان به عدم نظارت و واکنش به موقع برای رسیدن به اهداف خود بدون شناسایی شدن متکی هستند.</div> | <div dir="rtl" align="right">  این مسئله بر اساس <a href="https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html">نظرسنجی صنعتی</a>، در Top 10 قرار دارد.یک استراتژی برای تعیین اینکه آیا شما نظارت کافی دارید بررسی کردن رویدادهای نگاشته مربوط به تست نفوذ است. اقدامات تست کنندگان باید به اندازه کافی ثبت شود تا بدانند که چه آسیبی به آنها وارد شده است.</div> | <div dir="rtl" align="right">  بیشترین حملات موفقیت آمیز با شناسایی آسیب پذیری آغاز می‌شود. اجازه دادن به این کاوشگرها برای ادامه می‌تواند احتمال بهره جویی موفقیت آمیز را تا حدود 100 درصد افزایش دهد.در سال 2016، شناسایی یک شکاف (رخنه) <a href="https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&">به طور متوسط 191 روز </a> طول کشید - زمانی طولانی برای آسیب زدن.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب پذیر است ؟</div>

<p dir="rtl" align="right">نگاشت رویداد، تشخیص، نظارت و پاسخ فعال ناکافی در هر زمان رخ می‌دهد:</p>

<ul dir="rtl" align="right">
  <li>
رویداد های قابل بررسی، از قبیل ورود به سیستم، ورود ناموفق به سیستم و تراکنش های با ارزش بالا در سیستم ثبت نشده اند.
  </li>
  <li>
هشدارها و اشتباهات موجب ایجاد پیام های رویداد نامشخص، پیام های نامناسب یا غیرقابل تعریف می‌شود.
  </li>
  <li>
رویدادهای مربوط به برنامه ها و API ها برای فعالیت مشکوک نظارت نمی‌شود.
  </li>
  <li>
رویدادها فقط به صورت محلی ذخیره می‌شوند.
  </li>
  <li>
آستانه های مربوط به هشدار و فرآیندهای تشدید پاسخ مناسب یا موثر نیستند.
  </li>
  <li>
    تست نفوذ و اسکن با ابزارهای <a href="https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools">DAST</a> <a href="https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project"> ( مانند  OWASP ZAP) </a> باعث هشدار نمی شود.
  </li>
  <li>
برنامه قادر به تشخیص، تشدید یا هشدار برای حملات فعال در زمان واقعی یا نزدیک به زمان واقعی نیست.
  </li>
</ul>

<p dir="rtl" align="right">  شما به نشت اطلاعات آسیب‌پذیر هستید، اگر نگاشت رویداد وقایع و هشدارها قابل مشاهده برای یک کاربر و یا یک مهاجم باشد. (نگاه کنید به A3:2017 -  افشای اطلاعات حساس)
</p>

## <div dir="rtl" align="right">پیشگیری از حمله </div>

<p dir="rtl" align="right">با تجه به ریسک داده‌ی ذخیره شده یا پردازش شده توسط برنامه کاربردی:</p>

<ul dir="rtl" align="right">
  <li>اطمینان حاصل کنید که تمام ورودی ها به سیستم، خطاهای کنترل دسترسی و شکست های اعتبار سنجی ورودی طرف سرور را می‌توان با زمینه کاربری کافی برای شناسایی حساب های مشکوک یا مخرب ثبت کرد و زمان کافی را برای اجازه دادن تجزیه و تحلیل قانونی به تاخیر انداخت.
  </li>
  <li>اطمینان حاصل کنید که نگاشت های رویدادها در قالبی تولید می‌شود که می‌توانند به راحتی توسط راه حل‌های متمرکز مدیریت رویدادنگاری  مورد استفاده قرار گیرد.
  </li>
  <li>اطمینان حاصل کنید که تراکنش های با ارزش بالا، دارای یک دنباله حسابرسی با کنترلهای یکپارچگی برای جلوگیری از دستکاری یا حذف، مانند جداول پایگاه داده اضافه یا مشابه آن هستند.
  </li>
  <li>
ایجاد نظارت مؤثر و هشدار به طوری که فعالیت های مشکوک به موقع شناسایی و پاسخ داده شود.
  </li>
  <li>
    ایجاد و یا اتخاذ یک پاسخ تصادفی و برنامه ریکاوری، مانند <a href="https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final"> NIST 800-61 rev 2 </a> یا بالاتر.
  </li>
</ul>

<p dir="rtl" align="right">
  چارچوب های تجاری و منبع باز حفاظت از نرم افزارهای کاربردی مانند <a href="https://www.owasp.org/index.php/OWASP_AppSensor_Project">OWASP AppSensor</a>، فایروال های وب کاربردی مانند <a href="https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project"> ModSecurity  با OWASP ModSecurity Core Rule Set </a>و نرم افزار همبسته‌سازی نگاشت رویداد با داشبوردها و هشداردهی سفارشی وجود دارند.</p>

## <div dir="rtl" align="right">نمونه سناریو های حمله</div>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>یک پروژه انجمن منبع باز که توسط یک تیم کوچک اجرا می‌شد با استفاده از یک نقص در نرم افزار آن هک شد. مهاجمان موفق به از بین بردن منبع کد داخلی حاوی نسخه بعدی و تمامی‌محتویات انجمن شدند. اگرچه این منبع کد بازیابی شد، اما فقدان نظارت، عدم ثبت رویداد و عدم هشدار دادن منجر به نقص بسیار بدتری شد. پروژه نرم افزاری انجمن در نتیجه این موضوع دیگر فعال نیست.</p>

<p dir="rtl" align="right"><strong>سناریو # 2: </strong>یک مهاجم کاربران را با استفاده از گذرواژه معمولی اسکن می‌کند. آنها می‌توانند با استفاده از این گذرواژه تمام حساب ها را در اختیار بگیرند. برای همه کاربران دیگر، این اسکن فقط یک ورود ناموفق به جا می‌گذارد. پس از چند روز، این کار ممکن است با یک گذرواژه متفاوت تکرار شود.</p>

<p dir="rtl" align="right"><strong>سناریو # 3: </strong>:  بنا به گزارشات، یک خرده فروش بزرگ آمریکایی یک سندباکس آنالیز بدافزار داخلی داشته که پیوست ها را اسکن میکرده. برنامه سندباکس به طور بالقوه برنامه ناخواسته را شناسایی کرده بود، اما هیچکس به این کشف واکنشی نشان نداد. قبل از اینکه نفوذ به دلیل تراکنش های کارت اعتباری توسط یک بانک خارجی شناسایی شود، سندباکس چندین مرتبه هشدار داده بوده است.</p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div>

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
