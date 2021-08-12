# <div dir="rtl" align="right">A9:2017 استفاده از مولفه‌هایی با آسیب‌پذیری شناخته شده </div>
| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl قابلیت بهره برداری : ۲ | شیوع ۳ : قابل کشف بودن ۲ | تکنیکی: ۲  Business |
| <div dir="rtl" align="right">در حالی که پیدا کردن اکسپلویت های نوشته شده برای بسیاری از آسیب پذیری های شناخته شده آسان است، اما آسیب پذیری های دیگر به دنبال ایجاد اکسپلویت سفارشی هستند. </div> | <div dir="rtl" align="right">شیوع این موضوع بسیار گسترده است. الگوهای توسعه مولفه سنگین می‌تواند منجر شود به اینکه حتی تیم های توسعه متوجه نشوند کدام مولفه ها را در برنامه یا API خود استفاده می‌کنند، و همچنین کمتر آنها را به روز نگه می‌دارند.برخی از اسکنرها مانند retire.js در شناسایی کمک می‌کنند، اما برای تعیین نیازمندی های بهره جویی باید تلاش بیشتری صورت گیرد.</div> | <div dir="rtl" align="right">در حالی که برخی از آسیب پذیری های شناخته شده منجر به تأثیرات جزئی می‌شوند، برخی از بزرگترین رخنه ها تا به امروز به بهره جویی از آسیب پذیری شناخته شده در قطعات تکیه کرده اند. بسته به دارایی که محافظت می‌کنید، شاید نیاز باشد این ریسک در بالای لیست قرار گیرد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب پذیر است ؟</div>

<p dir="rtl" align="right">شما احتمالا آسیب پذیر هستید:</p>

<ul dir="rtl" align="right">
  <li>اگر نسخه های تمام مولفه‌هایی که از آنها استفاده می‌کنید را نشناسید (هر دو طرف و سمت سرور). این شامل اجزایی است که به طور مستقیم از وابستگی های تو در تو (توزیع شده) استفاده می‌کنند .
  </li>
  <li>اگر نرم افزار آسيب پذير، پشتیبانی نشده يا بروز نباشد. این شامل سیستم عامل، وب / برنامه سرور، سیستم مدیریت پایگاه داده (DBMS)، برنامه ها، API ها و تمام مولفه های سازنده، محیط های زمان اجرا و کتابخانه ها می‌باشد.
  </li>
  <li>
اگر شما به طور منظم آسیب پذیری ها را اسکن نمی‌کنید و امنیت بخش هایی که از آنها استفاده می‌کنید را کنترل نکنید. 
  </li>
  <li>اگر پلت فرم، چارچوب ها و وابستگی ها را در یک مد مبتنی بر ریسک تنظیم نکنید یا ارتقاء ندهید. این معمولا در محیط هایی اتفاق می‌افتد که وصله امنیتی کردن یک وظیفه ماهانه یا سه ماهه‌ای است که تحت کنترل تغییر است، که سازمان ها را چندین روز یا چند ماه از مواجهه غیرضروری برای رفع آسیب پذیری ها آزاد می‌سازد.
  </li>
  <li>
اگر توسعه دهندگان نرم افزار سازگاری کتابخانه های به روز شده، ارتقا داده شده یا وصله شده را تست نکنند.
  </li>
  <li>
    اگر تنظیمات اجزاء را امن نکنید <strong>(نگاه کنید به A6: ۲017-Misconfiguration Security)</strong>.
  </li>
</ul>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله :</div>

<p dir="rtl" align="right"><strong></strong>باید یک فرایند مدیریت وصله امنیتی در محل خود داشته باشید تا:</p>

<ul dir="rtl" align="right">
  <li>
حذف وابستگی های استفاده نشده، ویژگی های غیر ضروری، مولفه ها، فایل ها و اسناد.
  </li>
    <li>به طور مداوم فهرستی از نسخه های مولفه های سمت سرویس گیرنده و سرویس دهنده (مانند چارچوب، کتابخانه ها) و فهرست کردن وابستگی های آنها را با استفاده از ابزارهای مانند versions، DependencyCheck، retire.js و غیره.  
  </li>
    <li>به طور مداوم منابع مانند CVEو NVD را برای آسیب پذیری در مولفه ها نظارت کنید. از ابزار تجزیه و تحلیل ترکیب نرم افزار برای به کار انداختن خودکار و بهینه سازی فرآیند استفاده کنید. به هشدارهای ایمیل برای آسیب پذیری های امنیتی مرتبط با مولفه های مورد استفاده، توجه کنید. 
  </li>
    <li>فقط مولفه‌ها را از منابع رسمی‌بر روی لینک های ایمن دریافت کنید. بسته‌ها ی امضا شده برای کاهش یک جز مخرب اصلاح شده را ترجیح دهید.  
  </li>
    <li>
      نظارت بر کتابخانه ها و مولفه هایی که پشتیبانی نشده یا وصله های امنیتی برای نسخه های قدیمی‌تر ندارند. اگر وصله کردن غیرممکن باشد، یک virtual patch برای نظارت، شناسایی یا محافظت در برابر مسئله کشف شده در نظر بگیرید.
  </li>
</ul>

<p dir="rtl" align="right">هر سازمان باید اطمینان حاصل کند که یک برنامه مداوم در حال انجام برای نظارت، برچیدن و اعمال به روز رسانی و یا تغییرات پیکربندی برای طول عمر برنامه وجود دارد.</p>

## <div dir="rtl" align="right">نمونه سناریو های حمله</div>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>مولفه ها معمولا با همان امتیازات خود برنامه کاربردی اجرا می‌شوند، بنابراین نقص در هر جزء می‌تواند تأثیر جدی داشته باشد. چنین نقص هایی می‌تواند تصادفی باشد (مثلا خطای برنامه نویسی) یا عمدی (به عنوان مثال رخنه‌گاه). بعضی از موارد آسیب پذیری مولفه که مورد سواستفاده قرار می‌گیرند :</p>

<ul dir="rtl" align="right">
  <li>
    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638">CVE-2017-5638</a> ,
    آسیب پذیری Struts 2 با قابلیت کنترل از راه دور که باعث اجرای کد دلخواه بر روی سرور می‌شود، به خاطر رخنه قابل توجه مورد نقد قرار گرفته است.
  </li>
  <li>
    در حالی که وصله کردن <a href="https://en.wikipedia.org/wiki/Internet_of_things"> اینترنت اشیا IOT </a>اغلب پیچیده یا غیرممکن است، اهمیت وصله کردن آنها میتواند زیاد باشد. (به عنوان مثال دستگاههای پزشکی).
  </li>
</ul>

<p dir="rtl" align="right">ابزارهای خودکاری برای کمک به مهاجمین وجود دارد که سیستم های با پیکربندی اشتباه یا وصله نشده را پیدا می کنند. به عنوان مثال،  <a href="https://www.shodan.io/">موتور جستجوی  Shodan IoT </a> می تواند به شما در پیدا کردن دستگاه هایی که هنوز از آسیب پذیری <a href="https://en.wikipedia.org/wiki/Heartbleed">Heartbleed</a> که در آوریل 2014 رفع شده است رنج میبرند کمک شایانی می کند. </p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div> 

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x10-V1-Architecture.md)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)

### <div dir="rtl" align="right">خارجی</div>

* [The Unfortunate Reality of Insecure Libraries](https://cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)

* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
