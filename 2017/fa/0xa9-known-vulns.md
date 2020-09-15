# <div dir="rtl" align="right">A9:2017 استفاده از مولفه های با آسیب پذیری شناخته شده </div>
| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl قابلیت بهره برداری : ۲ | شیوع ۳ : قابل کشف بودن ۲ | تکنیکی: ۲  Business |
| <div dir="rtl" align="right">در حالی که پیدا کردن اکسپلویت های نوشته شده برای بسیاری از آسیب پذیری های شناخته شده آسان است، اما آسیب پذیری های دیگر به دنبال ایجاد اکسپلویت سفارشی هستند. </div> | <div dir="rtl" align="right">شیوع این موضوع بسیار گسترده است. الگوهای توسعه کامپوننت سنگین می تواند منجر شود به اینکه حتی تیم های توسعه متوجه نشوند کدام مولفه ها در برنامه یا API خود استفاده می کنند، و همچنین کمتر آنها را به روز نگه می دارند. برخی از اسکنرها مانند retire.js در شناسایی کمک می کنند، اما تعیین نیازمندی های بهره برداری باید تلاش بیشتری صورت گیرد.</div> | <div dir="rtl" align="right">در حالی که برخی از آسیب پذیری های شناخته شده منجر به تاثیرات جزئی می شوند، برخی از بزرگترین رخنه ها تا به امروز به بهره برداری از آسیب پذیری شناخته شده در قطعات تکیه کرده اند. بسته به دارایی که محافظت می کنید، شاید نیاز باشد این ریسک در بالای لیست قرار گیرد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب پذیر است ؟</div>

<p dir="rtl" align="right">شما احتمالا آسیب پذیر هستید:</p>

<ul dir="rtl" align="right">
  <li>
   اگر نسخه های تمام مولفه هایی که از آنها استفاده می کنید را نشناسید (هر دو طرف و سمت سرور). این شامل اجزایی است که به طور مستقیم از وابستگی های تو در تو (توزیع شده) استفاده می کنند .
  </li>
  <li>
    اگر نرم افزار آسيب پذير، پشتیبانی نشده يا بروز نباشد. این شامل سیستم عامل، وب / برنامه سرور، سیستم مدیریت پایگاه داده (DBMS)، برنامه ها، API  ها و تمام مولفه های سازنده، محیط های زمان اجرا و کتابخانه ها می باشد.
  </li>
  <li>
    اگر شما به طور منظم آسیب پذیری ها را اسکن نمی کنید و امنیت بخش هایی که از آنها استفاده می کنید را کنترل نکنید. 
  </li>
  <li>
    اگر پلت فرم، چارچوب ها و وابستگی ها را در یک مد مبتنی بر ریسک تنظیم نکنید یا ارتقاء ندهید. این معمولا در محیط ها اتفاق می افتد وقتی که وصله امنیتی کردن یک وظیفه ماهانه یا سه ماهه ای است که تحت کنترل تغییر است، که سازمان ها را چندین روز یا چند ماه از مواجه ه  غیرضروری برای رفع آسیب پذیری ها مشغول می سازد.
  </li>
  <li>
    اگر توسعه دهندگان نرم افزار سازگاری کتابخانه های به روز شده، ارتقا داده شده یا وصله شده را تست نکنند.
  </li>
  <li>
    اگر تنظیمات اجزاء را امن نکنید <strong>(نگاه کنید به A6: ۲017-Misconfiguration Security)</strong>.
  </li>
</ul>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله</div>

<p dir="rtl" align="right"><strong></strong>باید یک فرایند مدیریت وصله امنیتی در محل خود داشته باشید تا:</p>

<ul dir="rtl" align="right">
  <li>
حذف وابستگی های استفاده نشده، ویژگی های غیر ضروری، مولفه ها، فایل ها و اسناد.
  </li>
    <li>
      به طور مداوم  فهرستی از نسخه های مولفه های سمت سرویس گیرنده و سرویس دهنده (مانند چارچوب، کتابخانه ها) و فهرست کردن وابستگی های آنها را با استفاده از ابزارهای مانند versions، DependencyCheck، retire.js و غیره. 
  </li>
    <li>
    به طور مداوم منابع مانند CVE  و NVD  را برای آسیب پذیری در مولفه ها نظارت کنید. از ابزار تجزیه و تحلیل ترکیب نرم افزار برای به کار انداختن خودکار و بهینه سازی فرآیند استفاده کنید. به هشدارهای ایمیل برای آسیب پذیری های امنیتی مرتبط با مولفه های مورد استفاده، توجه کنید. 
  </li>
    <li>فقط مولفه ها را از منابع رسمی بر روی لینک های ایمن دریافت شود. بسته ها ی امضا شده برای کاهش یک جز مخرب اصلاح شده ترجیح داده می شود. 
  </li>
    <li>
     نظارت بر کتابخانه ها و مولفه هایی که پشتیبانی نشده یا وصله های امنیتی برای نسخه های قدیمی تر ندارند. اگر وصله کردن غیرممکن باشد، یک وصله مجازی برای نظارت، شناسایی یا محافظت در برابر مسئله کشف شده در نظر بگیرید.
  </li>
</ul>

<p dir="rtl" align="right">هر سازمان باید اطمینان حاصل کند که یک برنامه مداوم در حال انجام برای نظارت، برچیدن و اعمال به روز رسانی و یا تغییرات پیکربندی برای طول عمر برنامه وجود دارد.</p>

## <div dir="rtl" align="right">نمونه سناریو های حمله</div>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>مولفه ها معمولا با همان امتیازات به عنوان برنامه کاربردی اجرا می شوند، بنابراین نقص در هر جزء می تواند تاثیر جدی داشته باشد. چنین نقصی می تواند تصادفی باشد (مثلا خطای برنامه نویسی) یا عمدی (به عنوان مثال در قسمت پشتی). بعضی از موارد آسیب پذیری مولفه که مورد سواستفاده قرار می گیرند :</p>

<ul dir="rtl" align="right">
  <li>
    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638">CVE-2017-5638</a> ,
    یک آسیب پذیری با قابلیت کنترل از راه دور Struts 2 که باعث اجرای کد دلخواه بر روی سرور را امکان پذیر می سازد، به خاطر رخنه قابل توجه مورد نقد قرار گرفته است.
  </li>
  <li>
    در حالی که وصله کردن <a href="https://en.wikipedia.org/wiki/Internet_of_things"> اینترنت اشیا IOT </a>اغلب پیچیده یا غیرممکن است، اهمیت وصله کردن آنها میتواند عالی باشد (به عنوان مثال دستگاههای پزشکی).
  </li>
</ul>

<p dir="rtl" align="right">ابزارهای خودکاری برای کمک به مهاجمین وجود دارد که سیستم های سیستم های با پیکربندی اشتباه و وصله نشده را پیدا می کنند. به عنوان مثال،  <a href="https://www.shodan.io/report/89bnfUyJ">موتور جستجو  Shodan IoT </a> می تواند به شما در پیدا کردن دستگاه هایی که هنوز از آسیب پذیری <a href="https://en.wikipedia.org/wiki/Heartbleed">Heartbleed</a> که در آوریل 2014 رفع شده است کمک شایانی می کند. </p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div> 

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### <div dir="rtl" align="right">خارجی</div>

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
