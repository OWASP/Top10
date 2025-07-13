# <div dir="rtl" align="right">Deserialization A8:2017 نا امن </div>

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری 1 | شیوع 2 : قابل کشف بودن 2 | تکنیکی 3 : Business |
| <div dir="rtl" align="right">بهره جویی از Deserialization تا حدودی دشوار است، چرا که اکسپلویت های آماده به ندرت بدون تغییر یا دستکاری در کد پنهانشان کار می‌کنند.</div> | <div dir="rtl" align="right">این مسئله در Top 10 بر اساس <a href="https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html">این مسئله در Top 10  بر اساس تحقیقات صنعت و نه بر روی داده های قابل اندازه گیری وجود دارد.بعضی از ابزارها می‌توانند نقص های Deserialization را بیابند، اما برای کمک به اعتباربخشی، اغلب نیاز به کمک انسانی است. انتظار می‌رود که داده های شایع و پخش شده برای نقص های Deserialization افزایش یابد، زیرا ابزارهایی جهت کمک به شناسایی و پیدا کردن آدرس آنها توسعه یافته اند. </div> | <div dir="rtl" align="right">تاثير نقص Deserialization نمی‌تواند کم اهميت باشد. این نقص ها می‌تواند به اجرای کد از راه دور منجر شود، که یکی از جدی ترین حملات ممکن است.تأثیر کسب و کار بستگی به نیازهای حفاظت از برنامه و داده ها دارد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب‌پذیر است؟</div>

<p dir="rtl" align="right">برنامه های کاربردی و API ها در صورتی که اشیاء دستکاری شده و خصمانه‌‌ای که مهاجم تدارک دیده است را Deserialize کنند، آسیب پذیر خواهند بود.</p>

<p dir="rtl" align="right">این می تواند به دو نوع اصلی حملات منجر شود:</p>

<ul dir="rtl" align="right">
  <li>
    حملات مرتبط با ساختار داده و داده ها، جایی که مهاجم منطق برنامه را تغییر داده یا به اجرای کد دلخواه دستیابی پیدا می‌کند، در صورتی که کلاس‌هایی برای برنامه وجود داشته باشند که می‌توانند رفتار را در طی یا بعد از Deserialization تغییر دهند.
  </li>
  <li>
    حملات متداول دستکاری داده، مانند حملات مربوط به کنترل دسترسی، که در آن ساختار داده موجود استفاده می‌شود، اما محتوا تغییر یافته است.
  </li>
</ul>

<p dir="rtl" align="right">سریالیزیشن ممکن است در برنامه های کاربردی برای این موارد استفاده شود:</p>

<ul dir="rtl" align="right">
  <li>
    ارتباطات از راه دور و بین فرایند (RPC / IPC)
  </li>
  <li>
پروتکل های سیم، وب سرویس ها، کارگزاران پیام
  </li>
  <li>
    ذخیره سازی / پایداری
  </li>
  <li>
    پایگاههای داده، سرورهای ذخیره سازی، سیستم های فایل
  </li>
  <li>
   کوکی های HTTP، پارامترهای فرم HTML، توکن های تأیید API
  </li>
</ul>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله :</div>

<p dir="rtl" align="right">تنها الگوی امن معماری، قبول نکردن تشخیص اشیاء سریالی از منابع نامعتبر و یا استفاده نکردن از رسانه های سریالی که فقط نوع داده های اولیه را مجاز می‌شمارند، است.</p>

<p dir="rtl" align="right">اگر این امکان پذیر نیست، موارد زیر را در نظر بگیرید:</p>

<ul dir="rtl" align="right">
  <li>
بررسی یکپارچگی،‌ مانند امضاهای دیجیتالی بر روی هر شیء سریالی برای جلوگیری از ایجاد شیء خصمانه و یا دستکاری داده ها.
  </li>
  <li>
    اجرای محدودیت های سخت نوع در طول Deserialization قبل از ایجاد شی به عنوان کد به طور معمول یک مجموعه قابل تعریف از کلاس را انتظار دارد. دور زدن این تکنیک نشان داده شده است، بنابراین تنها تکیه بر این تکنیک توصیه نمی‌شود.
  </li>
  <li>
وقتی مقدور است،‌ جدا سازی و اجرای کد که در محیط های با دسترسی کم، Deserialize می‌کند.
  </li>
  <li>
   نگاشت رویداد استثناها و شکست های Deserialization، از جمله مواردی که نوع ورودی نوع مورد انتظار نیست، یا Deserialization استثنائات را حذف می‌کند.
  </li>
  <li>
محدود کردن یا نظارت بر اتصال به شبکه های ورودی و خروجی از کانتینرها و یا سرورهایی که Deserialize می‌کنند.
  </li>
  <li>
نظارت بر Deserialization، هشدار در صورتی که یک کاربر به طور مداوم Deserialize می‌کند.
  </li>
</ul>

## <div dir="rtl" align="right">نمونه سناریو های حمله</div>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>برنامه کاربردی React، مجموعه‌ای از میکروسرویس هایSpring Boot  را فراخوانی می‌کند. بعنوان برنامه نویسان کاربردی، سعی کردند اطمینان حاصل کنند که کد آنها غیر قابل تغییر است. راه حل هایی که با آن روبرو می‌شوند، سریالایز کردن موقعیت کاربر و عقب و جلو کردن آن با هر درخواست است. یک مهاجم به امضای""R00 شی جاوا توجه می‌کند و از ابزار Java Serial Killer  برای اجرای کد از راه دور در سرور برنامه کاربردی استفاده می‌کند.</p>

<p dir="rtl" align="right"><strong>سناریو # 2: </strong>یک انجمن PHP با استفاده از سریالایز شی PHP به منظور ذخیره یک "سوپر" کوکی، حاوی شناسه کاربری کاربر، نقش، هش رمز عبور و حالت های دیگر استفاده می‌کند:</p>

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

<p dir="rtl" align="right">یک مهاجم شیء سریالی را تغییر می‌دهد تا امتیازات مدیریت خود را به دست آورد:</p>

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div> 

* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://wiki.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
