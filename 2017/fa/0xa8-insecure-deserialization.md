# <div dir="rtl" align="right">Deserialization A8:2017 نا امن </div>

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 1 | Prevalence 2 : Detectability 2 | Technical 3 : Business |
| <div dir="rtl" align="right">بهره برداری از deserialization تا حدودی دشوار است، زیرا به عنوان off the shelf بهره برداری به ندرت بدون تغییر و یا پیچاندن کد بهره برداری اصلی است.</div> | <div dir="rtl" align="right">این مسئله در Top 10 بر اساس <a href="https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html"> تحقیقات صنعت </a> و نه بر روی داده های قابل اندازه گیری وجود دارد. بعضی از ابزارها می توانند نقص های deserialization را بیابند، اما برای کمک به اعتباربخشی، اغلب نیاز به کمک انسانی است. انتظار می رود که داده های شایع و پخش شده برای نقص های deserialization افزایش یابد، زیرا ابزارهایی جهت کمک به شناسایی و پیدا کردن آدرس آنها توسعه یافته اند. </div> | <div dir="rtl" align="right">تاثير نقص deserialization نمی تواند کم اهميت باشد. این نقص ها می تواند به اجرای کد از راه دور منجر شود، که یکی از جدی ترین حملات ممکن است. تاثیر کسب و کار بستگی به نیازهای حفاظت از برنامه و داده ها دارد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب‌پذیر است؟</div>

<p dir="rtl" align="right">برنامه های کاربردی و API  ها آسیب پذیر خواهند بود اگر آنها از اشیاء متخاصم یا دستکاری شده توسط مهاجم استفاده کنند.</p>

<p dir="rtl" align="right">این می تواند به دو نوع اصلی حملات منجر شود:</p>

<ul dir="rtl" align="right">
  <li>
    حملات مرتبط با ساختار داده و داده ها، جایی که مهاجم منطق برنامه را تغییر می دهد یا اگر اشیاء موجود در برنامه وجود داشته باشد که می توانند رفتار را در طی یا بعد از دیسریالیزیشن تغییر دهند، اجرای کد دلخواه کد را اجرا می کند.
  </li>
  <li>
    حملات متداول دستکاری اطلاعات، مانند حملات مربوط به کنترل دسترسی، که در آن ساختار داده موجود استفاده می شود، اما محتوای تغییر یافته است.
  </li>
</ul>

<p dir="rtl" align="right">سریالیزیشن  ممکن است در برنامه های کاربردی برای:</p>

<ul dir="rtl" align="right">
  <li>
    ارتباطات از راه دور و بین فرایند (RPC / IPC)
  </li>
  <li>
پروتکل های سیم، خدمات وب، کارگزاران پیام
  </li>
  <li>
    ذخیره سازی / پایداری
  </li>
  <li>
    پایگاههای داده، سرورهای ذخیره سازی، سیستم های فایل
  </li>
  <li>
   کوکی HTTP، پارامترهای فرم HTML، نشانه های تأیید API
  </li>
</ul>

## <div dir="rtl" align="right">پیشگیری از حمله</div>

<p dir="rtl" align="right">تنها الگوی امن معماری، تشخیص اشیاء سریالی از منابع نامعتبر و یا استفاده از رسانه های سریالی که فقط نوع داده های اولیه را مجاز می شمارند.</p>

<p dir="rtl" align="right">اگر این امکان پذیر نیست، یکی از موارد زیر را در نظر بگیرید:</p>

<ul dir="rtl" align="right">
  <li>
   اجرای چک های یکپارچه مانند امضاهای دیجیتالی بر روی هر شیء سریالی برای جلوگیری از ایجاد شیء خصمانه و یا دستکاری داده ها.
  </li>
  <li>
    اجرای محدودیت های سخت نوع در طول deserialization قبل از ایجاد شی به عنوان کد به طور معمول یک مجموعه قابل تعریف از کلاس انتظار می رود. دور زدن این تکنیک نشان داده شده است، بنابراین تنها تکیه بر این تکنیک توصیه نمی شود.
  </li>
  <li>
    کد جدا سازی و اجرای کد که deserializes در محیط های با دسترسی کم ممکن می شود.
  </li>
  <li>
   استثنائات و خرابی هایی ورود deserialization، از جمله مواردی که نوع ورودی نوع مورد انتظار نیست، یا deserialization  استثنائات را حذف می کند.
  </li>
  <li>
    محدود کردن یا نظارت بر اتصال به شبکه های ورودی و خروجی از کانتینر و یا سرورهایی که deserialize می شوند.
  </li>
  <li>
   نظارت بر deserialization، هشدار در صورتی که یک کاربر به طور مداوم deserializes می شود.
  </li>
</ul>

## <div dir="rtl" align="right">نمونه سناریو های حمله</div>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>برنامه کاربردی React، مجموعه ای از سرویس های خدمات میکرو Spring Boot را فراخوانی می کند. برنامه نویسان کاربردی، سعی کردند اطمینان حاصل کنند که کد آنها غیر قابل تغییر است. راه حل هایی که با آن روبرو می شوند، موقعیت کاربر را به صورت سریالی و هر درخواست به عقب و جلو منتقل می کند. یک مهاجم به امضای شی "R00" اشاره می کند و از ابزار Java Serial Killer برای به دست آوردن اجرای کد راه دور در سرور برنامه استفاده می کند.</p>

<p dir="rtl" align="right"><strong>سناریو # 2: </strong>یک انجمن PHP با استفاده از پیاده سازی شیء به منظور ذخیره یک "سوپر" کوکی، حاوی شناسه کاربری کاربر، نقش، هش رمز عبور و حالت های دیگر استفاده می کند:</p>

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

<p dir="rtl" align="right">یک مهاجم شیء سریالی را تغییر می دهد تا امتیازات مدیریت خود را به دست آورد:</p>

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div> 

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
