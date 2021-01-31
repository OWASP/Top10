# <div dir="rtl" align="right">A5:2017 کنترل دسترسی ناقص</div> 

| Threat agents/Attack vectors | Security Weakness  | Impacts |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۳ | شیوع: ۲ : قابل کشف بودن: ۲ | تکنیکی: ۳ : Business ? |
| <div dir="rtl" align="right"> بهره جویی از کنترل دسترسی یک مهارت اصلی مهاجمان است. ابزارهای <a href="https://www.owasp.org/index.php/Source_Code_Analysis_Tools">SAST</a> و <a href="https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools">DAST</a> می‌توانند فقدان کنترل دسترسی را تشخیص دهند، اما در صورت وجود کنترل دسترسی نمی‌توانند عملکرد آن را تایید کنند. کنترل دسترسی با استفاده از ابزار دستی و یا احتمالا از طریق خودکارسازی برای عدم وجود کنترل دسترسی در فریمورک های خاص قابل شناسایی است.</div> | <div dir="rtl" align="right">ضعف های کنترل دسترسی عموما به علت عدم تشخیص خودکار و عدم تست عملکردی موثر توسط توسعه دهندگان نرم افزار رایج هستند.تشخیص کنترل دسترسی به طور معمول نمی‌تواند به آزمایش خودکار ایستا یا پویا متوسل شود. تست دستی بهترین روش برای شناسایی کنترل دسترسی ناکارا یا نبود کنترل دسترسی است، از جمله روش HTTP (GET vs PUT)، کنترل کننده، direct object references </div> | <div dir="rtl" align="right">تأثیر فنی این حمله بدین گونه است که مهاجمان به عنوان کاربران یا مدیران، یا کاربران با استفاده از توابع اصلی، و یا ایجاد، دسترسی، به روز رسانی و یا حذف هر رکورد عمل می‌کنند .تأثیر کسب و کار بستگی به نیازهای حفاظت از برنامه و داده ها دارد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب پذیر است ؟</div>

<p dir="rtl" align="right">کنترل دسترسی سیاست را به گونه‌ای اعمال می‌کند که کاربران نمی‌توانند خارج از مجوز های مرتبط با خود عمل کنند. شکست کنترل دسترسی معمولا به افشای اطلاعات غیر مجاز، اصلاح یا خراب کردن تمام داده ها یا انجام یک کار تجاری در خارج از محدوده کاربر منجر می‌شود. آسیب پذیری های رایج کنترل دسترسی عبارتند از:</p>

<ul dir="rtl" align="right">
  <li>دور زدن بررسی های کنترل دسترسی از طریق تغییر URL، وضعیت برنامه کاربردی، یا صفحه HTML، یا با استفاده از یک ابزار حمله سفارشی API.  
  </li>
    <li>
اجازه دادن به کلید اصلی برای تعویض شدن با رکورد کاربران دیگر، اجازه مشاهده یا ویرایش حساب کاربری شخصی دیگر. 
  </li>
    <li>بالا بردن امتیاز. کار کردن به عنوان یک کاربر بدون ورود به سیستم و یا کار کردن به عنوان یک مدیر زمانی که به عنوان یک کاربر وارد سیستم شده است.  
  </li>
    <li>دستکاری متاداده، مانند بازپخش یا دستکاری با یک توکن دسترسی به JSON Web Token (JWT)  یا یک کوکی یا فیلد پنهان دستکاری شده برای افزایش امتیازات و یا سوء استفاده از لغو JWT.
  </li>
    <li>
تنظیم اشتباه CORS اجازه دسترسی غیر مجاز API را می‌دهد.
  </li>
    <li>اجبار به مرور صفحات مجاز به عنوان یک کاربر نامعتبر یا صفحات مجاز به عنوان یک کاربر استاندارد. دسترسی به API با کنترل دسترسی از دست رفته برای POST، PUT و DELETE.
</ul>

## <div dir="rtl" align="right">نحوه ی پیشگیری از حمله :</div>

<p dir="rtl" align="right">کنترل دسترسی تنها در صورتی که در کد سمت سرور مورد اعتماد یا API بدون سرور اعمال شود، مؤثر است. جایی که مهاجم نمی‌تواند بررسی کنترل دسترسی یا متا داده را تغییر دهد. </p>

<p dir="rtl" align="right">به استثنای منابع عمومی، انکار به طور پیشفرض. deny by default</p>

<ul dir="rtl" align="right">
  <li>
یک بار اجرای مکانیزم کنترل دسترسی و استفاده مجدد از آنها در طول برنامه، از جمله به حداقل رساندن استفاده از CORS.
  </li>
  <li>کنترل دسترسی های مدل باید مالکیت رکوردها را به جای پذیرفتن اینکه کاربر بتواند هر یک از رکوردها را ایجاد کند، بخواند، به روز رسانی و یا حذف کند، اعمال کند.
  </li>
  <li>
الزامات محدودیت کسب و کار یکتا باید توسط مدلهای دامنه اجرا شود.
  </li>
  <li>
    غیر فعال کردن فهرست دایرکتوری وب سرور و اطمینان از اینکه متا داده فایل به عنوان مثالgit) ) و فایل های پشتیبان در وب های ریشه موجود نیست.
  </li>
  <li>
نقص شدن های کنترل دسترسی را ثبت کنید، در صورت لزوم به مدیران هشدار دهید (برای مثال نقص های مکرر). 
  </li>
  <li>
محدود کردن سرعت API و دسترسی کنترل کننده برای به حداقل رساندن آسیب از ابزار حمله خودکار.
  </li>
  <li>
بعد از خروج توکن هایJWT باید بر روی سرور نامعتبر شود.
  </li>
  <li>
توسعه دهندگان و کارکنان QA باید کنترل دسترسی عملکردی و تست های یکپارچه سازیرا در نظر بگیرند.
  </li>
</ul>

## <div dir="rtl" align="right">نمونه سناریو های حمله</div>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>برنامه در یک درخواست SQL از داده های تأیید نشده که به اطلاعات حساب دسترسی دارد، استفاده می‌کند:</p>

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

<p dir="rtl" align="right">مهاجم به سادگی پارامتر  acctرا در مرورگر برای ارسال هر شماره حسابی کاربری که میخواهد، تغییر می‌دهد. اگر به درستی تأیید نشده باشد، مهاجم میتواند به هر حساب کاربری دسترسی پیدا کند.</p>

`http://example.com/app/accountInfo?acct=notmyacct`

<p dir="rtl" align="right"><strong>سناریو # 2: </strong>یک مهاجم به سادگی URL های هدف را مرور می‌کند. دسترسی مدیر برای دسترسی به صفحه مدیریت لازم است.
</p>

```
  http://example.com/app/getappInfo
  http://example.com/app/admin_getappInfo
```

<p dir="rtl" align="right">اگر یک کاربر احراز هویت نشده بتواند به یکی از این صفحات صفحه دسترسی داشته باشد، این یک نقص است. اگر شخصی به جز مدیر بتواند به صفحه مدیریت دسترسی پیدا کند، این نیز یک نقص است.</p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div> 

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Authorization Testing](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
