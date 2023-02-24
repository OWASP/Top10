# <div dir="rtl" align="right">A1:2017 تزریق</div> 

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۳ | شیوع: ۲ : قابل کشف بودن: ۳ | تکنیکی: ۳ : Business |
| <div dir="rtl" align="right">تقریبا هر منبع داده می تواند یک بردار تزریق، متغیرهای محیطی، پارامترها، خدمات وب داخلی و خارجی و انواع مختلف کاربران باشد. <a href="https://www.owasp.org/index.php/Injection_Flaws">نقص تزریق</a> زمانی رخ می دهد که مهاجم می تواند داده های خصمانه را به مفسر ارسال کند.</div> | <div dir="rtl" align="right">نقص تزریق بسیار شایع است، به خصوص در کد اصلی. آسیب پذیری های تزریق اغلب در درخواست‌های SQL، LDAP، Xpath  یا  NoSQL، دستورات سیستم عامل، پارس کننده‌های XML، هدرهای SMTP، زبان توضیفی و درخواست‌های ORM یافت می‌شوند. هنگام بررسی کد، کشف نقص تزریق آسان است. اسکنرها و فازرها می‌توانند به مهاجمان برای پیدا کردن نقص تزریق کمک کنند.</div> | <div dir="rtl" align="right">تزریق می تواند باعث از دست دادن اطلاعات یا انحراف، عدم پاسخگویی یا رد دسترسی شود. تزریق می تواند گاهی منجر به تصاحب کامل میزبان نیز گردد. تاثیر تجاری بستگی به نیازهای محافظت از برنامه و اطلاعات شما دارد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب‌پذیر است؟ </div>

<p dir="rtl" align="right">برنامه کاربردی در شرایط زیر به حمله آسیب پذیر است: </p>

<ul dir="rtl" align="right">
  <li>
ورودی های ارائه شده توسط کاربر اعتبار سنجی یا فیلتر نشوند. 
  </li>
  <li>
    داده های خصمانه به طور مستقیم با استفاده از پرس و جو های پویا و یا درخواست های غیر پارامتریک برای مفسر بدون آگاهی از متن مورد استفاده قرار می گیرد. 
  </li>
  <li>
    داده های خصمانه در پارامترهای جستجو در نگاشت شیء-ارتباطی (ORM) برای استخراج  همه اطلاعات یا اطلاعات حساس استفاده می‌شود.
  </li>
  <li>
   داده های خصمانه به طور مستقیم استفاده می شود یا پیوند داده می شوند با دستورات SQL یا دستور حاوی هر دو ساختار و داده های خصمانه در پرس و جوهای پویا، دستورات و روش های ذخیره شده.
  </li>
  <li>
    برخی از تزریقات رایج عبارتند از SQL، NoSQL، دستور OS، ORM، LDAP و زبان بیان (EL) یا تزریق OGNL . مفهوم در میان همه مفسرها یکسان است.
بررسی کد منبع بهترین روش تشخیص این است که آیا برنامه کاربردی شما برای تزریق آسیب پذیر هستند یا خیر، با تست کامل خودکار تمام پارامترها، سرصفحه ها، URL ها، کوکی ها، JSON، SOAP و ورودی های داده XML می توان نقص تزریق را پیگیری کرد. سازمانها می توانند از ابزارهای منبع استاتیک <a href="https://www.owasp.org/index.php/Source_Code_Analysis_Tools">SAST</a> و آزمون برنامه کاربردی پویا <a href="https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools">DAST</a> را در خط لوله CI /     CD  برای شناسایی نقص های تزریق  معرفی شده قبل از تولید در اختیار بگیرند و استفاده کنند. .
  </li>
</ul>c

## <div dir="rtl" align="right">نحوه پیشگیری از حمله:</div>

<p dir="rtl" align="right">جهت جلوگیری از حمله تزریق نیاز است تا داده‌ها جدا از دستورات و درخواست‌ها نگهداری شوند</p>

<ul dir="rtl" align="right">
  <li>
    گزینه ترجیح داده شده این است که از یک API مطمئن استفاده کنید که از استفاده کامل از مفسر اجتناب می‌کند یا یک رابط کاربری پارامتریک را فراهم می‌کند یا به استفاده از ابزارهای مدل سازی ارتباطی شیء (ORM) مهاجرت می‌کند.
    <strong>نکته: </strong>
    روش های ذخیره شده، حتی زمانی که پارامتری شده‌اند، هنوز می‌توانند تزریق SQL را در صورتی که PL / SQL یاT-SQL  پیوندها و داده ها را پیوند دهند یا داده های خصمانه را با EXECUTE IMMEDIATE یاexec()  اجرا کنند.
  </li>
  <li>
    از تصدیق ورودی مثبت یا "لیست سفید" سمت سرور استفاده کنید. از آنجایی که بسیاری از برنامه ها نیاز به کاراکترهای خاص مانند نواحی متنی یا API برای برنامه های کاربردی تلفن همراه دارند، این یک محافظت کامل ایجاد نمی‌کند.
  </li>
  <li>
    برای هر درخواست پویای باقی مانده دینامیک، از کاراکترهای خاص با استفاده از گریز (ESCAPE) از سینتکس خاص برای آن مفسر، گریز کنید.  
    <strong>نکته: </strong>
ساختار SQL مانند نام جدول، نام ستون و غیره نمیتواند گریزی داشته باشد و بنابراین ساختار ورودی های ارائه شده توسط کاربر خطرناک است. این یک مسئله رایج در نرم افزار گزارش نویسی است.
  </li>
  <li>
استفاده از LIMIT و دیگر کنترل های SQL درون پرس و جوها برای جلوگیری از افشای رکوردهای پرونده ها در حملا تزریق SQL. 
  </li>
</ul>

## <div dir="rtl" align="right">نمونه‌ سناریوهای حمله</div>

<p dir="rtl" align="right"><strong>سناریو #1:</strong>یک برنامه داده های نامطمئن را در ساختار این درخواست آسیب پذیر SQL استفاده می‌کند : </p>

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

<p dir="rtl" align="right"><strong>سناریو #2:</strong>به طور مشابه، اعتماد کورکورانه برنامه کاربردی به فریمورک ها ممکن است به درخواست هایی ختم شود که هنوز آسیب پذیر هستند (به عنوان مثال (Hibernate Query Language
 :</p>

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

<p dir="rtl" align="right">در هر دو مورد، مهاجم مقدار پارامتر < id> را در مرورگر خود تغییر می دهد تا <span style="direction:ltr;display:inline-block">' UNION SELECT SLEEP(10);-- </span> را ارسال کند : به طور مثال: </p>

`http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

<p dir="rtl" align="right">این معنای هر دو درخواست را تغییر می‌دهد تا تمام رکوردها را از جدول حساب‌ها بازگرداند. حملات خطرناک ترمی‌توانند داده ها را تغییر داده یا حذف کنند یا حتی دستورالعمل‌های ذخیره شده را فراخوانی کنند. </p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div> 

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### <div dir="rtl" align="right">خارجی</div>

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
