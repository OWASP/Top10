# <div dir="rtl" align="right">A4:2017 XML External Entities (XXE)</div> 

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : قابلیت بهره‌برداری: ۳ | شیوع: ۲ : قابل کشف بودن: ۳ | تکنیکی: ۳ : Business ? |
| <div dir="rtl" align="right">اگر مهاجمان بتوانند XML بارگذاری کنند یا محتوای آلوده در یک سندXML  وارد کنند، از کد ها، وابستگی ها یا ادغام های آسیب پذیر استفاده کنند، می‌توانند از پردازنده های XML آسیب پذیر برای مقاصد خود بهره جویی کنند.</div> | <div dir="rtl" align="right"> به طور پیش فرض، بسیاری از پردازنده های قدیمی‌ترXML  اجازه تعیین یک موجود خارجی را می‌دهند. ( یک URI  که در پردازش XML  محاسبه و ارزیابی می‌شود.)ابزارهای <a href="https://wiki.owasp.org/index.php/Source_Code_Analysis_Tools">SAST</a> می‌تواند این مسئله را با بررسی وابستگی ها و پیکربندی کشف کند. ابزارهای <a href="https://wiki.owasp.org/index.php/Category:Vulnerability_Scanning_Tools">DAST</a> نیاز به مراحل دستی بیشتر برای شناسایی و بهره جویی از این مسئله دارند. آزمایش کنندگان دستی باید برای چگونگی آزمایش XXE آموزش ببینند، زیرا معمولا از سال 2017 آزمایش نشده اند.</div> | <div dir="rtl" align="right">این نقص ها می‌تواند برای استخراج داده ها، اجرای یک درخواست از راه دور از سمت سرور، اسکن سیستم های داخلی، انجام حمله اختلال در سرویس و همچنین اجرای سایر حملات استفاده شود.تأثیر کسب و کار بستگی به الزامات حفاظتی همه برنامه های کاربردی متاثر و داده ها دارد.</div> |

## <div dir="rtl" align="right">آیا برنامه کاربردی آسیب‌پذیر است؟</div>

<p dir="rtl" align="right">برنامه های کاربردی و به ویژه سرویس های وب مبتنی بر XML و یا ادغام های پایین دست (downstream integrations) ممکن است در شرایط زیر برای حمله آسیب پذیر باشند:</p>

<ul dir="rtl" align="right">
  <li>
    برنامه های XML را به طور مستقیم یا آپلودهای XML را قبول می‌کند، به خصوص از منابع نامشخص، یا داده های غیر قابل اعتماد را به اسناد XML وارد می‌کند و سپس توسط یک پردازنده XML پردازش می‌شود.
  </li>
  <li>
    هر یک از پردازنده‌های XML در برنامه های کاربردی یا وب سرویس های مبتنی بر <a href="https://en.wikipedia.org/wiki/Document_type_definition">SOAP، document type definitions (DTDs)</a> ها را فعال کرده اند. به عنوان مکانیزم دقیق برای غیرفعال کردن پردازش DTD، بهترین کار، استفاده از مرجعی مانند<a href="https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet">OWASP Cheat Sheet 'XXE Prevention'</a>. است.
</li>
  <li>اگر برنامه کاربردی شما از SAML برای پردازش هویت در خلال امنیت یکپارچه یا اهداف SSO استفاده می‌کند. SAML از XML برای اثبات هویت استفاده می‌کند و ممکن است آسیب پذیر باشد.
</li>
  <li>اگر برنامه کاربردی از SOAP قبل از نسخه 1.2 استفاده کند، احتمالا حساس به حملات XXE است اگر موجودیت های XML به چارچوب SOAP منتقل شوند.</li>
  <li>آسیب پذیر بودن به حملات XXE به این معنی است که برنامه به حملات اختلال سرویس، از جمله حمله Billion Laughs، آسیب پذیر است.</li>
</ul>

## <div dir="rtl" align="right">نحوه پیشگیری از حمله:</div>

<p dir="rtl" align="right">آموزش توسعه دهندگان برای شناسایی و مقابله با XXE ضروری است. جدای از این، جلوگیری از XXE نیازمندی های زیر را دارد:</p>

<ul dir="rtl" align="right">
  <li>هر زمان که امکان دارد، از فرمت های داده‌ای پیچیده مانند JSON کمتر استفاده شود و از سریال سازی اطلاعات حساس اجتناب گردد.</li>
  <li>وصله امنیتی یا ارتقاء تمام پردازنده های XML و کتابخانه هایی که توسط برنامه کاربردی یا سیستم عامل اصلی استفاده می‌شود. از بررسی کننده های وابستگی استفاده کنید. SOAP به SOAP 1.2 یا بالاتر به روز رسانی کنید.
  </li>
  <li>
    موجودیت خارجی XML و پردازش DTD در تمام پارسرهایXML  در برنامه را غیر فعال کنید، با توجه به در برنامه را غیر فعال کنید، همانطور که در<a href="https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet"> OWASP Cheat Sheet 'XXE  Preventtion</a>.
  </li>
  <li>اعتبار سنجی ورودی، فیلتر کردن و یا پاکسازی ورودی را در سمت سرور برای جلوگیری از انتقال اطلاعات خصمانه در اسناد XML، هدرها یا گره ها پیاده سازی کنید.</li>
  <li>قابلیت آپلود فایل XML یا XSL، ورودی XML را با استفاده از اعتبارسنجی XSD یا مشابه آن را اعتبار سنجی کنید.</li>
  <li>ابزارهایSAST می‌تواند به شناسایی XXE در کد منبع برنامه کمک کند، اگرچه بررسی دستی کد بهترین گزینه در برنامه های بزرگ و پیچیده است.</li>
  <li>اگر این کنترل ها امکان پذیر نیست، از وصله های مجازی، دروازه های امنیتی  API یا فایروال های وب (WAF) برای شناسایی، نظارت و توقف حملات XXE استفاده کنید. </li>
</ul>

## <div dir="rtl" align="right">نمونه‌هایی از سناریوهای حمله</div>

<p dir="rtl" align="right">مشکلات متعدد XXE عمومی‌کشف شده است، از جمله حمله به دستگاه های Embedded XXE در بسیاری از مکان های غیر منتظره، از جمله وابستگی های عمیق nested رخ می‌دهد. ساده ترین راه این است که فایل XML مخرب را آپلود کنید، اگر قبول شود:</p>

<p dir="rtl" align="right"><strong>سناریو # 1: </strong>مهاجم تلاش می‌کند تا داده ها را از سرور استخراج کند:</p>

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

<p dir="rtl" align="right"><strong>سناریو # 2: </strong>مهاجم شبکه خصوصی سرور را با تغییر خط ENTITY بالا به خط زیر کاوش می‌کند:</p>

```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```
<p dir="rtl" align="right"><strong>سناریو # 3: </strong>یک مهاجم با استفاده از یک فایل بالقوه بی پایان، تلاش برای حمله منع سرویس می‌کند:</p>

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right">OWASP</div>

* [OWASP Application Security Verification Standard](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://wiki.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://wiki.owasp.org/index.php/XML_Security_Cheat_Sheet)

### <div dir="rtl" align="right">خارجی</div> 

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
