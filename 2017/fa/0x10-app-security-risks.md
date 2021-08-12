# <div dir="rtl" align="right">ریسک‌های امنیتی برنامه کاربردی</div>

## <div dir="rtl" align="right">ریسک‌های امنیتی برنامه کاربردی چه مواردی هستند؟</div>

<p dir="rtl" align="right">
مهاجمان به طور بالقوه می‌توانند از راه‌‌های مختلفی و از طریق برنامه کاربردی شما، به کسب و کار یا سازمان شما آسیب برسانند. هر یک از این راه‌ها بیانگر یک ریسک است که ممکن است به اندازه کافی که درخور توجه و جدی باشد یا نباشد.
</p>

![App Security Risks](images/0x10-risk-1.png)

<p dir="rtl" align="right">
  گاهی کشف و بهره جویی از این مسیرها آسان و گاهی بسیار دشوار است. به همین شکل، آسیب ناشی از آن ممکن است هیچ نتیجه‌ای نداشته باشد، یا ممکن است شما را از کسب و کار بیرون کند. برای تعیین خطر برای سازمان، شما می‌توانید احتمال هر عامل تهدید، بردار حمله و ضعف امنیتی را ارزیابی کنید و آن را با برآوردی از تأثیرات فنی و تجاری روی سازمان خود ترکیب کنید. این عوامل با هم، ریسک کلی شما را تعیین می‌کنند.
</p>

## <div dir="rtl" align="right">ریسک من چیست؟</div>

<p dir="rtl" align="right"><a href="https://www.owasp.org/index.php/Top10">OWASP Top 10</a>
روی شناسایی جدی‌ترین ریسک‌ها برای مجموعه وسیعی از سازمان ها متمرکز است. برای هر یک از این ریسک‌ها، ما اطلاعات کلی درباره احتمال و تأثیر فنی را با استفاده از رهنمود ساده پیش رو ارزیابی می‌کنیم که بر اساس <a href="https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology">روش رتبه بندی ریسک OWASP</a> است.
</p> 

| عوامل تهدید | قابل بهره‌برداری بودن | شیوع ضعف | قابل تشخیص بودن ضعف | اثر تکنیکال | تاثیرات کسب و کار |
| -- | -- | -- | -- | -- | -- |
| ویژه -   | ساده: ۳ | شایع: ۳ | ساده: ۳ | شدید: ۳ | مختص -     |
|  برنامه -  | متوسط: ۲ | عمومی: ۲ | متوسط: ۲ | متعادل: ۲ | کسب و -  |
|     کاربردی   | سخت: ۱ | نادر: ۱ | سخت: ۱ | جزئی: ۱ |     کار   |

<p dir="rtl" align="right">در این ویرایش، سیستم رتبه بندی ریسک را به روز کرده‌ایم تا کار محاسبه احتمال و تأثیر هرگونه ریسک داده شده را تسهیل کنیم. برای اطلاعات بیشتر، لطفا <a href="https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology">یادداشتی در مورد ریسک‌ها‌</a> را ببینید.
</p>

<p dir="rtl" align="right">
  هر سازمان و عوامل تهدید کننده آن، اهداف آنها و تأثیر هرگونه نقض، منحصر به فرد هستند. اگر یک سازمان عمومی ‌با استفاده از یک سیستم مدیریت محتوا (CMS) برای اطلاعات عمومی ‌و یک سیستم مربوط به بهداشت و سلامت، دقیقاً از همان CMS برای داده‌های حساس مربوط به سلامتی استفاده کند، تهدید کننده‌ها و تأثیرات تجاری می‌توانند برای این نرم افزار مشابه، بسیار متفاوت باشند. درک خطرات سازمان شما بر اساس عوامل تهدید قابل اجرا و تأثیرات تجاری بسیار مهم است.
</p>

<p dir="rtl" align="right">
  هر جا که امکان داشته، نام ریسک‌ها در Top 10 با <a href="https://cwe.mitre.org/data/definitions/22.html">فهرست ضعف های عمومی</a> ‌(CWE) به منظور ارتقای شیوه‌های نامگذاری پذیرفته شده و کاهش سردرگمی، مطابقت داده شده است.
</p>

## <div dir="rtl" align="right">منابع</div>

### <div dir="rtl" align="right"></div>OWASP

* [OWASP Risk Rating Methodology](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Article on Threat/Risk Modeling](https://www.owasp.org/index.php/Threat_Risk_Modeling)

### <div dir="rtl" align="right">خارجی</div> 

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
