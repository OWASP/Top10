# <div dir="rtl" align="right">توجهات این نسخه</div> 

## <div dir="rtl" align="right">از 2013 تا 2017 چه چیزهایی تغییر کرده اند؟</div>

<p dir="rtl" align="right">تغییرات در سال های اخیر شتاب گرفته اند و  OWASP TOP 10 به تغییر احتیاج داشت. ما به صورت کامل OWASP TOP 10  را از لحاظ ساختاری تغییر داده ایم و متدولوژی آن را مورد بازنگری قرار داده ایم. یک پروسه درخواست دیتا که با جامعه در ارتباط است تبیین کرده ایم،‌ خطرات را مجددا در دستور کار قرار داده ایم و هر خطر را مجددا از ابتدا نوشته ایم. و به فریمورک ها و زبان هایی که در حال حاضر به طور عمومی استفاده میشوند منابعی را اضافه کرده ایم.</p>
<p dir="rtl" align="right"></p>
Over the last few years, the fundamental technology and architecture of applications has changed significantly:

* Microservices written in node.js and Spring Boot are replacing traditional monolithic applications. Microservices come with their own security challenges including establishing trust between microservices, containers, secret management, etc. Old code never expected to be accessible from the Internet is now sitting behind an API or RESTful web service to be consumed by Single Page Applications (SPAs) and mobile applications. Architectural assumptions by the code, such as trusted callers, are no longer valid.
* Single page applications, written in JavaScript frameworks such as Angular and React, allow the creation of highly modular feature-rich front ends. Client-side functionality that has traditionally been delivered server-side brings its own security challenges.
* JavaScript is now the primary language of the web with node.js running server side and modern web frameworks such as Bootstrap, Electron, Angular, and React running on the client.

## <div dir="rtl" align="right">مشکلات جدیدی که با دیتا ساپورت میشوند:</div>

* **A4:2017-XML External Entities (XXE)** is a new category primarily supported by source code analysis security testing tools ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) data sets.

## <div dir="rtl" align="right">مشکلات جدیدی که توسط جامعه ساپورت میشوند:</div>

We asked the community to provide insight into two forward looking weakness categories. After over 500 peer submissions, and removing issues that were already supported by data (such as Sensitive Data Exposure and XXE), the two new issues are: 

* **A8:2017-Insecure Deserialization**, which permits remote code execution or sensitive object manipulation on affected platforms.
* **A10:2017-Insufficient Logging and Monitoring**, the lack of which can prevent or significantly delay malicious activity and breach detection, incident response, and digital forensics.

## <div dir="rtl" align="right">مرج شده یا بازنشسته شده، اما فراموش نشده : </div> 

* **A4-Insecure Direct Object References** and **A7-Missing Function Level Access Control** merged into **A5:2017-Broken Access Control**.
* **A8-Cross-Site Request Forgery (CSRF)**, as many frameworks include [CSRF defenses](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)), it was found in only 5% of applications.
* **A10-Unvalidated Redirects and Forwards**, while found in approximately in 8% of applications, it was edged out overall by XXE.

![0x06-release-notes-1](images/0x06-release-notes-1.png)
