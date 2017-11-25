# A4:2017 XML External Entities (XXE)

| ผู้โจมตี/ช่องทาง | จุดอ่อนด้านความปลอดภัย           | ผลกระทบ               |
| -- | -- | -- |
| การเข้าถึงช่องโหว่ : ความยากในการโจมตี 2 | แพร่กระจายง่าย 2 : ตรวจพบได้ง่าย 3 | ผลกระทบทางเทคนิค 3 : ผลกระทบทางธุรกิจ ? |
| ผู้โจมตีสามารถโจมตีตัวประมวลผล XML ในกรณีที่สามารถอัพโหลดหรือใส่ข้อมูลประเภท XML ไปประมวลผลบนฝั่งเซิร์ฟเวอร์ได้ เทคนิคการโจมตีช่องโหว่ XXE ขึ้นอยู่กับหลายปัจจัยทั้งระบบปฏิบัติการณ์และซอฟต์แวร์ที่ใช้ในประมวลผล XML ที่ถูกโจมตี | โดยทั่วไปแล้ว ตัวประมวลผล XML ยอมให้ใส่ค่าที่เรียกว่า external entity ได้ ซึ่งคือ URI ที่ถูกอ้างอิงถึงแล้วนำมาประมวลผลเป็นส่วนนึงของเอกสาร XML และทำให้เกิดอันตรายได้, โปรแกรมหาช่องโหว่อัตโนมัติในระดับโค้ด ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) สามารถหาช่องโหว่และการตั้งค่าที่ยอมให้ใช้ external entity ได้ดี ส่วนโปรแกรมหาช่องโหว่อัตโนมัติในขณะที่โปรแกรมทำงานอยู่ ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) จะต้องมีการยืนยันเพิ่มเติมโดยใช้ผู้ทดสอบระบบที่เชี่ยวชาญเพื่อให้แน่ใจว่ามีช่องโหว่จริง และสุดท้าย การทดสอบหาช่องโหว่แบบ manual ผู้ทดสอบระบบควรจะต้องมีการศึกษาเรียนรู้เพิ่มเติมว่าจะทดสอบ XXE ยังไง เนื่องจาก เป็นช่องโหว่ที่มักจะถูกมองข้ามจากสถิติในปี 2017 | ช่องโหว่ XXE สามารถใช้ในการอ่านข้อมูลจากไฟล์บนเครื่องเซิร์ฟเวอร์, ใช้ส่งข้อมูลเน็ตเวิร์คจากเซิร์ฟเวอร์ที่มีช่องโหว่, ใช้สแกนเน็ตเวิร์คฝั่งภายในของเซิร์ฟเวอร์ที่มีช่องโหว่, ใช้โจมตีให้ระบบให้ไม่สามารถใช้งานได้ |

## แอพพลิเคชั่นนี้มีช่องโหว่หรือไม่?

แอพพลิเคชั่นต่าง ๆ โดยเฉพาะ web service แบบ SOAP ที่ส่งข้อมูลในรูปแบบ XML อาจจะมีช่องโหว่ XXE ได้ในกรณีที่:

* แอพพลิเคชั่นรับค่า XML โดยตรงผ่านการอัพโหลดจากผู้ใช้งานเข้ามาถึงตัวประมวลผล XML โดยไม่ได้มีการตรวจสอบหรือทำให้ปลอดภัยจากการใช้งาน external entity ก่อน
* เนื่องจากตัวประมวลผล XML ในแอพพลิเคชั่น โดยเฉพาะ web service แบบ SOAP มักจะมีฟีเจอร์ [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) เปิดอยู่ ซึ่งทำให้เกิด XXE เช่นกัน สิ่งที่ควรทำคือปิดฟีเจอร์ DTD แต่ว่าวิธีการปิดฟีเจอร์ DTD มักจะแตกต่างกันขึ้นกับ library ของตัวประมวลผล XML ในแต่ละเจ้า คำแนะนำคือลองอ่านเอกสาร [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet) เพื่อหาวิธีปิดฟีเจอร์ DTD ที่ถูกต้องเหมาะสม 
* ถ้าแอพพลิเคชั่นมีการใช้งาน SAML เพื่อยืนยันตัวตนของผู้ใช้งานแบบ single sign on (SSO) แปลว่าแอพพลิเคชั่นนั้น ๆ อาจมีช่องโหว่ XXE ได้ เพราะว่า SAML รับ-ส่ง ข้อมูลแบบ XML เช่นกัน
* ถ้าแอพพลิเคชั่นใช้ web service แบบ SOAP เวอร์ชั่นก่อน 1.2 จะมีโอกาสเป็นไปได้สูงมาก ว่าจะมีช่องโหว่ XXE ถ้ารับข้อมูล XML จากผู้ใช้งานเข้ามาประมวลผล
* การที่แอพพลิเคชั่นใด ๆ มีช่องโหว่ XXE เท่ากับว่ามีความเป็นไปได้ว่าแอพพลิเคชั่นนั้น ๆ จะมีช่องโหว่ที่ทำให้ระบบไม่สามารถใช้งานได้ด้วย เพราะว่าหนึ่งในเทคนิคที่ใช้โจมตีของ XXE ที่ชื่อว่า Billion Laughs อาจทำให้ระบบไม่สามารถใช้งานได้นั้นเอง

## ป้องกันอย่างไร

ผู้พัฒนาโปรแกรมจำเป็นจะต้องศึกษาวิธีการตรวจสอบและป้องกันช่องโหว่ XXE โดยสรุปแล้ว สิ่งที่ควรจะทำคือ:

* ถ้าเลือกได้ ควรเลือกใช้รูปแบบข้อมูลที่ไม่ใช่ XML เช่น JSON แทน และควรเลี่ยงรูปแบบข้อมูลที่มีการยอมให้ทำ serialization กับข้อมูลโดยเฉพาะข้อมูลที่มีความสำคัญ
* ปรับปรุงเวอร์ชั่นของตัวประมวลผล XML และ library ที่เกี่ยวข้องกับ XML ที่แอพพลิเคชั่นใช้รวมถึงที่ระบบปฏิบัติการณ์ใช้ เป็นเวอร์ชั่นใหม่เสมอ และควรตรวจ SOAP ที่ใช้ว่าเป็นเวอร์ชั่น 1.2 หรือใหม่กว่า
* ปิดฟีเจอร์การทำงานของ external entity และ DTD ในโค้ดหรือการตั้งค่าของแอพพลิเคชั่น ตามเอกสาร [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet). 
* ตรวจสอบข้อมูลฝั่งเซิร์ฟเวอร์แบบ whitelisting และแปลงข้อมูลที่อยู่ในเอกสาร XML ให้ปลอดภัยจากการเรียกใช้งานฟีเจอร์ external entity และ DTD ทั้งใน XML document, header และ node ต่าง ๆ
* ตรวจสอบให้แน่ใจว่า ฟีเจอร์ของแอพพลิเคชั่นที่ยอมให้อัพโหลดไฟล์ประเภท XML หรือ XSL มีการตรวจสอบข้อมูลใน XML ว่ามีข้อมูลที่ยอมให้ใส่ได้เท่านั้นด้วยการใช้ฟีเจอร์การยืนยันข้อมูลด้วย XSD 
* ถึงแม้ว่าโปรแกรมหาช่องโหว่อัตโนมัติในระดับโค้ด ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) สามารถช่วยหาช่องโหว่ XXE ในโค้ดได้ แต่การทดสอบ ด้วยการใช้ผู้ทดสอบระบบที่เชี่ยวชาญมาอ่านโค้ดก็ยังคงเป็นทางเลือกที่ดีที่สุด สำหรับแอพพลิเคชั่นที่มีความซับซ้อนสูง

ถ้าวิธีการป้องกันที่อ้างอิงถึงนี้ไม่สามารถใช้งานได้ ควรเลือกใช้เทคนิคอื่น ๆ เช่น virtual patching, API security gateways หรือใช้ Web Application Firewalls (WAFs) ในการช่วยตรวจจับ เฝ้าระวังและป้องกันการโจมตีแบบ XXE แทน

## ตัวอย่างของกระบวนการโจมตี

ช่องโหว่ XXE ที่ถูกค้นพบมีเยอะขึ้นมาก และบางส่วนถูกพบในระบบที่อยู่ในอุปกรณ์ประเภท embeded device (อุปกรณ์ขนาดเล็กที่มีคอมพิวเตอร์เช่นเร้าเตอร์และอุปกรณ์ IoT ต่าง ๆ) เนื่องจากใช้ XML และไม่ได้มีการตรวจสอบค่าที่ดีพอ ตัวอย่างที่ง่ายที่สุดคือเกิดจากการที่ยอมให้อัพโหลดไฟล์ XML ได้:

**Scenario #1**: ผู้โจมตีต้องการจะอ่านไฟล์ /etc/passwd จากเครื่องเซิร์ฟเวอร์ด้วยช่องโหว่ XXE สามารถทดลองส่ง XML ต่อไปนี้เข้าไปในแอพพลิเคชั่น:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Scenario #2**: ผู้โจมตีต้องการจะส่ง HTTP request ไปยัง private network ของเครื่องเซิร์ฟเวอร์ที่มีช่องโหว่ XXE สามารถทำได้โดยเปลี่ยนค่าบรรทัด ENTITY เป็นค่า URL ของเครื่องปลายทาง:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Scenario #3**: ผู้โจมตีต้องการจะทำการโจมตีให้เซิร์ฟเวอร์ไม่สามารถใช้งานได้โดยการลองอ่านค่าไฟล์ที่มีเนื้อหาไม่สิ้นสุดอย่าง /dev/random ด้วยวิธีดังต่อไปนี้:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## อ้างอิง

### จาก OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### จากแหล่งอื่น

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
