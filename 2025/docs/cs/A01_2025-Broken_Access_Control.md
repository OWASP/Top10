#  A01:2025 Narušené řízení přístupu (Broken Access Control) ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}



## Pozadí

Tato kategorie si udržuje první místo v žebříčku Top Ten. U 100 % testovaných aplikací byla zjištěna určitá forma narušeného řízení přístupu. Mezi významné související slabiny (CWE) patří zejména *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201: Exposure of Sensitive Information Through Sent Data*, *CWE-918 Server-Side Request Forgery (SSRF)* a *CWE-352: Cross-Site Request Forgery (CSRF)*. Tato kategorie vykazuje v poskytnutých datech nejvyšší počet výskytů a zároveň druhý nejvyšší počet souvisejících zranitelností (CVE).


## Tabulka skóre


<table>
  <tr>
   <td>Počet mapovaných CWE 
   </td>
   <td>Max míra výskytu
   </td>
   <td>Průměrná míra výskytu
   </td>
   <td>Max pokrytí
   </td>
   <td>Průměrné pokrytí
   </td>
   <td>Průměrná vážená míra zneužitelnosti
   </td>
   <td>Průměrný vážený dopad
   </td>
   <td>Celkový počet výskytů
   </td>
   <td>Celkový počet CVE
   </td>
  </tr>
  <tr>
   <td>40
   </td>
   <td>20,15 %
   </td>
   <td>3,74 %
   </td>
   <td>100,00 %
   </td>
   <td>42,93 %
   </td>
   <td>7,04
   </td>
   <td>3,84
   </td>
   <td>1 839 701
   </td>
   <td>32 654
   </td>
  </tr>
</table>



## Popis 

Řízení přístupu vynucuje bezpečnostní politiku tak, aby uživatelé nemohli vykonávat činnosti mimo rozsah jim určených oprávnění. Selhání řízení přístupu typicky vedou k neoprávněnému zpřístupnění informací, k neoprávněné změně nebo zničení dat, případně k provádění aplikačních nebo obchodních funkcí mimo oprávnění daného uživatele. Mezi běžné zranitelnosti v oblasti řízení přístupu patří:



* Porušení principu nejmenších oprávnění (princip „deny by default“), kdy má být přístup povolen pouze ke konkrétním funkcím, rolím nebo uživatelům, avšak ve skutečnosti je dostupný komukoli.
* Obcházení kontrol řízení přístupu úpravou URL (manipulace s parametry nebo force browsing), změnou vnitřního stavu aplikace nebo HTML stránky, případně použitím nástroje, který modifikuje API požadavky.
* Umožnění zobrazení nebo úpravy cizího účtu na základě znalosti jeho jedinečného identifikátoru (Insecure Direct Object Reference – IDOR).
* Veřejně přístupné API s chybějícími kontrolami řízení přístupu pro metody POST, PUT a DELETE.
* Eskalace oprávnění, tedy jednání jako přihlášený uživatel bez autentizace nebo získání oprávnění nad rámec oprávnění odpovídajících přihlášenému uživateli (např. administrátorský přístup).
* Manipulace s metadaty, například opakované použití nebo pozměnění přístupového tokenu JSON Web Token (JWT), manipulace s cookie nebo skrytým formulářovým polem za účelem zvýšení oprávnění, případně zneužití mechanismu zneplatňování JWT.
* Chybná konfigurace CORS, která umožňuje přístup k API z neoprávněných nebo nedůvěryhodných zdrojů.
* Force browsing (hádání URL) umožňující přístup k autentizovaným stránkám jako neautentizovaný uživatel nebo k privilegovaným stránkám jako běžný uživatel.


## Jak tomu zabránit 

Řízení přístupu je účinné pouze tehdy, pokud je implementováno v důvěryhodném kódu na straně serveru nebo v serverless API, kde útočník nemůže ovlivnit samotnou kontrolu řízení přístupu ani související metadata.



* S výjimkou veřejných zdrojů musí být přístup implicitně zakázán (deny by default).
* Mechanismy řízení přístupu by měly být implementovány jednou a znovupoužitelné v celé aplikaci; zároveň by mělo být omezeno používání Cross-Origin Resource Sharing (CORS).
* Řízení přístupu na úrovni aplikačních modelů musí vynucovat vazbu mezi uživatelem (nebo jiným subjektem) a konkrétními datovými záznamy, nikoli umožňovat uživatelům vytvářet, číst, upravovat nebo mazat libovolné záznamy.
* Jedinečné byznys limity aplikace musí být vynucovány na úrovni doménových modelů.
* Na webovém serveru musí být zakázán výpis adresářů a je nutné zajistit, aby se ve webovém kořeni nenacházela metadata repozitářů (např. .git) ani záložní soubory.
* Porušení řízení přístupu musí být logována a v odůvodněných případech (např. při opakovaných selháních) musí být administrátoři upozorněni.
* Pro přístup k API a kontrolerům musí být uplatněn rate limiting, aby se omezily dopady automatizovaných útočných nástrojů.
* Stavové identifikátory relací musí být po odhlášení na straně serveru zneplatněny. Bezstavové tokeny JWT by měly mít krátkou dobu platnosti, aby se minimalizovalo časové okno pro jejich zneužití. U JWT s delší dobou platnosti je vhodné použít refresh tokeny a postupy dle standardů OAuth pro odvolání přístupu.
* Doporučuje se používat zavedené knihovny nebo návrhové vzory, které poskytují jednoduché a deklarativní řízení přístupu.

Vývojáři i pracovníci QA by měli zahrnout funkční testování řízení přístupu do jednotkových i integračních testů.


## Příklady scénářů útoků 

**Scénář #1:** Aplikace používá neověřená data v SQL dotazu, který přistupuje k informacím o účtu:


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
```


Útočník může jednoduše upravit parametr acct v prohlížeči a odeslat libovolné číslo účtu. Pokud není hodnota správně ověřena, útočník může získat přístup k účtu jiného uživatele.


```
https://example.com/app/accountInfo?acct=notmyacct
```


**Scénář #2:** Útočník jednoduše přistupuje k URL adresám přímo. Přístup na administrační stránku vyžaduje administrátorská oprávnění.


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


Pokud má neautentizovaný uživatel přístup k některé z těchto stránek, jedná se o chybu. Pokud má uživatel bez administrátorských oprávnění přístup k administrační stránce, jedná se rovněž o chybu.

**Scénář #3:** Aplikace má veškeré řízení přístupu implementováno pouze na straně klienta (front-endu). Přestože se útočník nemůže dostat na adresu `https://example.com/app/admin_getappInfo` kvůli JavaScriptovému kódu spuštěnému v prohlížeči, může jednoduše spustit následující příkaz z příkazové řádky:


```
$ curl https://example.com/app/admin_getappInfo
```

## Reference

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## Seznam mapovaných CWE

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)

* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)

* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)

* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)

* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)

* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)

* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)

* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)

* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
