# A08:2025 Selhání integrity softwaru nebo dat (Software or Data Integrity Failures) ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Pozadí

Selhání integrity softwaru nebo dat zůstává na 8. místě, s mírnou, upřesňující změnou názvu z „Selhání integrity softwaru *a* dat“. Tato kategorie se zaměřuje na selhání v udržování hranic důvěry (trust boundaries) a ověřování integrity softwaru, kódu a datových artefaktů na nižší úrovni než selhání dodavatelského řetězce softwaru. Tato kategorie se zaměřuje na vytváření předpokladů souvisejících s aktualizacemi softwaru a kritickými daty bez ověření jejich integrity. Mezi významné Common Weakness Enumerations (CWE) patří *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, *CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes*, and *CWE-502: Deserialization of Untrusted Data*.

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
   <td>Průměrná vážená zneužitelnost
   </td>
   <td>Průměrný vážený dopad
   </td>
   <td>Celkový počet výskytů
   </td>
   <td>Celkový počet CVE
   </td>
  </tr>
  <tr>
   <td>14
   </td>
   <td>8,98 %
   </td>
   <td>2,75 %
   </td>
   <td>78,52 %
   </td>
   <td>45,49 %
   </td>
   <td>7,11
   </td>
   <td>4,79
   </td>
   <td>501 327
   </td>
   <td>3 331
   </td>
  </tr>
</table>



## Popis

Selhání integrity softwaru a dat souvisí s kódem a infrastrukturou, které nechrání před tím, aby neplatný nebo nedůvěryhodný kód či data byly považovány za důvěryhodné a platné. Příkladem je situace, kdy aplikace využívá pluginy, knihovny nebo moduly z nedůvěryhodných zdrojů, repozitářů a sítí pro doručování obsahu (Content Delivery Network, CDN). Nezabezpečená CI/CD pipeline, aniž by využívala a poskytovala kontroly integrity softwaru, může zavést možnost neoprávněného přístupu, nezabezpečeného nebo škodlivého kódu či kompromitace systému. Dalším příkladem je CI/CD, které stahuje kód nebo artefakty z nedůvěryhodných míst a/nebo je před použitím neověřuje (kontrolou podpisu nebo podobným mechanismem). A konečně, mnoho aplikací nyní obsahuje funkci automatické aktualizace, kdy jsou aktualizace stahovány bez dostatečného ověření integrity a aplikovány na dříve důvěryhodnou aplikaci. Útočníci by potenciálně mohli nahrát vlastní aktualizace, které by byly distribuovány a spuštěny na všech instalacích. Dalším příkladem je situace, kdy jsou objekty nebo data enkódována nebo serializována do struktury, kterou útočník může vidět a upravovat; takový návrh je zranitelný vůči nezabezpečené deserializaci.


## Jak tomu zabránit



* Používejte digitální podpisy nebo podobné mechanismy k ověření, že software nebo data pocházejí z očekávaného zdroje a nebyly pozměněny.
* Zajistěte, aby knihovny a závislosti (např. npm nebo Maven) čerpaly pouze z důvěryhodných repozitářů. Pokud máte vyšší rizikový profil, zvažte hostování interního ověřeného („known-good“) repozitáře, který je prověřen.
* Zajistěte, aby existoval proces revize změn kódu a konfigurace, který minimalizuje možnost, že by do vašeho softwarového pipeline mohl být zaveden škodlivý kód nebo konfigurace.
* Zajistěte, aby vaše CI/CD pipeline měla řádnou segregaci, konfiguraci a řízení přístupu, aby byla zajištěna integrita kódu procházejícího procesy sestavení a nasazení.
* Zajistěte, aby nepodepsaná nebo nešifrovaná serializovaná data nebyla přijímána od nedůvěryhodných klientů a následně používána bez nějaké formy kontroly integrity nebo digitálního podpisu k detekci manipulace nebo opětovného přehrání (replay) serializovaných dat.


## Příklady scénářů útoků 

**Scénář #1 Zahrnutí webové funkcionality z nedůvěryhodného zdroje:** Společnost využívá externího poskytovatele služeb pro zajištění podpory. Pro zjednodušení má nastavené mapování DNS z myCompany.SupportProvider.com na support.myCompany.com. To znamená, že všechny cookies nastavené pro doménu myCompany.com, včetně autentizačních cookies, jsou nyní odesílány poskytovateli podpory. Kdokoli s přístupem k infrastruktuře poskytovatele podpory může odcizit cookies všech uživatelů, kteří navštívili support.myCompany.com, a provést únos relace (session hijacking).

**Scénář #2 Aktualizace bez podpisu:** Mnoho domácích routerů, set-top boxů, firmwaru zařízení a dalších zařízení neověřuje aktualizace pomocí podepsaného firmwaru. Nepodepsaný firmware je rostoucím cílem útočníků a očekává se, že se situace bude jen zhoršovat. To je velký problém, protože často neexistuje jiný mechanismus nápravy než provést opravu v budoucí verzi a počkat, až starší verze postupně „dožijí“ (budou vyřazeny).

**Scénář #3 Použití balíčku z nedůvěryhodného zdroje:** Vývojář má potíže s nalezením aktualizované verze balíčku, který hledá, a proto jej nestáhne z běžného, důvěryhodného správce balíčků, ale z webové stránky. Balíček není podepsán, a proto není možnost zajistit jeho integritu. Balíček obsahuje škodlivý kód.

**Scénář #4 Nezabezpečená deserializace:** Aplikace využívající React volá sadu mikroslužeb Spring Boot. Jako funkcionální programátoři se snažili zajistit, aby jejich kód byl neměnný. Řešení, se kterým přišli, je serializovat stav uživatele a předávat jej tam a zpět s každým požadavkem. Útočník si všimne signatury Java objektu „rO0“ (v base64) a pomocí [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) získá možnost vzdáleného spuštění kódu na aplikačním serveru.

## Reference

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)


## Seznam mapovaných CWE

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

* [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

* [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

* [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

* [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)

* [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

* [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

* [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

* [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
