# A10:2025 Nesprávné zpracování výjimečných stavů (Mishandling of Exceptional Conditions) ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Nesprávné zpracování výjimečných stavů je nová kategorie pro rok 2025. Tato kategorie obsahuje 24 CWE a zaměřuje se na nesprávné zpracování chyb (error handling), logické chyby, failing open (tj. pokračování i po chybě) a další související scénáře vyplývající z abnormálních stavů, se kterými se systémy mohou setkat. Tato kategorie obsahuje některé CWE, které byly dříve spojovány se špatnou kvalitou kódu. To bylo pro nás příliš obecné; podle našeho názoru poskytuje tato konkrétnější kategorie lepší vodítko.

Mezi významné CWE zahrnuté v této kategorii patří: *CWE-209 Generation of Error Message Containing Sensitive Information, CWE-234 Failure to Handle Missing Parameter, CWE-274 Improper Handling of Insufficient Privileges, CWE-476 NULL Pointer Dereference,* a *CWE-636 Not Failing Securely ('Failing Open')*.


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
   <td>24
   </td>
   <td>20,67 %
   </td>
   <td>2,95 %
   </td>
   <td>100,00 %
   </td>
   <td>37,95 %
   </td>
   <td>7,11
   </td>
   <td>3,81
   </td>
   <td>769 581
   </td>
   <td>3 416
   </td>
  </tr>
</table>



## Popis

K nesprávnému zpracování výjimečných stavů v softwaru dochází, když programy nedokážou zabránit tomu, aby nastaly neobvyklé a nepředvídatelné situace, nedokážou je detekovat a reagovat na ně, což vede k selháním, neočekávanému chování a někdy i ke zranitelnostem. Může se jednat o jednu nebo více z následujících tří nedostatků: aplikace nezabrání vzniku neobvyklé situace, nedokáže identifikovat situaci v okamžiku, kdy k ní dochází, a/nebo na ni reaguje špatně nebo vůbec.

 

Výjimečné stavy mohou být způsobeny chybějící, špatnou nebo neúplnou validací vstupů, pozdním zpracováním chyb (error handling) na vysoké úrovni namísto ve funkcích, kde k nim dochází, nebo neočekávanými stavy prostředí, jako jsou problémy s pamětí, oprávněními nebo sítí, nekonzistentním zpracováním výjimek nebo výjimkami, které nejsou zpracovány vůbec, což umožňuje systému upadnout do neznámého a nepředvídatelného stavu. Kdykoli si aplikace není jistá svým dalším pokynem, došlo k nesprávnému zpracování výjimečného stavu. Těžko zjistitelné chyby a výjimky mohou dlouhodobě ohrožovat bezpečnost celé aplikace.

 

Když výjimečné stavy zpracujeme nesprávně, může dojít k mnoha různým bezpečnostním zranitelnostem, jako jsou logické chyby, přetečení, souběhy (race conditiony; též „závodní stavy“), podvodné transakce nebo problémy s pamětí, stavem, zdroji, načasováním, ověřováním a autorizací. Tyto typy zranitelností mohou negativně ovlivnit důvěrnost, dostupnost a/nebo integritu systému nebo jeho dat. Útočníci manipulují s chybným zpracováním chyb aplikace, aby tyto zranitelnosti využili. 


## Jak tomu zabránit

Abychom mohli výjimečný stav správně zpracovat, musíme na takové situace plánovat (očekávat nejhorší). Musíme „zachytit“ každou možnou systémovou chybu přímo v místě, kde k ní dochází, a poté ji zpracovat (tj. udělat něco smysluplného k vyřešení problému a zajistit, že se z něj zotavíme). Součástí zpracování by mělo být vyvolání chyby (aby byl uživatel informován srozumitelným způsobem), logování události a také vyvolání upozornění (alertu), pokud to považujeme za oprávněné. Měli bychom mít také globální handler výjimek (globální obsluhu/zpracování výjimek) pro případ, že nám něco unikne. V ideálním případě bychom měli mít také nástroje nebo funkcionalitu pro monitoring a/nebo observability, které sledují opakované chyby nebo vzorce naznačující probíhající útok a které mohou vyvolat nějakou reakci, obranu nebo blokování. To nám může pomoci blokovat a reagovat na skripty a boty, které se zaměřují na slabiny našeho zpracování chyb.

 

Zachytávání a zpracování výjimečných stavů zajišťuje, že základní infrastruktura našich programů není ponechána, aby se vypořádávala s nepředvídatelnými situacemi. Pokud jste uprostřed jakékoli transakce, je mimořádně důležité, abyste provedli rollback každé její části a začali znovu (také známé jako fail closed). Pokus o zotavení transakce uprostřed jejího průběhu je často místem, kde vznikají nevratné chyby.

 

Kdykoli je to možné, přidejte rate limiting, kvóty zdrojů, throttling (omezení) a další limity, abyste výjimečným stavům předcházeli už na začátku. V informačních technologiích by nic nemělo být bez limitu, protože to vede k nízké odolnosti aplikací, odmítnutí služby, úspěšným brute force útokům a mimořádně vysokým účtům za cloud. Zvažte, zda by identické opakované chyby nad určitou míru neměly být vypisovány pouze jako statistiky ukazující, jak často nastaly a v jakém časovém rámci. Tyto informace by měly být připojeny k původní zprávě tak, aby nenarušovaly automatizované logování a monitorování, viz [A09:2025 Selhání bezpečnostního logování a upozorňování (Security Logging & Alerting Failures)](A09_2025-Security_Logging_and_Alerting_Failures.md).

Kromě toho bychom chtěli zahrnout přísnou validaci vstupů (se sanitizací (očištěním) nebo escapováním potenciálně nebezpečných znaků, které musíme akceptovat), centralizované zpracování chyb, logování, monitorování a upozorňování a globální obsluhu výjimek (global exception handler). Jedna aplikace by neměla mít více funkcí pro zpracování výjimečných stavů; mělo by se to provádět na jednom místě, pokaždé stejným způsobem. Měli bychom také vytvořit bezpečnostní požadavky projektu pro všechna doporučení v této části, provést threat modelling (modelování hrozeb) a/nebo aktivity secure design review (bezpečnostní posouzení návrhu) ve fázi návrhu projektů, provést code review (revizi kódu) nebo statickou analýzu a také provést zátěžové, výkonnostní a penetrační testování finálního systému.

 

Pokud je to možné, měla by celá vaše organizace zpracovávat výjimečné stavy stejným způsobem, protože to usnadňuje kontrolu a audit kódu z hlediska chyb v této důležité bezpečnostní kontrole.


## Příklady scénářů útoků 

**Scénář #1:** K vyčerpání zdrojů v důsledku nesprávného zpracování výjimečných stavů (Denial of Service) může dojít, pokud aplikace při nahrávání souborů zachytává výjimky, ale poté řádně neuvolňuje zdroje. Každá nová výjimka zanechává zdroje uzamčené nebo jinak nedostupné, dokud nejsou všechny zdroje vyčerpány.

**Scénář #2:** Odhalení citlivých údajů v důsledku nesprávného zpracování nebo databázových chyb, které uživateli zobrazí kompletní systémovou chybu. Útočník pokračuje ve vyvolávání chyb, aby mohl citlivé systémové informace využít k vytvoření účinnějšího útoku typu SQL injection. Citlivé údaje v chybových hlášeních pro uživatele jsou součástí průzkumu (reconnaissance).

**Scénář #3:** Poškození stavu finančních transakcí může být způsobeno útočníkem, který přeruší vícekrokovou transakci narušením síťového spojení. Představte si, že sled kroků transakce je: odepsat z účtu uživatele, připsat na účet příjemce, zaznamenat transakci. Pokud systém při chybě uprostřed transakce správně nevrátí zpět (rollback) celou transakci (fail closed), útočník by mohl potenciálně vyprázdnit účet uživatele, nebo může dojít k souběhu (race condition), který útočníkovi umožní odeslat peníze příjemci vícekrát.


## Reference

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/) 

## Seznam mapovaných CWE
* [CWE-209	Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215	Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234	Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235	Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248	Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252	Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274	Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280	Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369	Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390	Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391	Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394	Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396	Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397	Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460	Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476	NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478	Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484	Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550	Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636	Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703	Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754	Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755	Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756	Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)
