# A07:2025 Selhání autentizace (Authentication Failures) ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Selhání autentizace si udržuje 7. místo s mírnou změnou názvu, aby přesněji odráželo 36 CWE v této kategorii. Navzdory přínosům standardizovaných frameworků (rámců) si tato kategorie udržela 7. místo z roku 2021. Mezi významné CWE patří *CWE-259 Use of Hard-coded Password*, *CWE-297: Improper Validation of Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, *CWE-384: Session Fixation*, and *CWE-798 Use of Hard-coded Credentials*.


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
   <td>36
   </td>
   <td>15,80 %
   </td>
   <td>2,92 %
   </td>
   <td>100,00 %
   </td>
   <td>37,14 %
   </td>
   <td>7,69
   </td>
   <td>4,44
   </td>
   <td>1 120 673
   </td>
   <td>7 147
   </td>
  </tr>
</table>



## Popis

Tato zranitelnost je přítomna, pokud útočník dokáže oklamat systém tak, aby rozpoznal neplatného nebo nesprávného uživatele jako legitimního. K oslabení autentizace může dojít, pokud aplikace:

* Umožňuje automatizované útoky, jako je credential stuffing, kdy útočník má k dispozici prolomený seznam platných uživatelských jmen a hesel. V poslední době se tento typ útoku rozšířil tak, že zahrnuje i hybridní útoky na hesla v rámci credential stuffingu (známé také jako password spray útoky), kdy útočník používá variace nebo inkrementy uniklých přihlašovacích údajů k získání přístupu, například zkouší Password1!, Password2!, Password3! atd.

* Umožňuje brute force nebo jiné automatizované, skriptované útoky, které nejsou rychle blokovány.

* Umožňuje výchozí, slabá nebo dobře známá hesla, jako například Password1 nebo uživatelské jméno admin s heslem admin.

* Umožňuje uživatelům vytvářet nové účty s přihlašovacími údaji známými z dřívějších úniků.

* Umožňuje používat slabé nebo neúčinné procesy obnovy přihlašovacích údajů a „zapomenutého hesla“, například „odpovědi založené na znalostech“, které nelze učinit bezpečnými.

* Používá úložiště hesel v prostém textu, šifrovaná nebo slabě hashovaná (viz [A04:2025-Kryptografická selhání (Cryptographic Failures)](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)).

* Nemá vícefaktorové ověřování nebo je neúčinné.

* Umožňuje použití slabých nebo neúčinných náhradních mechanismů, pokud není k dispozici vícefaktorové ověřování.

* Vystavuje identifikátor relace v URL, ve skrytém poli („hidden“) nebo na jiném nezabezpečeném místě, které je klientovi dostupné.

* Po úspěšném přihlášení znovu používá stejný identifikátor relace.

* Při odhlášení nebo po určité době nečinnosti nesprávně zneplatňuje uživatelské relace nebo autentizační tokeny (zejména tokeny jednotného přihlášení (SSO)).

* Nevynucuje správně rozsah oprávnění (scope) a zamýšleného příjemce (audience) poskytnutých pověření (credentials).

## Jak tomu zabránit

* Pokud je to možné, implementujte a vynucujte používání vícefaktorového ověřování, abyste zabránili automatizovaným útokům typu credential stuffing, brute force a opětovnému použití odcizených přihlašovacích údajů.

* Pokud je to možné, podporujte a umožňujte používání správců hesel, aby uživatelům pomáhaly dělat lepší volby.

* Nezavádějte ani nenasazujte žádné výchozí přihlašovací údaje, zejména pro administrátorské účty.

* Implementujte kontroly slabých hesel, například porovnáním nových nebo změněných hesel se seznamem 10 000 nejhorších hesel.

* Při vytváření nových účtů a změnách hesel ověřujte vůči seznamům přihlašovacích údajů známých z úniků (např. pomocí [haveibeenpwned.com](https://haveibeenpwned.com)).

* Slaďte délku hesla, složitost a zásady rotace hesel s doporučeními  [National Institute of Standards and Technology (NIST) 800-63b's guidelines in section 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets), nebo s jinými moderními, na důkazech založenými zásadami pro hesla.

* Nenuťte uživatele rotovat (měnit) hesla, pokud nemáte podezření na únik/kompromitaci. Pokud máte podezření na kompromitaci, okamžitě vynuťte reset hesel.

* Zajistěte, aby registrace, obnova přihlašovacích údajů a API cesty byly zajištěny proti útokům typu enumerace účtů tím, že pro všechny výsledky použijete stejné zprávy („Neplatné uživatelské jméno nebo heslo.“).

* Omezte nebo postupně prodlužujte zpoždění při neúspěšných pokusech o přihlášení, ale dávejte pozor, abyste nevytvořili scénář denial of service. Zaznamenávejte všechna selhání a upozorněte správce, pokud jsou útoky typu credential stuffing, brute force nebo jiné útoky detekovány nebo je na ně podezření.

* Používejte vestavěný serverový správce relací, který je bezpečný a po přihlášení generuje nové náhodné ID relace s vysokou entropií. Identifikátory relací by neměly být v URL, měly by být bezpečně uloženy v zabezpečené cookie a zneplatněny po odhlášení, po vypršení nečinnosti (idle timeout) a po vypršení absolutního časového limitu (absolute timeout).

* V ideálním případě používejte předem připravený, široce důvěryhodný systém pro zpracování autentizace, identity a správy relací (session management). Toto riziko přeneste, kdykoli je to možné, nákupem a využíváním hardenovaného (zpevněného/zabezpečeného) a dobře otestovaného systému.

* Ověřte zamýšlené použití poskytnutých pověření, např. u JWT ověřte hodnoty aud, iss, a scopes.


## Příklady scénářů útoků 

**Scénář #1:** Credential stuffing, tedy použití seznamů známých kombinací uživatelských jmen a hesel, je dnes velmi běžný útok. V poslední době bylo zjištěno, že útočníci hesla „inkrementují“ nebo je jinak upravují na základě běžného lidského chování. Například změní „Winter2025“ na „Winter2026“ nebo „ILoveMyDog6“ na „ILoveMyDog7“ či „ILoveMyDog5“. Toto upravování pokusů o zadání hesla se nazývá hybridní útok credential stuffing nebo útok typu password spray a může být ještě účinnější než tradiční verze. Pokud aplikace neimplementuje obranu proti automatizovaným hrozbám (brute force, skripty nebo boty) ani proti credential stuffingu, může být použita jako password oracle k určení, zda jsou přihlašovací údaje platné, a k získání neoprávněného přístupu.

**Scénář #2:** Většina úspěšných útoků na autentizaci nastává v důsledku pokračujícího používání hesel jako jediného autentizačního faktoru. Požadavky na rotaci hesel a na jejich složitost, které byly kdysi považovány za osvědčené postupy, vedou uživatele jak k opětovnému používání hesel, tak k používání slabých hesel. Organizacím se doporučuje tyto postupy podle NIST 800-63 ukončit a vynucovat používání vícefaktorového ověřování na všech důležitých systémech.

**Scénář #3:** Časové limity relací aplikace nejsou správně implementovány. Uživatel používá veřejný počítač k přístupu k aplikaci a místo toho, aby vybral možnost „odhlásit se“, jednoduše zavře kartu prohlížeče a odejde. Dalším příkladem je situace, kdy SSO relaci (Single Sign-On) nelze ukončit pomocí SLO (Single Logout). To znamená, že jedno přihlášení vás přihlásí například do poštovního klienta, systému dokumentů a chatovacího systému, ale odhlášení se týká pouze aktuálního systému. Pokud útočník použije stejný prohlížeč poté, co se oběť domnívá, že se úspěšně odhlásila, ale v některých aplikacích je stále autentizována, může získat přístup k účtu oběti. Stejný problém může nastat v kancelářích a podnicích, když citlivá aplikace nebyla správně ukončena a kolega má (dočasný) přístup k odemčenému počítači.

## Reference

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## Seznam mapovaných CWE

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)
