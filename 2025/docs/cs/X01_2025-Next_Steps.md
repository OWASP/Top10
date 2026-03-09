# Další kroky

OWASP Top 10 je ze své podstaty omezen na deset nejvýznamnějších rizik. V každém OWASP Top 10 jsou podrobně zvažována i rizika, která byla „na hraně“ zařazení, ale nakonec se do seznamu nedostala. Ostatní rizika byla rozšířenější a měla větší dopad.

Následující dva problémy rozhodně stojí za pozornost a nápravu, zejména pro organizace, které směřují k vyspělému programu zabezpečení aplikací, bezpečnostní konzultanty a dodavatele nástrojů, kteří chtějí rozšířit nabídku o další oblasti.


## X01:2025 Nedostatečná odolnost aplikací (Lack of Application Resilience)

### Pozadí

Jedná se o přejmenování kategorie „Odmítnutí služby (Denial of Service)“ z roku 2021. Byla přejmenována, protože popisovala spíše symptom než kořenovou příčinu. Tato kategorie se zaměřuje na CWE, které popisují slabiny související s problémy odolnosti. Skóre této kategorie bylo velmi blízké skóre kategorie A10:2025 Nesprávné zpracování výjimečných stavů (Mishandling of Exceptional Conditions). Mezi relevantní CWE patří: *CWE-400 Uncontrolled Resource Consumption, CWE-409 Improper Handling of Highly Compressed Data (Data Amplification), CWE-674 Uncontrolled Recursion*, a *CWE-835 Loop with Unreachable Exit Condition ('Infinite Loop').*


### Tabulka skóre


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
   <td>16
   </td>
   <td>20,05 %
   </td>
   <td>4,55 %
   </td>
   <td>86,01 %
   </td>
   <td>41,47 %
   </td>
   <td>7,92
   </td>
   <td>3,49
   </td>
   <td>865 066
   </td>
   <td>4 423
   </td>
  </tr>
</table>



### Popis 

Tato kategorie představuje systémovou slabinu v tom, jak aplikace reagují na zátěž, selhání a hraniční případy, ze kterých se nedokážou zotavit. Pokud aplikace nedokáže elegantně zvládnout, ustát nebo se zotavit z neočekávaných stavů, omezení zdrojů a dalších nepříznivých událostí, může to snadno vést k problémům s dostupností (nejčastěji), ale také k poškození dat, úniku citlivých dat, kaskádovým selháním a/nebo obejití bezpečnostních kontrol.

Kromě toho mohou [X02:2025 Selhání správy paměti (Memory Management Failures)](#x022025-memory-management-failures) vést k selhání aplikace nebo dokonce celého systému.

### Jak tomu zabránit 

Aby bylo možné tomuto typu zranitelnosti předejít, musíte své systémy navrhovat s ohledem na selhání a obnovu.

* Přidejte limity, kvóty a funkce pro převzetí služeb při selhání (failover) a věnujte zvláštní pozornost operacím, které spotřebovávají nejvíce zdrojů
* Identifikujte stránky náročné na zdroje a plánujte dopředu: snižte plochu útoku, zejména nezpřístupňujte neznámým nebo nedůvěryhodným uživatelům nepotřebné „gadgety“ a funkce, které vyžadují mnoho zdrojů (např. CPU, paměť)
* Provádějte přísnou validaci vstupů pomocí seznamů povolených hodnot (allow-listů) a omezení velikosti a poté důkladně testujte
* Omezte velikost odpovědí a nikdy neposílejte klientovi nezpracované odpovědi (zpracovávejte je na straně serveru)
* Ve výchozím stavu bezpečně/uzavřeně (fail closed, nikdy „open“), deny by default (implicitně zamítnout) a při chybě rollbackovat
* Vyhněte se blokujícím synchronním voláním ve vláknech obsluhy požadavků (používejte asynchronní/neblokující přístup, nastavte time-outy, limity souběžnosti apod.)
* Pečlivě otestujte funkcionalitu zpracování chyb
* Implementujte resilience patterns (vzorce odolnosti), jako jsou circuit breakers (pojistky), bulkheads (oddělení/kompartmenty; izolace částí systému), retry logika (logika opakování / opakované pokusy) a graceful degradation (řízený přechod do omezeného režimu)
* Provádějte performance a load testing; pokud to odpovídá vašemu risk apetitu, přidejte chaos engineering (testování odolnosti řízeným vyvoláváním poruch)
* Implementujte a navrhujte architekturu pro redundanci tam, kde je to rozumné a cenově dostupné
* Implementujte monitoring, observability a alerting
* Filtrujte neplatné zdrojové adresy (source addresses) v souladu s RFC 2267
* Blokujte známé botnety podle fingerprintů, IP adres nebo dynamicky podle chování
* Proof-of-Work: iniciujte na straně útočníka operace náročné na zdroje, které nemají velký dopad na běžné uživatele, ale dopadají na boty snažící se odesílat obrovské množství požadavků. Proof-of-Work ztěžujte, pokud roste celkové zatížení systému, zejména u systémů, které jsou méně důvěryhodné nebo se jeví jako boti
* Omezte dobu trvání relace na straně serveru na základě nečinnosti a konečného časového limitu
* Omezte ukládání informací vázaných na relaci


### Příklady scénářů útoků 

**Scénář #1:** Útočníci záměrně spotřebovávají zdroje aplikace, aby vyvolali selhání v systému, což vede k odmítnutí služby. Může jít o vyčerpání paměti, zaplnění diskového prostoru, saturaci CPU nebo navazování nekonečného množství připojení.

**Scénář #2:** Fuzzing vstupů, který vede k zkonstruovaným odpovědím narušujícím obchodní logiku aplikace.

**Scénář #3:** Útočníci se zaměřují na závislosti aplikace, vyřadí z provozu API nebo jiné externí služby a aplikace není schopna pokračovat.


### Reference.

* [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### Seznam mapovaných CWE
* [CWE-73  External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)
* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)
* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)
* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)
* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)
* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)
* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)
* [CWE-653 Improper Isolation or Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)
* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)
* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)


## X02:2025 Selhání správy paměti (Memory Management Failures)

### Pozadí 

Jazyky jako Java, C#, JavaScript/TypeScript (node.js), Go a „bezpečný“ Rust jsou paměťově bezpečné. Problémy se správou paměti se obvykle vyskytují v jazycích, které nejsou paměťově bezpečné, jako jsou C a C++. Tato kategorie získala v komunitním průzkumu nejnižší hodnocení a v datech také nízké, přestože má třetí nejvyšší počet souvisejících CVE. Domníváme se, že je to způsobeno převahou webových aplikací nad tradičnějšími desktopovými aplikacemi. Zranitelnosti správy paměti mají často nejvyšší skóre CVSS. 


### Tabulka skóre


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
   <td>2,96 %
   </td>
   <td>1,13 %
   </td>
   <td>55,62 %
   </td>
   <td>28,45 %
   </td>
   <td>6,75
   </td>
   <td>4,82
   </td>
   <td>220 414
   </td>
   <td>30 978
   </td>
  </tr>
</table>



### Popis 

Když je aplikace nucena spravovat paměť sama, je velmi snadné dělat chyby. Paměťově bezpečné jazyky se používají stále častěji, ale po celém světě je stále mnoho legacy systémů v produkci, nové nízkoúrovňové systémy, které vyžadují použití jazyků bez paměťové bezpečnosti, a webové aplikace, které komunikují s mainframe systémy, zařízeními IoT, firmwarem a dalšími systémy, které mohou být nuceny spravovat vlastní paměť. Mezi reprezentativní CWE patří *CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')* a *CWE-121 Stack-based Buffer Overflow*.

K selhání správy paměti může dojít, když:

* Nepřidělíte proměnné dostatek paměti.
* Nevalidujete vstup, což způsobí přetečení haldy, zásobníku nebo bufferu.
* Uložíte datovou hodnotu, která je větší, než dokáže pojmout datový typ proměnné.
* Pokusíte se použít nepřidělenou paměť nebo adresní prostor.
* Vytvoříte chyby typu off-by-one (počítání od 1 místo od nuly).
* Pokusíte se přistoupit k objektu poté, co byl uvolněn.
* Použijete neinicializované proměnné.
* Způsobíte únik paměti nebo jinak chybně vyčerpáte veškerou dostupnou paměť, dokud aplikace neselže.

Selhání správy paměti může vést k selhání aplikace nebo dokonce celého systému, viz také [X01:2025 – Nedostatečná odolnost aplikací (Lack of Application Resilience)](#x012025-lack-of-application-resilience)


### Jak tomu zabránit 

Nejlepší způsob, jak zabránit selháním správy paměti, je používat paměťově bezpečný jazyk. Mezi příklady patří Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript atd. Při vytváření nových aplikací se snažte svou organizaci přesvědčit, že vyplatí se překonat křivku učení a přejít na paměťově bezpečný jazyk. Pokud provádíte kompletní refaktoring, prosazujte přepsání (rewrite) do paměťově bezpečného jazyka, pokud je to možné a proveditelné.

Pokud nemůžete použít paměťově bezpečný jazyk, proveďte následující kroky:

* Zapněte následující funkce systému/serveru, které ztěžují zneužití chyb správy paměti: náhodné rozložení adresového prostoru (ASLR), Ochrana před spuštěním dat (DEP) a ochrana před přepsáním strukturovaných výjimek (SEHOP).
* Monitorujte aplikaci z hlediska úniků paměti.
* Velmi pečlivě validujte všechny vstupy do systému a odmítněte všechny vstupy, které neodpovídají očekávání.
* Prostudujte jazyk, který používáte, a vytvořte seznam nebezpečných a bezpečnějších funkcí; poté jej sdílejte s celým týmem. Pokud je to možné, přidejte jej do vašich pokynů nebo standardu pro bezpečné kódování. Například v jazyce C upřednostňujte strncpy() před strcpy() a strncat() před strcat().
* Pokud váš jazyk nebo framework nabízí knihovny pro paměťovou bezpečnost, používejte je. Například safestringlib nebo SafeStr.
* Kdykoli je to možné, používejte spravované buffery a řetězce namísto „holých“ polí a ukazatelů.
* Absolvujte školení bezpečného kódování zaměřené na problémy paměti a/nebo na vámi používaný jazyk. Informujte školitele, že řešíte selhání správy paměti.
* Provádějte revize kódu a/nebo statickou analýzu.
* Používejte nástroje a ochrany na úrovni kompilace/runtime, které ztěžují zneužití chyb správy paměti, např. StackShield, StackGuard a Libsafe.
* Provádějte fuzzing na každém vstupu do vašeho systému.
* Pokud provádíte penetrační test, informujte testera, že vás znepokojují selhání správy paměti a že chcete, aby jim při testování věnoval zvláštní pozornost.
* Opravte všechny chyby a varování kompilátoru. Neignorujte varování jen proto, že program projde kompilací. 
* Zajistěte, aby byla podkladová infrastruktura pravidelně záplatována, skenována a hardenována (zpevňována).
* Monitorujte podkladovou infrastrukturu zejména z hlediska potenciálních paměťových zranitelností a dalších selhání.
* Zvažte použití [kanárků (canaries)](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) k ochraně zásobníku před útoky přetečením.


### Příklady scénářů útoků 

**Scénář #1:** Přetečení vyrovnávací paměti (buffer overflow) je nejznámější paměťová zranitelnost – situace, kdy útočník odešle do pole více informací, než kolik může přijmout, takže dojde k přetečení bufferu vytvořeného pro příslušnou proměnnou. Při úspěšném útoku znaky přetečení přepíší hodnoty na zásobníku (např. ukazatel zásobníku / návratovou adresu), což útočníkovi umožní vložit do programu škodlivé instrukce.

**Scénář #2:** Use-After-Free (UAF) se vyskytuje natolik často, že jde o polo-běžný typ hlášení v bug bounty programech pro webové prohlížeče. Představte si webový prohlížeč zpracovávající JavaScript, který manipuluje s prvky DOM. Útočník zkonstruuje JavaScriptový payload, který vytvoří objekt (například prvek DOM) a získá na něj reference. Pečlivou manipulací vyvolá stav, kdy prohlížeč uvolní paměť objektu, ale zároveň zůstane dangling pointer (visící ukazatel) na tuto paměť. Než si prohlížeč „uvědomí“ (tj. než správně ošetří), že paměť už byla uvolněna, útočník alokuje nový objekt, který obsadí tentýž paměťový prostor. Když se pak prohlížeč pokusí použít původní ukazatel, ukazuje už na data ovládaná útočníkem. Pokud šlo o ukazatel na virtuální tabulku funkcí (vtable), může útočník přesměrovat provádění kódu na svůj payload. 

**Scénář #3:** Síťová služba přijímá vstup od uživatele, neprovádí jeho řádnou validaci ani sanitizaci a poté jej předá přímo logovací funkci. Uživatelský vstup je předán logovací funkci jako syslog(user_input) namísto syslog("%s", user_input), tedy bez explicitně zadaného formátu. Útočník odešle škodlivé payloady obsahující specifikátory formátu, například %x pro čtení paměti zásobníku (únik citlivých dat) nebo %n pro zápis do paměťových adres. Řetězením více formátovacích specifikátorů může zmapovat zásobník, najít důležité adresy a následně je přepsat. Jedná se o zranitelnost formátovacího řetězce (format string vulnerability; externě řízený/nekontrolovaný formátovací řetězec). 

Poznámka: moderní prohlížeče používají k obraně proti takovým útokům více vrstev ochrany, včetně [sandboxingu prohlížeče](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing) ASLR, DEP/NX, RELRO a PIE. Útok na prohlížeč založený na selhání správy paměti není jednoduché provést.

### Reference

* [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### Seznam mapovaných CWE
* [CWE-14 Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
* [CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-124 Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html)
* [CWE-125 Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-126 Buffer Over-read](https://cwe.mitre.org/data/definitions/126.html)
* [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-191 Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
* [CWE-196 Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html)
* [CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
* [CWE-415 Double Free](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-457 Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
* [CWE-459 Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
* [CWE-467 Use of sizeof() on a Pointer Type](https://cwe.mitre.org/data/definitions/467.html)
* [CWE-787 Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
* [CWE-788 Access of Memory Location After End of Buffer](https://cwe.mitre.org/data/definitions/788.html)
* [CWE-824 Access of Uninitialized Pointer](https://cwe.mitre.org/data/definitions/824.html)



## X03:2025 Nevhodná důvěra v kód generovaný AI (Inappropriate Trust in AI Generated Code („Vibe Coding“))

### Pozadí

V současnosti celý svět mluví o umělé inteligenci a používá ji – a to platí i pro vývojáře softwaru. Přestože v tuto chvíli neexistují žádné CVE ani CWE přímo vztahující se ke kódu generovanému umělou inteligencí, je dobře známo a zdokumentováno, že takový kód často obsahuje více zranitelností než kód napsaný člověkem.


### Popis

Pozorujeme, jak se postupy vývoje softwaru mění: už nejde jen o kód psaný s asistencí umělé inteligence, ale i o kód, který je napsán a commitnutý do repozitáře téměř úplně bez lidského dohledu (často se pro to používá označení ‚vibe coding‘). Stejně jako nikdy nebylo dobré bez rozmyslu kopírovat úryvky kódu z blogů nebo webů, tady je ten problém ještě výraznější. Kvalitní a bezpečné ukázky kódu byly a jsou vzácné a kvůli systémovým omezením mohou být při generování AI statisticky podreprezentované.


### Jak tomu zabránit
Všem, kdo píší kód, důrazně doporučujeme při používání AI zvážit následující:

* Měli byste být schopni přečíst a plně porozumět veškerému kódu, který odevzdáváte, i když jej napsala AI nebo byl zkopírován z online fóra. Nesete odpovědnost za veškerý kód, který commitnete do repozitáře.
* Veškerý kód vzniklý s pomocí AI byste měli důkladně prověřit na zranitelnosti, ideálně vlastníma očima a zároveň i pomocí bezpečnostních nástrojů určených k tomuto účelu (např. statické analýzy). Zvažte použití klasických technik code review, jak jsou popsány v [OWASP Cheat Sheet Series: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
* Ideálně pište vlastní kód, nechte AI navrhnout vylepšení, zkontrolujte výstup AI a nechte AI provést opravy, dokud nebudete s výsledkem spokojeni.
* Zvažte použití serveru pro Retrieval-Augmented Generation (RAG) s vašimi vlastními shromážděnými a zrevidovanými vzorky bezpečného kódu a dokumentací (např. interními bezpečnostními doporučeními pro kódování, standardy nebo politikami vaší organizace) a nechte RAG server vynucovat příslušné politiky či standardy.
* Zvažte pořízení nástrojů, které pro práci s vámi zvolenými AI modely/nástroji zavádějí guardrails (ochranná opatření) pro soukromí a bezpečnost.
* Zvažte pořízení privátního AI řešení, ideálně se smluvním ujednáním (včetně dohody o ochraně soukromí / zpracování dat), že model nebude trénován na datech, dotazech, kódu ani jiných citlivých informacích vaší organizace.
* Zvažte nasazení serveru Model Context Protocol (MCP) mezi vaše IDE a AI a nastavte jej tak, aby vynucoval používání vámi zvolených bezpečnostních nástrojů.
* Zaveďte zásady a procesy jako součást SDLC, aby vývojáři (a všichni zaměstnanci) věděli, jak AI v rámci organizace používat a jak ji nepoužívat.
* Vytvořte seznam kvalitních a efektivních promptů, které zohledňují osvědčené postupy IT bezpečnosti; ideálně i vaše interní pravidla pro bezpečné kódování. Vývojáři je mohou použít jako výchozí bod pro svou práci.
* AI se pravděpodobně stane součástí každé fáze životního cyklu vývoje systému – jak z hlediska efektivního, tak bezpečného využití. Používejte ji uvážlivě.
* V praxi se **<u>ne</u>**doporučuje používat „vibe coding“ pro složité funkce, business-kritické aplikace nebo software, který má být dlouhodobě udržovaný.
* Zaveďte technické kontroly a pojistky proti používání Shadow AI (neautorizovaných AI nástrojů).
* Proškolte vývojáře v interních zásadách, bezpečném používání AI a osvědčených postupech pro využití AI při vývoji softwaru.



### Reference

* [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


### Seznam mapovaných CWE
-žádný-
