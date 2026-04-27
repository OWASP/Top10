# A06:2025 Nezabezpečený návrh (Insecure Design) ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Kategorie Nezabezpečený návrh klesla v žebříčku o dvě příčky, ze 4. na 6. místo, protože ji předstihly kategorie **[A02:2025 Chybná bezpečnostní konfigurace (Security Misconfiguration)](A02_2025-Security_Misconfiguration.md)** a **[A03:2025 Selhání dodavatelského řetězce softwaru (Software Supply Chain Failures)](A03_2025-Software_Supply_Chain_Failures.md)**. Tato kategorie byla zavedena v roce 2021 a od té doby lze v oboru pozorovat znatelné zlepšení v oblasti modelování hrozeb i větší důraz na bezpečný návrh. Kategorie se zaměřuje na rizika související s nedostatky v návrhu a architektuře aplikací a zdůrazňuje potřebu širšího využívání modelování hrozeb, bezpečných návrhových vzorů a referenčních architektur. Patří sem také nedostatky v byznysové logice aplikace, například chybějící vymezení nežádoucích nebo neočekávaných změn stavu aplikace. Jako komunita se musíme posunout za hranice pojetí „shift-left“ omezeného na oblast kódování a zaměřit se také na činnosti předcházející samotnému psaní kódu, jako je formulace požadavků a návrh aplikace. Tyto činnosti jsou zásadní pro uplatňování principů Secure by Design (viz například **[Establish a Modern AppSec Program: Planning and Design Phase](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**). Mezi významné položky Common Weakness Enumeration (CWE) patří *CWE-256: Unprotected Storage of Credentials, CWE-269: Improper Privilege Management, CWE-434: Unrestricted Upload of File with Dangerous Type, CWE-501: Trust Boundary Violation a CWE-522: Insufficiently Protected Credentials*.

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
   <td>39
   </td>
   <td>22,18 %
   </td>
   <td>1,86 %
   </td>
   <td>88,76 %
   </td>
   <td>35,18 %
   </td>
   <td>6,96
   </td>
   <td>4,05
   </td>
   <td>729 882
   </td>
   <td>7 647
   </td>
  </tr>
</table>



## Popis 

Nezabezpečený návrh je široká kategorie zahrnující různé slabiny, vyjádřené jako „chybějící nebo neúčinný návrh bezpečnostních kontrol“. Nezabezpečený návrh není zdrojem všech ostatních kategorií rizik Top 10. Je třeba poznamenat, že existuje rozdíl mezi nezabezpečeným návrhem a nezabezpečenou implementací. Vady návrhu a defekty implementace rozlišujeme z určitého důvodu: mají různé kořenové příčiny, objevují se v různých fázích vývojového procesu a vyžadují odlišné způsoby nápravy.

I bezpečný návrh může obsahovat defekty implementace vedoucí ke zranitelnostem, které mohou být zneužity. Nezabezpečený návrh nelze napravit dokonalou implementací, protože potřebné bezpečnostní kontroly pro obranu proti konkrétním útokům nebyly nikdy vytvořeny. Jedním z faktorů přispívajících k nezabezpečenému návrhu je nedostatečné profilování byznysových rizik, která jsou vlastní vyvíjenému softwaru nebo systému, a tedy selhání při určení toho, jaká úroveň bezpečnostního návrhu je požadována.

Tři klíčové součásti bezpečného návrhu jsou:

* shromažďování požadavků a správa zdrojů,
* vytvoření bezpečného návrhu,
* existence bezpečného vývojového životního cyklu (Secure Development Lifecycle, SDLC).

### Požadavky a správa zdrojů

Shromážděte a vyjednejte se zástupci byznysu požadavky na aplikaci, včetně požadavků na ochranu týkajících se důvěrnosti, integrity, dostupnosti a autenticity všech datových aktiv a očekávané byznysové logiky. Vezměte v úvahu, jak moc bude vaše aplikace vystavena, a zda potřebujete oddělení tenantů (nad rámec toho, co je nutné pro řízení přístupu). Sestavte technické požadavky, včetně funkčních a nefunkčních bezpečnostních požadavků. Naplánujte a vyjednejte rozpočet pokrývající všechny činnosti návrhu, vývoje, testování a provozu, včetně bezpečnostních aktivit.

### Zabezpečený návrh

Zabezpečený návrh je kultura a metodika, která průběžně vyhodnocuje hrozby a zajišťuje, aby byl kód robustně navržen a testován tak, aby bránil známým metodám útoku. Modelování hrozeb by mělo být integrováno do refinement schůzek (nebo obdobných aktivit); hledejte změny v datových tocích, řízení přístupu nebo jiných bezpečnostních kontrolách. Při tvorbě user story určete správný tok a chybové stavy a zajistěte, aby jim odpovědné i dotčené strany dobře rozuměly a souhlasily s nimi. Analyzujte předpoklady a podmínky očekávaných i chybových toků, abyste zajistili, že zůstávají přesné a žádoucí. Určete, jak ověřovat předpoklady a vynucovat podmínky potřebné pro správné chování. Zajistěte, aby byly výsledky zdokumentovány v user story. Učte se z chyb a nabízejte pozitivní pobídky na podporu zlepšování. Zabezpečený návrh není ani doplněk, ani nástroj, který lze do softwaru přidat.


### Bezpečný vývojový cyklus (Secure Development Lifecycle, SDLC)

Bezpečný software vyžaduje bezpečný vývojový cyklus, bezpečný návrhový vzor, metodiku „paved road“, bezpečnou knihovnu komponent, vhodné nástroje, modelování hrozeb a post-incidentní analýzy, které se využívají ke zlepšování procesu. Obraťte se na své bezpečnostní specialisty na začátku softwarového projektu, v jeho průběhu i při průběžné údržbě softwaru. Zvažte využití modelu [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/), který vám pomůže strukturovat úsilí v oblasti bezpečného vývoje softwaru.

Vlastní odpovědnost vývojářů bývá často podceňována. Podporujte kulturu uvědomění, odpovědnosti a proaktivního snižování rizik. Pravidelné výměny poznatků o bezpečnosti (např. během modelování hrozeb) mohou pomáhat vytvářet způsob uvažování, který zahrnuje bezpečnost do všech důležitých návrhových rozhodnutí.


## Jak tomu zabránit

* Zaveďte a používejte bezpečný vývojový cyklus ve spolupráci s odborníky na AppSec, kteří pomohou vyhodnocovat a navrhovat bezpečnostní kontroly a kontroly související s ochranou soukromí.
* Zaveďte a používejte knihovnu bezpečných návrhových vzorů nebo komponent typu „paved road“.
* Používejte modelování hrozeb pro kritické části aplikace, jako je autentizace, řízení přístupu, byznysová logika a klíčové toky.
* Používejte modelování hrozeb jako vzdělávací nástroj pro rozvoj bezpečnostního způsobu uvažování.
* Začleňujte bezpečnostní jazyk a bezpečnostní kontroly do user stories.
* Začleňujte kontroly plausibility na každé vrstvě aplikace (od frontendu po backend).
* Pište jednotkové a integrační testy, abyste ověřili, že všechny kritické toky jsou odolné vůči hrozbám podle modelu hrozeb. Sestavte use cases (případy použití) a misuse cases (případy zneužití) pro každou vrstvu aplikace.
* Oddělte jednotlivé vrstvy aplikace na úrovni systému i sítě podle míry expozice a požadavků na ochranu.
* Zajistěte robustní oddělení tenantů již v návrhu, a to napříč všemi vrstvami.


## Příklady scénářů útoků

**Scénář #1:** Proces obnovy přihlašovacích údajů může obsahovat „otázky a odpovědi“, což zakazují NIST 800-63B, OWASP ASVS a OWASP Top 10. Otázky a odpovědi nelze považovat za důvěryhodný důkaz identity, protože odpovědi může znát více než jedna osoba. Taková funkcionalita by měla být odstraněna a nahrazena bezpečnějším návrhem.

**Scénář #2:** Řetězec kin umožňuje skupinové slevy při rezervaci a zálohu vyžaduje až při více než patnácti účastnících. Útočníci mohou pro tento tok provést modelování hrozeb a otestovat, zda v byznysové logice aplikace najdou vektor útoku, například rezervaci šesti set míst ve všech kinech najednou v několika málo požadavcích, což způsobí masivní ztrátu příjmů.

**Scénář #3:** E-shop maloobchodního řetězce nemá ochranu proti botům provozovaným překupníky, kteří nakupují špičkové grafické karty za účelem dalšího prodeje na aukčních webech. To vede k velmi špatné publicitě pro výrobce grafických karet i vlastníky maloobchodního řetězce a k přetrvávající nevraživosti u nadšenců, kteří tyto karty nemohou získat za žádnou cenu. Pečlivý návrh ochrany proti botům a pravidla doménové logiky, například nákupy provedené během několika sekund od zahájení dostupnosti, mohou identifikovat neautentické nákupy a takové transakce odmítnout.


## Reference

* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## Seznam mapovaných CWE

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

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

* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

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

* [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

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
