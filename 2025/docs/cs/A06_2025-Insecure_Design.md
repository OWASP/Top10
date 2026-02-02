# A06:2025 Nezabezpečený návrh ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Nezabezpečený návrh je v žebříčku o dvě příčky níže, ze 4. na 6. místo, protože jej předstihly **[A02:2025 Chybná bezpečnostní konfigurace (Security Misconfiguration)](A02_2025-Security_Misconfiguration.md)** a **[A03:2025 Selhání dodavatelského řetězce softwaru (Software Supply Chain Failures)](A03_2025-Software_Supply_Chain_Failures.md)**. Tato kategorie byla zavedena v roce 2021 a v oboru jsme zaznamenali znatelné zlepšení v oblasti modelování hrozeb a větší důraz na bezpečný návrh. Tato kategorie se zaměřuje na rizika související s nedostatky v návrhu a architektuře a vyzývá k většímu využívání modelování hrozeb, bezpečných návrhových vzorů a referenčních architektur. Patří sem nedostatky v byznysové logice aplikace, např. chybějící vymezení nežádoucích nebo neočekávaných změn stavu uvnitř aplikace. Jako komunita musíme jít nad rámec „shift-left“ v oblasti psaní kódu a zaměřit se na činnosti před psaním kódu, jako je psaní požadavků a návrh aplikací, které jsou zásadní pro principy Secure by Design (viz například **[Establish a Modern AppSec Program: Planning and Design Phase](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**). Mezi významné položky Common Weakness Enumeration (CWE) patří *CWE-256: Unprotected Storage of Credentials, CWE-269 Improper Privilege Management, CWE-434 Unrestricted Upload of File with Dangerous Type, CWE-501: Trust Boundary Violation, and CWE-522: Insufficiently Protected Credentials.*


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

Nezabezpečený návrh je široká kategorie představující různé slabiny, charakterizovaná jako „chybějící nebo neúčinný návrh bezpečnostních kontrol“. Nezabezpečený návrh není zdrojem všech ostatních kategorií rizik v žebříčku Top Ten. Upozorňujeme, že existuje rozdíl mezi nezabezpečeným návrhem a nezabezpečenou implementací. Rozlišujeme mezi vadami návrhu a defekty implementace z toho důvodu, že mají různé příčiny, vyskytují se v různých fázích vývojového procesu a mají odlišná nápravná opatření (remediace). Bezpečný návrh může stále obsahovat defekty implementace, které vedou ke zranitelnostem, jež mohou být zneužity. Nezabezpečený návrh nelze opravit dokonalou implementací, protože potřebné bezpečnostní kontroly nebyly vytvořeny, aby chránily před konkrétními útoky. Jedním z faktorů, který přispívá k nezabezpečenému návrhu, je nedostatek profilování byznysových rizik vlastních vyvíjenému softwaru nebo systému, a tedy selhání určit, jaká úroveň bezpečnostního návrhu je požadována.

Tři klíčové prvky bezpečného designu jsou:

* Shromažďování požadavků a správa zdrojů
* Tvorba zabezpečného návrhu
* Zavedení bezpečného vývojového cyklu (Secure Development Lifecycle, SDLC)

### Požadavky a správa zdrojů

Shromážděte a vyjednejte s byznysovou stranou požadavky na aplikaci, včetně požadavků na ochranu týkajících se důvěrnosti, integrity, dostupnosti a autenticity všech datových aktiv a očekávané byznysové logiky. Vezměte v úvahu, jak exponovaná bude vaše aplikace, a zda potřebujete oddělení tenantů (nad rámec toho, co je nutné pro řízení přístupu). Sestavte technické požadavky, včetně funkčních a nefunkčních bezpečnostních požadavků. Naplánujte a vyjednejte rozpočet pokrývající veškerý návrh, vývoj, testování a provoz, včetně bezpečnostních aktivit.

### Zabezpečený návrh

Zabezpečený návrh je kultura a metodika, která neustále vyhodnocuje hrozby a zajišťuje, že kód je robustně navržen a testován tak, aby odolal známým metodám útoku. Modelování hrozeb by mělo být integrováno do refinement schůzek (nebo obdobných aktivit); hledejte změny v datových tocích, řízení přístupu a dalších bezpečnostních kontrolách. Při tvorbě user story určete správné toky a chybové stavy a zajistěte, aby byly dobře pochopeny a odsouhlaseny odpovědnými i dotčenými stranami. Analyzujte předpoklady a podmínky pro očekávané i chybové toky, abyste zajistili, že zůstávají přesné a žádoucí. Určete, jak ověřit předpoklady a vynucovat podmínky potřebné pro správné chování. Zajistěte, aby byly výsledky zdokumentovány v user story. Poučte se z chyb a poskytujte pozitivní pobídky na podporu zlepšování. Zabezpečený návrh není ani doplněk, ani nástroj, který lze do softwaru přidat.


### Bezpečný vývojový cyklus (Secure Development Lifecycle, SDLC)

Bezpečný software vyžaduje bezpečný vývojový cyklus, bezpečné návrhové vzory, metodiku „paved road“, bezpečnou knihovnu komponent, vhodné nástroje, modelování hrozeb a post-incidentní analýzy, které slouží ke zlepšování procesu.  Obraťte se na své bezpečnostní specialisty na začátku softwarového projektu, v jeho průběhu i při průběžné údržbě softwaru. Zvažte využití modelu [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/), který vám pomůže strukturovat vaše úsilí v oblasti bezpečného vývoje softwaru.

Často je podceňována vlastní odpovědnost vývojářů. Podporujte kulturu bezpečnostního uvědomění, odpovědnosti a proaktivního snižování rizik. Pravidelné diskuse o bezpečnosti (např. během modelování hrozeb) mohou vytvořit způsob uvažování, který zahrnuje bezpečnost do všech důležitých návrhových rozhodnutí. 


## Jak tomu zabránit


* Zaveďte a používejte bezpečný vývojový cyklus ve spolupráci s AppSec odborníky, kteří pomohou vyhodnotit a navrhnout bezpečnostní a soukromí-týkající se kontroly.
* Zaveďte a používejte knihovnu bezpečných návrhových vzorů nebo komponent typu „paved-road“.
* Používejte modelování hrozeb pro kritické části aplikace, jako je autentizace, řízení přístupu, byznysová logika a klíčové toky.
* Používejte modelování hrozeb jako vzdělávací nástroj pro rozvoj bezpečnostního uvažování.
* Začleňujte bezpečnostní terminologii a bezpečnostní kontroly do user stories.
* Začleňujte kontroly plauzibility na každé vrstvě aplikace (od frontendu po backend).
* Napište jednotkové a integrační testy, abyste ověřili, že všechny kritické toky jsou odolné vůči modelu hrozeb. Sestavte use cases (případy použití) a misuse cases (případy zneužití) pro každou vrstvu aplikace.
* Oddělte vrstvy (tiers) na úrovni systému i sítě podle míry expozice a požadavků na ochranu.
* Oddělte tenanty robustně už návrhem napříč všemi vrstvami.


## Příklady scénářů útoků

**Scénář #1:** Proces obnovy přihlašovacích údajů může využívat „otázky a odpovědi“, což je přístup zakázaný dokumentem NIST 800-63B, standardem OWASP ASVS a OWASP Top 10. Otázky a odpovědi nelze považovat za spolehlivý důkaz identity, protože správné odpovědi může znát více osob. Taková funkcionalita by měla být odstraněna a nahrazena bezpečnějším návrhem.

**Scénář #2:** Řetězec kin umožňuje skupinové slevy při rezervaci a do patnácti účastníků nevyžaduje zálohu. Útočníci mohou provést modelování hrozeb tohoto toku a otestovat, zda lze nalézt vektor útoku v byznysové logice aplikace, například rezervací šest set míst napříč všemi kiny současně v několika málo požadavcích, což může vést k masivní ztrátě příjmů.

**Scénář #3:** E-shop maloobchodního řetězce nemá ochranu proti botům provozovaným překupníky, kteří nakupují špičkové grafické karty za účelem jejich dalšího prodeje na aukčních webech. To má za následek špatnou publicitu pro výrobce grafických karet i majitele maloobchodních řetězců a přetrvávající nepřátelství ze strany nadšenců, kteří tyto karty nemohou získat za žádnou cenu. Pečlivý návrh ochrany proti botům a pravidla doménové logiky, jako jsou nákupy provedené během několika sekund od dostupnosti, mohou identifikovat neautentické nákupy a takové transakce odmítnout.


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
