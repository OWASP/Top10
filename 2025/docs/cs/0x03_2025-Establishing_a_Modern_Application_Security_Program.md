# Zavedení moderního programu bezpečnosti aplikací

Seznamy OWASP Top Ten jsou osvětové dokumenty, jejichž cílem je zvýšit povědomí o nejkritičtějších rizicích v oblasti, kterou pokrývají. Nejsou zamýšleny jako úplný výčet, ale pouze jako výchozí bod. V předchozích verzích tohoto seznamu jsme jako nejlepší způsob, jak se těmto rizikům a dalším vyhnout, doporučovali zahájit program bezpečnosti aplikací. V této části se zaměříme na to, jak moderní program bezpečnosti aplikací zahájit a dále rozvíjet.

 

Pokud již program bezpečnosti aplikací máte, zvažte provedení posouzení jeho vyspělosti pomocí [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) nebo DSOMM (DevSecOps Maturity Model). Tyto modely vyspělosti jsou komplexní a vyčerpávající a lze je použít k určení oblastí, na které byste se měli při rozšiřování a zvyšování vyspělosti programu nejvíce zaměřit. Upozornění: není nutné realizovat vše, co je v OWASP SAMM nebo DSOMM uvedeno, aby bylo možné říci, že svou práci děláte dobře. Tyto modely mají sloužit jako vodítko a nabídnout mnoho možností. Nejsou určeny k tomu, aby stanovovaly nedosažitelné standardy nebo popisovaly finančně neúnosné programy. Jsou rozsáhlé právě proto, aby poskytly co nejvíce nápadů a variant.

 

Pokud program budujete zcela od začátku, nebo pokud jsou pro váš tým OWASP SAMM či DSOMM v současnosti „příliš rozsáhlé“, projděte si prosím následující doporučení.


### 1. Zavedení portfoliového přístupu založeného na riziku:

* Identifikujte potřeby ochrany portfolia vašich aplikací z byznysového hlediska. Tyto potřeby by měly být částečně řízeny právními předpisy o ochraně soukromí a dalšími regulacemi relevantními pro chráněná datová aktiva.
* Zaveďte [společný model hodnocení rizik](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) s konzistentní sadou faktorů pravděpodobnosti a dopadu, které odrážejí toleranci vaší organizace k riziku.
* Na tomto základě měřte a prioritizujte všechny své aplikace a API. Výsledky zaznamenejte do své [databáze pro správu konfigurací (Configuration Management Database, CMDB)](https://de.wikipedia.org/wiki/Configuration_Management_Database).
* Zaveďte směrnice pro poskytování jistoty (zajištění důvěryhodnosti; assurance), které jednoznačně definují požadované pokrytí a úroveň důslednosti.


### 2. Vybudujte pevné základy:

* Zaveďte soubor cílených politik a standardů, které poskytují základní úroveň bezpečnosti aplikací, již musí dodržovat všechny vývojové týmy.
* Definujte společnou sadu opakovaně použitelných bezpečnostních kontrol, které tyto politiky a standardy doplňují a poskytují vodítka pro jejich použití při návrhu a vývoji.
* Zaveďte vzdělávací kurikulum v oblasti bezpečnosti aplikací, které je povinné a přizpůsobené různým vývojovým rolím a tematickým oblastem.


### 3. Integrujte bezpečnost do stávajících procesů:

* Definujte a integrujte činnosti bezpečné implementace a bezpečnostního ověřování do stávajících vývojových a provozních procesů.
* Tyto činnosti zahrnují modelování hrozeb, bezpečný návrh a revizi návrhu, bezpečné programování a revizi kódu, penetrační testování a nápravu zjištěných problémů.
* Zajistěte odborníky v dané oblasti a podpůrné služby, aby vývojové a projektové týmy mohly být úspěšné.
* Proveďte revizi současného životního cyklu vývoje systémů a všech aktivit v oblasti bezpečnosti softwaru, nástrojů, politik a procesů a tyto skutečnosti zdokumentujte.
* Pro nový software přidejte jednu nebo více bezpečnostních aktivit do každé fáze životního cyklu vývoje systému (SDLC). Níže uvádíme řadu návrhů, co lze v jednotlivých fázích dělat. Zajistěte, aby byly tyto nové aktivity prováděny u každého nového projektu nebo softwarové iniciativy. Tím zajistíte, že každý nový software bude dodán v bezpečnostním stavu přijatelném pro vaši organizaci.
* Vybírejte jednotlivé aktivity tak, aby výsledný produkt splňoval přijatelnou úroveň rizika pro vaši organizaci.
* Pro stávající software (někdy označovaný jako legacy) je vhodné mít plán údržby. Níže v části nazvané „Provoz a řízení změn (Operations and Change Management)“ uvádíme návrhy, jak bezpečné aplikace udržovat.


### 4. Vzdělávání v oblasti bezpečnosti aplikací:

* Zvažte zahájení programu Security Champion, případně obecného vzdělávacího programu v oblasti bezpečnosti pro vývojáře (někdy označovaného jako advocacy nebo security awareness program), jehož cílem je naučit je vše, co považujete za důležité, aby znali. Takový program pomáhá udržovat aktuální znalosti, podporuje bezpečný způsob práce a přispívá k pozitivnější bezpečnostní kultuře na pracovišti. Často také zlepšuje důvěru mezi týmy a vede k lepším pracovním vztahům. OWASP vás v tomto podporuje prostřednictvím [OWASP Security Champions Guide](https://securitychampions.owasp.org/), který je postupně rozšiřován.
* OWASP Education Project poskytuje školicí materiály pro vzdělávání vývojářů v oblasti bezpečnosti webových aplikací. Pro praktické seznámení se zranitelnostmi lze využít projekty [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/) nebo [OWASP WebGoat](https://owasp.org/www-project-webgoat/). Pro udržení aktuálních znalostí se doporučuje účast na [OWASP AppSec Conference](https://owasp.org/events/), [OWASP Conference Training](https://owasp.org/events/), nebo na setkáních místních [OWASP Chapter](https://owasp.org/chapters/).


### 5. Zajištění přehledu pro management:

* Řiďte bezpečnost na základě metrik. Podporujte zlepšování a rozhodování o financování na základě metrik a analyzovaných dat, která byla shromážděna. Metriky zahrnují například dodržování bezpečnostních postupů a aktivit, nově zavedené zranitelnosti, odstraněné zranitelnosti, pokrytí aplikací, hustotu chyb podle typu a počtu jejich výskytů apod.
* Analyzujte data z činností bezpečné implementace a ověřování s cílem identifikovat kořenové příčiny a vzorce zranitelností, které mohou vést ke strategickým a systémovým zlepšením napříč organizací. Poučte se z chyb a zavádějte pozitivní pobídky na podporu dalšího zlepšování.



## Zavedení a používání opakovatelných bezpečnostních procesů a standardních bezpečnostních kontrol

### Fáze řízení požadavků a zdrojů:

* Shromažďujte a projednávejte byznysové požadavky na aplikaci se zástupci byznysu, včetně požadavků na ochranu všech datových aktiv z hlediska důvěrnosti, autenticity, integrity a dostupnosti, a očekávané aplikační (byznys) logiky.
* Sestavte technické požadavky, včetně funkčních a nefunkčních bezpečnostních požadavků. OWASP doporučuje používat [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) jako referenční rámec pro stanovení bezpečnostních požadavků na vaše aplikace.
* Naplánujte a vyjednejte rozpočet, který pokrývá všechny aspekty návrhu, implementace, testování a provozu, včetně bezpečnostních aktivit.
* Zařaďte bezpečnostní aktivity do harmonogramu projektu.
* Na zahájení projektu (kick-off) se představte jako zástupce bezpečnosti, aby bylo jasné, na koho se obracet v otázkách bezpečnosti.


### Žádosti o nabídku (RFP) a uzavírání smluv:

*  Vyjednávejte požadavky s interními nebo externími vývojáři, včetně pokynů a bezpečnostních požadavků v návaznosti na váš bezpečnostní program, např. životní cyklus vývoje softwaru (SDLC) a osvědčené postupy (best practices).
*  Posuzujte míru splnění všech technických požadavků, včetně fáze plánování a návrhu.
*  Vyjednávejte všechny technické požadavky, včetně požadavků na návrh, bezpečnost a dohody o úrovni poskytovaných služeb (Service Level Agreement, SLA).
*  Používejte šablony a kontrolní seznamy, například [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex).<br>
**Poznámka:** Tento annex je určen pro smluvní právo USA, proto se před použitím vzorového annexu poraďte s kvalifikovaným právním odborníkem.


### Fáze plánování a návrhu:

*  Projednávejte plánování a návrh s vývojáři a interními zainteresovanými stranami, např. se specialisty na bezpečnost.
*  Definujte bezpečnostní architekturu, bezpečnostní kontroly, protiopatření a procesy revize návrhu odpovídající potřebám ochrany a očekávané úrovni hrozeb. Tento proces by měl být podporován bezpečnostními specialisty.
*  Namísto dodatečného začleňování bezpečnosti do aplikací a API je výrazně nákladově efektivnější navrhovat bezpečnost již od počátku. OWASP doporučuje [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) a [OWASP Proactive Controls](https://top10proactive.owasp.org/) jako vhodný výchozí bod pro doporučení, jak navrhovat bezpečnost od samého začátku.
*  Provádějte modelování hrozeb; viz [OWASP Cheat Sheet: Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).
*  Vzdělávejte softwarové architekty v principech a vzorech bezpečného návrhu a vyzvěte je, aby je tam, kde je to možné, zahrnovali do svých návrhů.
*  Analyzujte datové toky společně s vývojáři.
*  Přidávejte bezpečnostní user stories vedle všech ostatních user stories.


### Bezpečný životní cyklus vývoje (Secure Development Lifecycle):

* Pro zlepšení procesů, které vaše organizace používá při vývoji aplikací a API, OWASP doporučuje [OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/). Tento model pomáhá organizacím formulovat a implementovat strategii bezpečnosti softwaru přizpůsobenou konkrétním rizikům, kterým daná organizace čelí.
* Poskytujte vývojářům školení v oblasti bezpečného programování (kódování) a další školení, která jim pomohou vytvářet robustnější a bezpečnější aplikace.
* Provádějte revize zdrojového kódu; viz [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
* Poskytněte vývojářům bezpečnostní nástroje a naučte je je používat, zejména nástroje pro statickou analýzu, analýzu složení softwaru (softwarových závislostí) (Software Composition Analysis), skenery tajných údajů (secrets) a skenery Infrastructure as Code (IaC).
* Pokud je to možné, vytvářejte pro vývojáře ochranné mantinely (guardrails – tedy technická ochranná opatření, která je směrují k bezpečnějším volbám).
* Navrhování silných a zároveň použitelných bezpečnostních kontrol je obtížné. Pokud je to možné, poskytujte bezpečná výchozí nastavení (secure defaults) a vytvářejte tzv. „paved roads“ (tj. zajistěte, aby nejjednodušší způsob byl zároveň nejbezpečnější a zjevně preferovaný postup). [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) představují dobrý výchozí bod pro vývojáře a mnoho moderních frameworků dnes již obsahuje standardní a účinné bezpečnostní mechanismy pro autorizaci, validaci, prevenci CSRF apod.
* Poskytněte vývojářům zásuvné moduly do IDE související s bezpečností a podporujte jejich používání.
* Zajistěte nástroj pro správu tajných údajů (secret management), potřebné licence a dokumentaci k jeho používání.
* Poskytněte vývojářům soukromý nástroj umělé inteligence (AI), ideálně s RAG serverem obsahujícím užitečnou bezpečnostní dokumentaci, prompty připravené vaším týmem pro dosažení lepších výsledků a MCP serverem, který volá bezpečnostní nástroje používané ve vaší organizaci. Naučte je AI používat bezpečně, protože ji budou používat bez ohledu na to, zda si to přejete.


### Zavedení kontinuálního testování bezpečnosti aplikací:

*  Testujte technické funkce a jejich integraci s IT architekturou a koordinujte testování byznysové logiky.
*  Vytvářejte testovací případy typu „use“ (běžné použití) a „abuse“ (zneužití) z technického i byznysového pohledu.
*  Řiďte bezpečnostní testování v souladu s interními procesy, potřebami ochrany a předpokládanou úrovní hrozeb dané aplikace.
*  Zajistěte nástroje pro bezpečnostní testování (fuzzery, DAST apod.), bezpečné prostředí pro testování a školení k jejich používání, nebo testování provádějte za vývojáře, nebo najměte testera.
*  Pokud je požadována vysoká míra jistoty (assurance), zvažte formální penetrační test, stejně jako zátěžové a výkonnostní testování.
*  Spolupracujte s vývojáři při rozhodování, které nálezy z hlášení o chybách je nutné opravit, a zajistěte, aby jim jejich manažeři poskytli čas na jejich odstranění.


### Nasazení (Rollout):

*  Uveďte aplikaci do provozu a v případě potřeby proveďte migraci z dříve používaných aplikací.
*  Dokončete veškerou dokumentaci, včetně databáze pro řízení změn (CMDB) a bezpečnostní architektury.


### Provoz a řízení změn (Operations and Change Management):

*  Provoz musí zahrnovat směrnice pro bezpečnostní správu aplikace (např. patch management).
*  Zvyšujte bezpečnostní povědomí uživatelů a řešte konflikty mezi použitelností a bezpečností.
*  Plánujte a řiďte změny, např. migraci na nové verze aplikace nebo dalších komponent, jako je operační systém, middleware a knihovny.
* Zajistěte, aby všechny aplikace byly evidovány v inventáři a aby byly zdokumentovány všechny důležité informace. Aktualizujte veškerou dokumentaci, včetně záznamů v databázi pro řízení změn (CMDB) a dokumentace bezpečnostní architektury, bezpečnostních kontrol a protiopatření, včetně provozních postupů (runbooks) nebo projektové dokumentace.
*  Provádějte logování, monitorování a upozorňování (alerting) pro všechny aplikace. Pokud některá z těchto oblastí chybí, doplňte ji.
*  Vytvořte procesy pro efektivní a účinné aktualizace a záplatování.
*  Zaveďte pravidelné harmonogramy skenování (ideálně dynamické, statické, skenování tajných údajů, IaC a analýzu softwarového složení).
*  Stanovte SLA pro opravy bezpečnostních chyb.
*  Poskytněte zaměstnancům (a ideálně i zákazníkům) způsob, jak hlásit chyby.
*  Zřiďte vyškolený tým pro reakci na bezpečnostní incidenty (incident response team), který rozumí tomu, jak vypadají útoky na software, a zná nástroje k jejich sledování (observabilitu).
*  Používejte nástroje pro blokování nebo ochranu před automatizovanými útoky.
*  Provádějte pravidelný hardening konfigurací alespoň jednou ročně (nebo častěji).
*  Minimálně jednou ročně provádějte penetrační testování (v závislosti na požadované míře jistoty).
*  Zaveďte procesy a nástroje pro posílení a ochranu vašeho softwarového dodavatelského řetězce.
*  Zaveďte a průběžně aktualizujte plán kontinuity byznysu a obnovy po havárii (business continuity a disaster recovery), který zahrnuje nejdůležitější aplikace a nástroje používané k jejich provozu a údržbě.


### Vyřazování systémů (Retiring Systems):

*	Veškerá požadovaná data by měla být archivována. Všechna ostatní data by měla být bezpečně smazána.

*	Aplikaci bezpečně vyřaďte z provozu, včetně odstranění nepoužívaných účtů, rolí a oprávnění.

*	Nastavte stav aplikace na „retired“ v databázi pro řízení změn (CMDB).


## Použití OWASP Top 10 jako standardu

OWASP Top 10 je primárně osvětový dokument. To však organizacím nebrání v tom, aby jej od svého vzniku v roce 2003 používaly jako de facto průmyslový standard AppSec. Pokud chcete OWASP Top 10 používat jako standard pro kódování (programování) nebo testování, je nutné si uvědomit, že představuje pouhé minimum a pouze výchozí bod.

Jednou z obtíží při používání OWASP Top 10 jako standardu je, že dokumentujeme AppSec rizika, nikoli nutně snadno testovatelné problémy. Například [A06:2025 Nezabezpečený návrh (Insecure Design)](A06_2025-Insecure_Design.md) je mimo rozsah většiny forem testování. Dalším příkladem je ověřování, zda je implementováno průběžné, používané a účinné logování a monitorování, které lze provést pouze prostřednictvím rozhovorů a vyžádání vzorku účinných reakcí na incidenty. Nástroj pro statickou analýzu kódu může hledat absenci logování, ale může být nemožné určit, zda byznys logika nebo řízení přístupu loguje kritická bezpečnostní narušení. Penetrační testeři mohou být schopni zjistit pouze to, že v testovacím prostředí vyvolali reakci na incident, která je zřídka monitorována stejným způsobem jako produkce.
 
Zde jsou naše doporučení, kdy je vhodné OWASP Top 10 použít:


<table>
  <tr>
   <td><strong>Oblast (Use Case)</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>OWASP Application Security Verification Standard</strong>
   </td>
  </tr>
  <tr>
   <td>Povědomí
   </td>
   <td>Ano
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Školení
   </td>
   <td>Základní úroveň
   </td>
   <td>Komplexní
   </td>
  </tr>
  <tr>
   <td>Návrh a architektura
   </td>
   <td>Částečně
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Kódovací standard
   </td>
   <td>Naprosté minimum
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Bezpečnostní revize kódu
   </td>
   <td>Naprosté minimum
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Kontrolní seznam pro peer review
   </td>
   <td>Naprosté minimum
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Jednotkové testování (Unit testing)
   </td>
   <td>Částečně
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Integrační testování
   </td>
   <td>Částečně 
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Penetrační testování
   </td>
   <td>Naprosté minimum
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Nástrojová podpora
   </td>
   <td>Naprosté minimum
   </td>
   <td>Ano
   </td>
  </tr>
  <tr>
   <td>Bezpečný dodavatelský řetězec
   </td>
   <td>Částečně
   </td>
   <td>Ano
   </td>
  </tr>
</table>

Doporučujeme všem, kdo chtějí zavést standard zabezpečení aplikací, použít [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS), protože je navržen tak, aby byl ověřitelný a testovatelný, a lze jej použít ve všech fázích bezpečného životního cyklu vývoje.

ASVS je jedinou přijatelnou volbou pro dodavatele nástrojů. Nástroje nemohou komplexně detekovat, testovat ani chránit vůči OWASP Top 10 vzhledem k povaze některých rizik v OWASP Top 10, zejména s odkazem na [A06:2025 Nezabezpečený návrh (Insecure Design)](A06_2025-Insecure_Design.md). OWASP odrazuje od jakýchkoli tvrzení o úplném pokrytí OWASP Top 10, protože to prostě není pravda.
