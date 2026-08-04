# A03:2025 Selhání dodavatelského řetězce softwaru (Software Supply Chain Failures) ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Tato položka byla nejvýše hodnocena v komunitním průzkumu Top 10, přičemž přesně 50 % respondentů ji zařadilo na 1. místo. Od svého prvního výskytu v Top 10 v roce 2013 jako „A9 – Používání komponent se známými zranitelnostmi“ se rozsah tohoto rizika rozšířil tak, aby zahrnoval veškerá selhání dodavatelského řetězce, nikoli pouze ta, která zahrnují známé zranitelnosti. Navzdory tomuto rozšířenému rozsahu zůstávají selhání dodavatelského řetězce výzvou z hlediska identifikace, přičemž pouze 11 položek Common Vulnerabilities and Exposures (CVE) má související CWE. Při testování a hlášení v poskytnutých datech však tato kategorie vykazuje nejvyšší průměrnou míru výskytu, a to 5,19 %. Relevantní CWE jsou *CWE-477: Use of Obsolete Function, CWE-1104: Use of Unmaintained Third Party Components, CWE-1329: Reliance on Component That is Not Updateable a CWE-1395: Dependency on Vulnerable Third-Party Component*.

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
   <td>6
   </td>
   <td>9,56 %
   </td>
   <td>5,72 %
   </td>
   <td>65,42 %
   </td>
   <td>27,47 %
   </td>
   <td>8,17
   </td>
   <td>5,23
   </td>
   <td>215 248
   </td>
   <td>11
   </td>
  </tr>
</table>



## Popis

Selhání dodavatelského řetězce softwaru jsou selhání nebo jiné kompromitace v procesu sestavování, distribuce nebo aktualizace softwaru. Často jsou způsobena zranitelnostmi nebo škodlivými změnami v kódu třetích stran, nástrojích nebo jiných závislostech, na nichž systém závisí.

Pravděpodobně jste zranitelní, pokud:

* nesledujete pečlivě verze všech komponent, které používáte (na straně klienta i na straně serveru). To zahrnuje komponenty, které používáte přímo, i vnořené (tranzitivní) závislosti.
* software je zranitelný, nepodporovaný nebo zastaralý. To zahrnuje operační systém, webový/aplikační server, systém správy databází (DBMS), aplikace, API a všechny komponenty, běhová prostředí a knihovny.
* neprovádíte pravidelně skenování zranitelností a neodebíráte bezpečnostní bulletiny vztahující se ke komponentám, které používáte.
* nemáte proces řízení změn nebo sledování změn v rámci svého dodavatelského řetězce, včetně sledování IDE, rozšíření IDE a aktualizací, změn v repozitáři kódu vaší organizace, sandboxů, repozitářů obrazů a knihoven, způsobu, jakým jsou artefakty vytvářeny a ukládány, atd. Každá část vašeho dodavatelského řetězce by měla být dokumentována, zejména změny.
* nemáte hardenovanou každou část svého dodavatelského řetězce, se zvláštním zaměřením na řízení přístupu a uplatňování nejmenších oprávnění.
* vaše systémy dodavatelského řetězce nemají žádné oddělení rolí. Žádná jednotlivá osoba by neměla být schopna napsat kód a povýšit jej až do produkce bez dohledu jiné lidské osoby.
* komponenty z nedůvěryhodných zdrojů, napříč jakoukoli částí technologického stacku, jsou používány v produkčních prostředích nebo mohou mít na produkční prostředí dopad.
* neopravujete nebo neupgradujete základní platformu, frameworky a závislosti včasným způsobem založeným na riziku. K tomu běžně dochází v prostředích, kde je záplatování měsíčním nebo čtvrtletním úkolem v rámci řízení změn, což ponechává organizace vystavené dnům nebo měsícům zbytečné expozice před opravou zranitelností.
* vývojáři softwaru netestují kompatibilitu aktualizovaných, upgradovaných nebo záplatovaných knihoven.
* nezabezpečujete konfigurace každé části svého systému (viz [A02:2025 - Chybná bezpečnostní konfigurace (Security Misconfiguration)](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
* vaše CI/CD pipeline má slabší zabezpečení než systémy, které sestavuje a nasazuje, zejména pokud je složitá.


## Jak tomu zabránit

Měl by být zaveden proces správy záplat za účelem:

* Centrálně generovat a spravovat Software Bill of Materials (SBOM) celého vašeho softwaru.
* Sledovat nejen vaše přímé závislosti, ale také jejich (tranzitivní) závislosti, a tak dále.
* Snižovat útočnou plochu odstraňováním nepoužívaných závislostí, zbytečných funkcí, komponent, souborů a dokumentace.
* Průběžně inventarizovat verze komponent na straně klienta i na straně serveru (např. frameworků, knihoven) a jejich závislostí pomocí nástrojů, jako jsou OWASP Dependency Track, OWASP Dependency Check, retire.js atd.
* Průběžně monitorovat zdroje, jako jsou Common Vulnerabilities and Exposures (CVE), National Vulnerability Database (NVD) a [Open Source Vulnerabilities (OSV)](https://osv.dev/), z hlediska zranitelností v komponentách, které používáte. K automatizaci procesu používat analýzu složení softwaru, nástroje pro dodavatelský řetězec softwaru nebo bezpečnostně zaměřené nástroje SBOM. Odebírat upozornění na bezpečnostní zranitelnosti související s komponentami, které používáte.
* Získávat komponenty pouze z oficiálních (důvěryhodných) zdrojů přes zabezpečené odkazy. Upřednostňovat podepsané balíčky, aby se snížila pravděpodobnost zahrnutí pozměněné, škodlivé komponenty (viz [A08:2025-Software and Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
* Záměrně volit, kterou verzi závislosti používáte, a upgradovat pouze tehdy, když je to potřeba.
* Monitorovat knihovny a komponenty, které nejsou udržované nebo nevytvářejí bezpečnostní záplaty pro starší verze. Pokud záplatování není možné, zvážit migraci na alternativu. Pokud to není možné, zvážit nasazení virtuální záplaty za účelem monitorování, detekce nebo ochrany proti zjištěnému problému.
* Pravidelně aktualizovat vaše CI/CD, IDE a jakékoli další vývojářské nástroje.
* Vyhnout se nasazování aktualizací na všechny systémy současně. Používat postupná zavádění nebo kanárková nasazení k omezení expozice v případě kompromitace důvěryhodného dodavatele.

Měl by být zaveden proces řízení změn nebo systém sledování za účelem sledování změn v:

* Nastaveních CI/CD (všechny nástroje pro sestavení a pipeline)
* Repozitářích kódu
* Sandboxových oblastech
* Vývojářských IDE
* Nástrojích SBOM a vytvořených artefaktech
* Logovacích systémech a logách
* Integracích třetích stran, například SaaS
* Repozitářích artefaktů
* Registrech kontejnerů

Zodolnit (hardenovat) následující systémy, což zahrnuje povolení MFA a uzamčení IAM:

* Váš repozitář kódu (což zahrnuje neukládání tajných údajů do repozitáře, ochranu větví, zálohy)
* Vývojářské pracovní stanice (pravidelné záplatování, MFA, monitorování a další)
* Váš server pro sestavení a CI/CD (oddělení povinností, řízení přístupu, podepsaná sestavení, tajné údaje s rozsahem na prostředí, logy umožňující zjistit manipulaci, další)
* Vaše artefakty (zajištění integrity prostřednictvím provenience, podepisování a časového razítkování, povyšování artefaktů namísto opětovného sestavování pro každé prostředí, zajištění neměnnosti sestavení)
* Infrastrukturu jako kód (spravovanou stejně jako veškerý kód, včetně používání PR a správy verzí)

Každá organizace musí zajistit průběžný plán monitorování, triáže a aplikování aktualizací nebo změn konfigurace po dobu životnosti aplikace nebo portfolia.


## Příklady scénářů útoků

**Scénář #1:** Důvěryhodný dodavatel je kompromitován malwarem, což vede ke kompromitaci vašich počítačových systémů při upgradu. Nejznámějším příkladem je pravděpodobně:

* Kompromitace SolarWinds v roce 2019, která vedla ke kompromitaci přibližně 18 000 organizací.  [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Scénář #2:** Důvěryhodný dodavatel je kompromitován tak, že se chová škodlivě pouze za určité podmínky.

* Krádež 1,5 miliardy USD z platformy Bybit v roce 2025 byla způsobena útokem na [dodavatelský řetězec v softwaru peněženky](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/), který se spustil pouze tehdy, když byla používána cílová peněženka.

**Scénář #3:** [Útok na dodavatelský řetězec Shai-Hulud](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) v roce 2025 byl prvním úspěšným samostatně se šířícím červem npm. Útoky vložily škodlivé verze populárních balíčků, které pomocí post-install skriptu shromažďovaly a exfiltrovaly citlivá data do veřejných repozitářů GitHub. Malware také detekoval tokeny npm v prostředí oběti a automaticky je používal k nahrání škodlivých verzí jakéhokoli dostupného balíčku. Červ dosáhl více než 500 verzí balíčků, než byl zastaven službou npm. Tento útok na dodavatelský řetězec byl pokročilý, rychle se šířící a způsobující škody a zaměřením na vývojářské stroje prokázal, že samotní vývojáři jsou nyní prvořadými cíli útoků na dodavatelský řetězec.

**Scénář #4:** Komponenty obvykle běží se stejnými oprávněními jako samotná aplikace, takže nedostatky v jakékoli komponentě mohou vést k závažnému dopadu. Takové nedostatky mohou být neúmyslné (např. chyba v kódu) nebo úmyslné (např. zadní vrátka v komponentě). Některé příklady objevených zneužitelných zranitelností komponent jsou:

* CVE-2017-5638, zranitelnost vzdáleného spuštění kódu ve Struts 2, která umožňuje spuštění libovolného kódu na serveru, byla označována za příčinu významných narušení.
* CVE-2021-44228 („Log4Shell“), zero-day zranitelnost vzdáleného spuštění kódu v Apache Log4j, byla dávána za vinu ransomwaru, kryptominingu a dalším útočným kampaním.


## Reference

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## Seznam mapovaných CWE

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
