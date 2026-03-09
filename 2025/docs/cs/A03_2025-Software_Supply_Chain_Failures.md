# A03:2025 Selhání dodavatelského řetězce softwaru (Software Supply Chain Failures) ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Tato položka se umístila na prvním místě v komunitním průzkumu Top 10, přičemž ji přesně 50 % respondentů zařadilo na 1. místo. Od svého prvního výskytu v Top 10 v roce 2013 pod názvem „A9 – Používání komponent se známými zranitelnostmi“ se rozsah tohoto rizika rozšířil a nyní zahrnuje veškerá selhání dodavatelského řetězce, nikoli pouze ta související se známými zranitelnostmi. Navzdory tomuto rozšíření zůstávají selhání dodavatelského řetězce obtížně identifikovatelná – pouze 11 položek Common Vulnerabilities and Exposures (CVE) má přiřazené související CWE. Při testování a reportování v komunitně poskytnutých datech však tato kategorie vykazuje nejvyšší průměrnou míru výskytu, a to 5,19 %. Mezi relevantní CWE patří *CWE-477: Use of Obsolete Function*, *CWE-1104: Use of Unmaintained Third Party Components*, *CWE-1329: Reliance on Component That is Not Updateable* a *CWE-1395: Dependency on Vulnerable Third-Party Component*.

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

Selhání softwarového dodavatelského řetězce jsou selhání nebo jiné kompromitace v procesu sestavování, distribuce nebo aktualizace softwaru. Často jsou způsobeny zranitelnostmi nebo škodlivými změnami v kódu třetích stran, nástrojích nebo dalších závislostech, na nichž systém závisí.

Pravděpodobně jste zranitelní, pokud:

* nesledujete systematicky verze všech používaných komponent, a to jak na straně klienta, tak na straně serveru. To zahrnuje jak přímo používané komponenty, tak i vnořené (tranzitivní) závislosti.
* používaný software je zranitelný, nepodporovaný nebo zastaralý, včetně operačního systému, webového nebo aplikačního serveru, systému správy databází (DBMS), aplikací, API, běhových prostředí a knihoven.
* neprovádíte pravidelné skenování zranitelností ani neodebíráte bezpečnostní bulletiny vztahující se k používaným komponentám.
* nemáte zaveden proces řízení změn ani systematickou evidenci změn v rámci dodavatelského řetězce, včetně sledování vývojových prostředí (IDE), jejich rozšíření a aktualizací, změn v repozitářích zdrojového kódu organizace, sandboxů, repozitářů obrazů a knihoven, způsobu vytváření a ukládání artefaktů apod. Každá část dodavatelského řetězce by měla být dokumentována, zejména prováděné změny.
* nebyly hardenovány všechny části vašeho dodavatelského řetězce, se zvláštním důrazem na kontrolu přístupu a uplatňování principu nejmenších oprávnění.
* v systémech dodavatelského řetězce není uplatněno oddělení rolí. Žádná jednotlivá osoba by neměla mít možnost napsat kód a bez kontroly jinou osobou jej nasadit až do produkčního prostředí.
* komponenty z nedůvěryhodných zdrojů jsou používány v produkčních prostředích nebo na ně mohou mít vliv, a to napříč jakoukoli částí technologického stacku.
* neopravujete ani neaktualizujete základní platformu, frameworky a závislosti včas a na základě rizik. K tomu obvykle dochází v prostředích, kde jsou opravy prováděny jednou za měsíc nebo za čtvrtletí v rámci řízení změn, což vystavuje organizace zbytečnému riziku po dobu několika dnů nebo měsíců, než jsou zranitelnosti opraveny.
* vývojáři netestují kompatibilitu aktualizovaných, upgradovaných nebo záplatovaných knihoven.
* nezabezpečujete konfigurace všech částí svého systému (viz [A02:2025 - Chybná bezpečnostní konfigurace (Security Misconfiguration)](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
* vaše CI/CD pipeline má slabší zabezpečení než systémy, které sestavuje a nasazuje, zejména pokud je složitá.


## Jak tomu zabránit

Měl by být zaveden proces správy záplat, jehož cílem je:

* Centrálně vytvářet a spravovat Software Bill of Materials (SBOM) pro celý software.
* Sledovat nejen přímé závislosti, ale i jejich vnořené (tranzitivní) závislosti.
* Snižovat útočnou plochu odstraňováním nepoužívaných závislostí, zbytečných funkcí, komponent, souborů a dokumentace.
* Průběžně evidovat verze komponent na straně klienta i serveru (např. frameworky, knihovny) a jejich závislosti s využitím nástrojů jako OWASP Dependency Track, OWASP Dependency Check, retire.js apod.
* Průběžně sledovat zdroje, jako jsou Common Vulnerabilities and Exposures (CVE), National Vulnerability Database (NVD) a [Open Source Vulnerabilities (OSV)](https://osv.dev/), z hlediska zranitelností v používaných komponentách. K automatizaci procesu využívat nástroje pro analýzu softwarové skladby, softwarového dodavatelského řetězce nebo bezpečnostně zaměřené nástroje SBOM. Odebírat upozornění na bezpečnostní zranitelnosti související s používanými komponentami.
* Získávat komponenty výhradně z oficiálních (důvěryhodných) zdrojů prostřednictvím zabezpečených spojení. Upřednostňovat podepsané balíčky ke snížení pravděpodobnosti zahrnutí pozměněné nebo škodlivé komponenty (viz [A08:2025-Software and Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
* Pečlivě volit, kterou verzi závislosti používat, a aktualizovat pouze tehdy, když je to nutné.
* Sledovat knihovny a komponenty, které nejsou udržované nebo neposkytují bezpečnostní opravy pro starší verze. Pokud není možné provést záplatu, zvážit migraci na alternativu. Pokud ani to není možné, zvážit nasazení virtuální záplaty k monitorování, detekci nebo ochraně před zjištěným problémem.
* Pravidelně aktualizovat své CI/CD nástroje, IDE a další vývojářské nástroje.
* Vyhnout se nasazování aktualizací na všechny systémy současně. Používat postupné zavádění nebo kanárkové nasazení, abyste omezili riziko v případě narušení důvěryhodného dodavatele.


Měl by být zaveden proces řízení změn nebo systém sledování změn pro sledování změn v:

* Nastavení CI/CD (všechny build nástroje a pipeline)
* Repozitářích kódu
* Sandboxových oblastech
* Vývojářských IDE
* Nástrojích SBOM a vytvářených artefaktech
* Logovacích systémech a logech
* Integracích třetích stran, například SaaS
* Repozitářích artefaktů
* Registrech kontejnerů


Zabezpečit (hardenovat) následující systémy, včetně povolení MFA a uzamčení IAM:

* Repozitáře zdrojového kódu (včetně neukládání tajných údajů, ochrany větví a zálohování)
* Vývojářské pracovní stanice (pravidelné záplatování, MFA, monitorování a další)
* Build server a CI/CD (oddělení rolí, řízení přístupu, podepsané buildy, tajné údaje vázané na prostředí, logy odolné proti manipulaci a další)
* Artefakty (zajištění integrity prostřednictvím provenance, podepisování a časového razítkování, propagace artefaktů namísto opakovaného sestavování pro každé prostředí, zajištění neměnnosti buildů)
* Infrastruktura jako kód (spravovaná stejně jako veškerý kód, včetně používání pull requestů a správy verzí)

Každá organizace musí zajistit průběžný plán monitorování, triáže a aplikace aktualizací nebo změn konfigurace po celou dobu životnosti aplikace nebo aplikačního portfolia.


## Příklady scénářů útoků

**Scénář #1:** Důvěryhodný dodavatel je kompromitován malwarem, což vede ke kompromitaci vašich počítačových systémů při aktualizaci. Nejznámějším příkladem je pravděpodobně:

* Kompromitace SolarWinds v roce 2019, která vedla ke kompromitaci přibližně 18 000 organizací. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Scénář #2:** Důvěryhodný dodavatel je kompromitován tak, že se chová škodlivě pouze za specifické podmínky.

* Krádež 1,5 miliardy USD z platformy Bybit v roce 2025 byla způsobena útokem na [dodavatelský řetězec v softwaru peněženky](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/), který se spustil pouze při používání cílové peněženky.

**Scénář #3:** [Útok na dodavatelský řetězec Shai-Hulud](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) v roce 2025 byl prvním úspěšným samopropagujícím se npm červem. Útoky zasévaly škodlivé verze populárních balíčků, které pomocí post-install skriptu shromažďovaly a exfiltrovaly citlivá data do veřejných repozitářů GitHub. Malware rovněž detekoval npm tokeny v prostředí oběti a automaticky je využíval k nahrávání škodlivých verzí všech dostupných balíčků. Červ se rozšířil do více než 500 verzí balíčků, než byl narušen ze strany npm. Tento útok na dodavatelský řetězec byl pokročilý, rychle se šířil a byl škodlivý a tím, že cílil na vývojářské stroje, ukázal, že vývojáři sami jsou nyní hlavním cílem útoků na dodavatelský řetězec.

**Scénář #4:** Komponenty obvykle běží se stejnými oprávněními jako samotná aplikace, a proto mohou chyby v jakékoli komponentě mít závažný dopad. Tyto chyby mohou být neúmyslné (např. programátorská chyba) nebo úmyslné (např. zadní vrátka v komponentě). Mezi některé příklady zneužitelných zranitelností komponent patří:

* CVE-2017-5638 – zranitelnost vzdáleného spuštění kódu v Apache Struts 2, která umožňuje spuštění libovolného kódu na serveru a byla dávána do souvislosti s významnými narušeními bezpečnosti.
* CVE-2021-44228 („Log4Shell“) – zero-day zranitelnost vzdáleného spuštění kódu v Apache Log4j, která byla dávána do souvislosti s ransomwarem, kryptominingem a dalšími útočnými kampaněmi.


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
