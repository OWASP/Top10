# A9:2017 Používání komponent se známými zranitelnostmi

| Průvodci hrozeb / Vektor útoku | Bezpečnostní slabina           | Dopady               |
| -- | -- | -- |
| Access Lvl : Zneužitelnost 2 | Rozšíření 3 : Zjistitelnost 2 | Technické 2 : Obchodní |
| Ačkoliv je snadné nalézt již zaznamenané exploity související s mnoha známými zranitelnostmi, jiné zranitelnosti vyžadují soustředěné úsilí vytvoření vlastního exploitu. | Tento problému je velmi rozšířen. Vývojové vzorce náročné na komponenty mohou vést k tomu, že vývojové týmy ani nepochopí, které komponenty používají ve své aplikaci nebo API – tím méně je budou udržovat aktuální. Některé skenery, jako například retire.js, pomáhají při detekci, ale určení zneužitelnosti vyžaduje další úsilí. | Zatímco některé známé zranitelnosti vedou pouze znamenají jen malé dopady, některé z dosud největších prolomení se spoléhaly na využití známých zranitelností v komponentách. V závislosti na aktivech, která chráníte, by toto riziko mělo být na začátku seznamu. |

## Je aplikace zranitelná?

Pravděpodobně jste zranitelní:

* Neznáte-li verze všech komponent, které používáte (na straně klienta i na straně serveru). To se týká jak komponent, které používáte přímo, tak jako vnořené závislosti.
* Je-li software zranitelný, nepodporovaný nebo zastaralý. To se týká OS, webového / aplikačního serveru, systému správy databází (DBMS), aplikace, API a všechny komponenty, běžící prostředí a knihovny.
* Nevyhledáváte-li pravidelně zranitelnosti a nejste přihlášení k odběru bulletinů zaměřených na zabezpečení souvisejících s komponentami, které používáte.
* Neopravíte-li nebo neupgradujete-li základní platformu, frameworky včas a s ohledem na rizika. To se běžně děje v prostředích, kdy záplatování je měsíční nebo čtvrtletní úkol v rámci řízení změn, což znamená, že organizace je po mnoho dní nebo měsíců zbytečně vystavena zranitelnostem které ve skutečnosti už jsou opraveny.
* Netestují-li vývojáři softwaru kompatibilitu aktualizovaných, upgradovaných nebo opravených knihoven.
* Nezajistíte-li konfigurace komponent (viz **A6:2017-Nesprávná bezpečnostní konfigurace**).

## Jaká je prevence?

Je třeba zavést proces řízení oprav, který umožní:

* Odstranit nepoužívané závislosti, nepotřebné funkce, komponenty, soubory a dokumentaci.
* Průběžně inventarizovat verze komponent jak na straně klienta, tak na straně serveru (např. frameworky, knihovny) a jejich závislosti pomocí nástrojů, jakými jsou versions, DependencyCheck, retire.js atd.  
* •	Průběžně sledujte zdroje o zranitelnostech komponent v CVE a NVD. K automatizaci procesu použijte Software Composition Analysis. Přihlaste se k odběru e-mailových upozornění na zranitelnosti související s komponentami, které používáte. 
* Komponenty získávejte pouze z oficiálních zdrojů přes zabezpečené odkazy. Upřednostňujte podepsané balíčky, abyste snížili šanci získání upravenou škodlivou komponentu.
* Dávejte pozor na knihovny a komponenty, které již nejsou podporovány nebo již nedostávají bezpečnostní aktualizace. Pokud oprava není možná, zkuste použít virtuální opravy k detekci nebo k zabránění zneužití známých chyb zabezpečení.

Každá organizace by měla zajistit, aby aktualizace nebo změny konfigurace byly sledovány, upřednostňovány a aplikovány během celého životního cyklu aplikace nebo portfolia.

## Příklady útočných scénářů

**Scénář #1**: Komponenty obvykle běží se stejnými oprávněními jako samotná aplikace, takže nedostatky v kterékoliv komponentě mohou mít závažný dopad. Tyto chyby mohou být neúmyslné (např. chyba kódování) nebo úmyslné (např. zadní vrátka v komponentě). Některé příklady odhalených zneužitelných zranitelnosti komponent:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), zranitelnost frameworku Struts 2 umožňující vzdálené spuštění libovolného kódu na serveru. Stála za mnoha významných narušení.
* Zatímco [internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) internet věcí (IoT) je často obtížné nebo nemožné opravit, důležitost jejich oprav může být velká (např. biomedicínská zařízení).

Existují automatizované nástroje pomáhající útočníkům najít neopravené nebo nesprávně nakonfigurované systémy. Například [vyhledavač Shodan IoT](https://www.shodan.io/report/89bnfUyJ) může vám pomoci najít zařízení, která stále trpí zranitelností [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) opravené v dubnu 2014.

## Reference

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Externí

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
