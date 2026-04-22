# A09:2025 Selhání bezpečnostního logování a upozorňování (Security Logging & Alerting Failures) ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## Pozadí

Název této kategorie byl mírně upraven, aby více zdůraznil funkci upozorňování (alerting), která je nezbytná k vyvolání reakce na relevantní události zaznamenané v logovacích záznamech. V datech bude tato oblast vždy spíše podreprezentovaná a již potřetí byla do žebříčku Top 10 zařazena na základě hlasování účastníků komunitního průzkumu. Její testování je mimořádně obtížné a v datech CVE/CVSS je zastoupena jen minimálně (pouze 723 záznamy CVE), přesto však může mít zásadní dopad na viditelnost bezpečnostních událostí, upozorňování na incidenty i forenzní analýzu. Zahrnuje problémy s *nesprávným zpracováním kódování výstupu při zápisu do logovacích souborů (CWE-117), s vkládáním citlivých dat do logovacích souborů (CWE-532) a s nedostatečným logováním (CWE-778).*

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
   <td>5
   </td>
   <td>11,33 %
   </td>
   <td>3,91 %
   </td>
   <td>85,96 %
   </td>
   <td>46,48 %
   </td>
   <td>7,19
   </td>
   <td>2,65
   </td>
   <td>260 288
   </td>
   <td>723
   </td>
  </tr>
</table>



## Popis 

Bez logování a monitorování nelze útoky a narušení zabezpečení odhalit a bez upozorňování je během bezpečnostního incidentu velmi obtížné reagovat rychle a účinně. K nedostatkům v logování, průběžném monitorování, detekci a upozorňování, které mají vést k zahájení aktivní reakce, dochází vždy, když:

* Auditovatelné události, jako jsou přihlášení, neúspěšná přihlášení a transakce s vysokou hodnotou, nejsou logovány vůbec nebo jsou logovány nekonzistentně (například se logují pouze úspěšná přihlášení, nikoli neúspěšné pokusy).
* Varování a chyby negenerují žádné, dostatečné nebo srozumitelné logovací záznamy.
* Integrita logů není řádně chráněna před manipulací.
* Logy aplikací a rozhraní API nejsou monitorovány z hlediska podezřelé aktivity.
* Logy jsou ukládány pouze lokálně a nejsou řádně zálohovány.
* Vhodné prahové hodnoty pro upozorňování a procesy eskalace reakce nejsou zavedeny nebo nejsou účinné. Upozornění nejsou přijímána ani vyhodnocována v přiměřené době.
* Penetrační testování a skeny prováděné nástroji pro dynamické testování bezpečnosti aplikací (DAST), jako jsou Burp nebo ZAP, nespouštějí upozornění.
* Aplikace nedokáže aktivní útoky detekovat, eskalovat ani na ně upozornit v reálném čase nebo téměř v reálném čase.
* Jste zranitelní vůči úniku citlivých informací tím, že události logování a upozorňování zpřístupníte uživateli nebo útočníkovi (viz [A01:2025 Nedostatečné řízení přístupu (Broken Access Control)](A01_2025-Broken_Access_Control.md)), nebo tím, že logujete citlivé informace, které by logovány být neměly (například PII nebo PHI).
* Pokud nejsou data v logu správně zakódována, jste zranitelní vůči injektážím nebo útokům na systémy logování či monitorování.
* Aplikace opomíjí chyby a jiné výjimečné stavy nebo je zpracovává nesprávně, takže systém neví, že k chybě došlo, a není proto schopen zaznamenat, že nastal problém.
* Odpovídající „use cases“ pro vyvolání upozornění chybějí nebo jsou zastaralé, a proto nelze rozpoznat zvláštní situaci.
* Příliš velké množství falešně pozitivních upozornění znemožňuje odlišit důležitá upozornění od nedůležitých, v důsledku čehož jsou rozpoznána příliš pozdě, nebo vůbec ne (fyzické přetížení týmu SOC).
* Zjištěná upozornění nelze správně zpracovat, protože playbook pro daný use case je neúplný, zastaralý nebo chybí.


## Jak tomu zabránit

Vývojáři by měli v závislosti na riziku aplikace implementovat některé nebo všechny z následujících kontrol:

* Zajistěte, aby všechna selhání přihlášení, selhání kontroly přístupu a selhání validace vstupů na straně serveru mohla být logována s dostatečným uživatelským kontextem pro identifikaci podezřelých nebo škodlivých účtů a aby byla uchovávána dostatečně dlouho pro účely opožděné forenzní analýzy.
* Zajistěte, aby byla logována každá část vaší aplikace, která obsahuje bezpečnostní kontrolu, bez ohledu na to, zda uspěje nebo selže.
* Zajistěte, aby byly logy generovány ve formátu, který mohou řešení pro správu logů snadno zpracovat.
* Zajistěte, aby data logů byla správně enkódována, aby se zabránilo injektování nebo útokům na logovací nebo monitorovací systémy.
* Zajistěte, aby všechny transakce měly auditní stopu s kontrolami integrity, které zabrání manipulaci nebo smazání, například append-only databázové tabulky nebo podobný mechanismus.
* Zajistěte, aby všechny transakce, které vyvolají chybu, byly rollbackovány a spuštěny znovu. Vždy fail closed (tj. bezpečně selžte; nepokračujte).
* Pokud se vaše aplikace nebo její uživatelé chovají podezřele, vyvolejte upozornění. Vytvořte pro vývojáře k tomuto tématu pokyny, aby s tím mohli v kódu počítat, nebo pro to zakupte systém.
* Týmy DevSecOps a bezpečnostní týmy by měly zavést účinné scénáře monitorování a upozorňování (use cases) včetně playbooků, aby tým Security Operations Center (SOC) podezřelé aktivity rychle detekoval a reagoval na ně.
* Přidejte do aplikace „honeytokeny“ jako pasti pro útočníky, např. do databáze nebo dat, jako skutečnou a/nebo technickou identitu uživatele. Jelikož se v běžném provozu nepoužívají, jakýkoli přístup generuje logovací data, na která lze vyvolat upozornění s téměř nulovým počtem falešných pozitiv (false positives).
* Analýza chování a podpora umělou inteligencí mohou být volitelně doplňkovou technikou, která podporuje nízkou míru falešně pozitivních upozornění.
* Vytvořte nebo přijměte plán reakce na incidenty a obnovy, například National Institute of Standards and Technology (NIST) 800-61r2 nebo novější. Naučte své softwarové vývojáře, jak vypadají útoky na aplikace a bezpečnostní incidenty, aby je mohli hlásit.


Existují komerční a open-source produkty pro ochranu aplikací, jako je OWASP ModSecurity Core Rule Set, a open-source software pro korelaci logů, jako je stack Elasticsearch, Logstash, Kibana (ELK), které nabízejí vlastní dashboardy a upozorňování a mohou vám pomoci tyto problémy řešit. Existují také komerční nástroje observability, které vám mohou pomoci na útoky reagovat nebo je blokovat téměř v reálném čase.


## Příklady scénářů útoků

**Scénář #1:** Provozovatel webových stránek poskytovatele dětského zdravotního pojištění/plánu nedokázal odhalit narušení bezpečnosti kvůli nedostatku monitorování a logování. Externí subjekt informoval poskytovatele zdravotního plánu, že útočník získal přístup k tisícům citlivých zdravotních záznamů více než 3,5 milionu dětí a upravil je. Postincidentní přezkum zjistil, že vývojáři webových stránek neřešili významné zranitelnosti. Jelikož systém nebyl logován ani monitorován, mohl únik dat probíhat již od roku 2013, tedy po dobu více než sedmi let.

**Scénář #2:** Velká indická letecká společnost zaznamenala únik dat zahrnující osobní údaje milionů cestujících za více než deset let, včetně údajů z pasů a kreditních karet. K úniku dat došlo u externího poskytovatele cloudového hostingu, který leteckou společnost o úniku po určité době informoval.

**Scénář #3:** Velká evropská letecká společnost utrpěla narušení zabezpečení, které podléhalo oznámení podle GDPR. Narušení bylo údajně způsobeno bezpečnostními zranitelnostmi v platební aplikaci, které útočníci zneužili a získali tak více než 400 000 záznamů o platbách zákazníků. Regulátor ochrany osobních údajů letecké společnosti v důsledku toho uložil pokutu ve výši 20 milionů liber.


## Reference

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## Seznam mapovaných CWE

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
