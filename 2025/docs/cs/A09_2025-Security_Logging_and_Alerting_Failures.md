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

Vývojáři by měli v závislosti na rizikovosti aplikace implementovat některá nebo všechna následující opatření:

* Zajistěte, aby všechna selhání přihlášení, kontroly přístupu a validace vstupů na straně serveru mohla být logována s dostatečným uživatelským kontextem umožňujícím identifikaci podezřelých nebo škodlivých účtů a aby byla uchovávána po dostatečně dlouhou dobu pro účely následné forenzní analýzy.
* Zajistěte, aby byla logována každá část aplikace obsahující bezpečnostní kontrolu, a to bez ohledu na to, zda tato kontrola uspěje, nebo selže.
* Zajistěte, aby byly logy generovány ve formátu, který mohou řešení pro správu logů snadno zpracovat.
* Zajistěte, aby byla data logů správně kódována, aby se zabránilo injektážím nebo útokům na systémy logování či monitorování.
* Zajistěte, aby všechny transakce měly auditní stopu s kontrolami integrity, které zabrání manipulaci nebo smazání, například v podobě append-only databázových tabulek nebo podobného mechanismu.
* Zajistěte, aby všechny transakce, které vyvolají chybu, byly vráceny zpět a znovu spuštěny. Vždy bezpečně selhávejte (fail closed).
* Pokud se aplikace nebo její uživatelé chovají podezřele, vyvolejte upozornění. Připravte pro vývojáře pokyny k této oblasti, aby s ní mohli při vývoji počítat, nebo pro tento účel pořiďte vhodný systém.
* Týmy DevSecOps a bezpečnostní týmy by měly zavést účinné scénáře monitorování a upozorňování (use cases) včetně playbooků, aby tým Security Operations Center (SOC) dokázal podezřelé aktivity rychle detekovat a reagovat na ně.
* Přidejte do aplikace „honeytokeny“ jako pasti na útočníky, například do databáze nebo dat, a to jako skutečnou a/nebo technickou identitu uživatele. Jelikož se při běžném provozu nepoužívají, jakýkoli přístup k nim generuje logovací data, která lze využít k vyvolání upozornění s téměř nulovým počtem falešně pozitivních případů.
* Analýza chování a podpora umělou inteligencí mohou volitelně sloužit jako doplňková technika podporující nízkou míru falešně pozitivních upozornění.
* Vytvořte nebo převezměte plán reakce na incidenty a obnovy, například podle National Institute of Standards and Technology (NIST) 800-61r2 nebo novější verze. Naučte své vývojáře softwaru, jak vypadají útoky na aplikace a bezpečnostní incidenty, aby je dokázali hlásit.

Existují komerční i open-source produkty pro ochranu aplikací, jako je OWASP ModSecurity Core Rule Set, a open-source nástroje pro korelaci logů, jako je stack Elasticsearch, Logstash, Kibana (ELK), které nabízejí vlastní dashboardy a upozorňování a mohou vám pomoci při řešení těchto problémů. Existují také komerční nástroje pro observability, které vám mohou pomoci reagovat na útoky nebo je blokovat téměř v reálném čase.


## Příklady scénářů útoků

**Scénář č. 1:** Provozovatel webu poskytovatele dětského zdravotního pojištění nedokázal kvůli nedostatečnému monitorování a logování odhalit narušení bezpečnosti. Externí subjekt informoval poskytovatele zdravotního pojištění, že útočník získal přístup k tisícům citlivých zdravotních záznamů více než 3,5 milionu dětí a upravil je. Následné přezkoumání po incidentu ukázalo, že vývojáři webu neodstranili významné zranitelnosti. Protože systém nebyl logován ani monitorován, mohl únik dat probíhat již od roku 2013, tedy déle než sedm let.

**Scénář č. 2:** U velké indické letecké společnosti došlo k úniku dat, který zahrnoval osobní údaje milionů cestujících za období delší než deset let, včetně údajů z pasů a platebních karet. K úniku došlo u externího poskytovatele cloudového hostingu, který leteckou společnost o narušení informoval až s odstupem času.

**Scénář č. 3:** Velká evropská letecká společnost utrpěla narušení zabezpečení podléhající oznamovací povinnosti podle GDPR. To bylo podle dostupných informací způsobeno bezpečnostními zranitelnostmi v platební aplikaci, které útočníci zneužili a získali tak více než 400 000 záznamů o platbách zákazníků. V důsledku toho uložil regulátor pro ochranu osobních údajů letecké společnosti pokutu ve výši 20 milionů liber.

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
