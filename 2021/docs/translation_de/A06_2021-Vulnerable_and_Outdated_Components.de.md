---
source: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/“
title: "A06:2021 – Anfällige und veraltete Komponenten“
id: "A06:2021“
lang:	"de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".6" -%}
#A06:2021 – Anfällige und veraltete Komponenten ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id , name="Vulnerable and Outdated Components", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.9") }}


## Faktoren {{ osib_anchor(osib=osib~".factors", id=id~"-factors", name=title~":Factors", aussehen=appearance, source=source~"#" ~id, parent= osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Es belegte Platz 2 in der Top-10-Community-Umfrage, verfügte aber auch über genügend Daten, um es datentechnisch in die Top 10 zu schaffen. Vulnerable Komponenten sind ein bekanntes Problem, das wir nur schwer testen und bewerten können. Sie stellen die einzige Kategorie dar, in der den enthaltenen CWEs keine Common Vulnerability and Exposures (CVEs) zugeordnet sind. Daher wird eine standardmäßige Exploit-/Auswirkungsgewichtung von 5,0 verwendet. Bemerkenswerte CWEs sind *CWE-1104: Verwendung nicht gewarteter Drittanbieterkomponenten* und die beiden CWEs aus den Top 10 2013 und 2017.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Die Anwendung besitzt möglicherweise Schwachstellen, wenn folgendes zutrifft:

- Keine Kenntnis über Versionen der in der Anwendung benutzten Komponenten (sowohl client- als auch serverseitig). Dies beinhaltet sowohl direkte als auch indirekte, verschachtelte Abhängigkeiten.

- Die verwendete Software besitzt Schwachstellen, wird nicht mehr unterstützt oder ist veraltet. Dies beinhaltet das Betriebssystem, den Web-/Applikationsserver, das Datenbankmanagementsystem (DBMS), Anwendungen, APIs und alle verwendeten Komponenten, Laufzeitumgebungen sowie Bibliotheken.

- Schwachstellenscans werden nicht regelmäßig durchgeführt und die sicherheitsrelevante Bulletins der benutzten Komponenten sind nicht abonniert.

- Die zugrundeliegende Plattform, das Framework und die Abhängigkeiten werden nicht risikobasiert und rechtzeitig repariert oder aktualisiert. Dies passiert in der Regel in Umgebungen in denen Patchen eine monatliche oder quartalsweise Tätigkeit und einer Änderungskontrolle unterliegt. Dies setzt die Organisation unnötigerweise über Tage oder Monate dem Risiko von Schwachstellen aus, für die schon Patches existieren.

- Softwareentwickler keine Kompatibilitäts-Tests der aktualisierten oder gepatchten Bibliotheken durchführen.

- Die Komponenten nicht sicher konfiguriert sind (siehe [A05:2021-Sicherheitsrelevante Fehlkonfiguration](A05_2021-Security_Misconfiguration.de.md)).

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Es sollte ein Patch-Management-Prozess vorhanden sein:

- Entfernen Sie ungenutzte Abhängigkeiten, unnötige Funktionen, Komponenten, Dateien und Dokumentation.

- Kontinuierliche Bestandsaufnahme der Versionen sowohl der clientseitigen als auch der serverseitigen Komponenten (z. B. Frameworks, Bibliotheken) und ihrer Abhängigkeiten mithilfe von Tools wie "versions", "OWASP Dependency Check", "retire.js" usw. Überwachen Sie kontinuierlich Quellen wie Common Vulnerability and Exposures (CVE)) und die National Vulnerability Database (NVD) für Schwachstellen in den Komponenten. Verwenden Sie Software-Tools zur Analyse der Softwarebestandteile, um den Prozess zu automatisieren. Abonnieren Sie E-Mail-Benachrichtigungen zu Sicherheitslücken im Zusammenhang mit den von Ihnen verwendeten Komponenten.

- Beziehen Sie Komponenten nur von offiziellen Quellen über sichere Links. Bevorzugen Sie signierte Pakete, um die Wahrscheinlichkeit zu verringern, dass eine modifizierte, bösartige Komponente enthalten ist (siehe [A08:2021-Fehlerhafte Prüfung der Software- und Datenintegrität](A08_2021-Software_and_Data_Integrity_Failures.de.md))

- Überwachen Sie Bibliotheken und Komponenten, die nicht gewartet werden oder keine Sicherheitspatches für ältere Versionen erstellen. Wenn das Patchen nicht möglich ist, erwägen Sie die Bereitstellung eines virtuellen Patches zur Überwachung, Erkennung oder zum Schutz vor dem entdeckten Problem.

Jede Organisation muss einen fortlaufenden Plan für die Überwachung, Triage und Anwendung von Updates oder Konfigurationsänderungen während der gesamten Lebensdauer der Anwendung oder des Portfolios sicherstellen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Komponenten werden normalerweise mit denselben Berechtigungen wie die Anwendung selbst ausgeführt, sodass Fehler in einer Komponente schwerwiegende Auswirkungen haben können. Solche Fehler können zufällig (z. B. ein Programmierfehler) oder absichtlich (z. B. eine Backdoor in einer Komponente) sein. Einige Beispiele für entdeckte ausnutzbare Komponentenschwachstellen sind:

– CVE-2017-5638, eine Remote Code Execution Schwachstelle in Struts 2, die den Angreifer ermächtigt beliebigen Code auf dem Server auszuführen, wurde für einige erhebliche Sicherheitsvorfälle verantwortlich gemacht.

- Obwohl das Patchen von Geräten des Internet of Things (IoT) oft nur sehr schwierig oder unmöglich ist, kann dies sehr wichtig sein (z.B. biomedizinische Geräte).

Es existieren automatisierte Tools, die Angreifern helfen, nicht gepatchte oder falsch konfigurierte Systeme zu finden. Die Shodan IoT-Suchmaschine kann Ihnen beispielsweise dabei helfen, Geräte zu finden, die immer noch für die im April 2014 gepatchte Heartbleed-Sicherheitslücke verwundbar sind.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}
- {{ osib_link(link="osib.owasp.asvs.4-0." ~ "1", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V1 Architektur, Design und Bedrohungsmodellierung]( /www-project-application-security-verification-standard) ->
- {{ osib_link(link="osib.owasp.dependency check", osib=osib) }} <!--- [OWASP-Abhängigkeitsprüfung (für Java- und .NET-Bibliotheken)](/www-project-dependency-check) --->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.1.10", osib=osib) }} <!--- [OWASP-Testhandbuch – Kartenanwendungsarchitektur (OTG-INFO-010)](/ www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture) --->
- {{ osib_link(link="osib.owasp.community.0.other.virtual Patching Best Practices", osib=osib) }} <!--- [OWASP Virtual Patching Best Practices](/www-community/Virtual_Patching_Best_Practices) --->
- {{ osib_link(link="osib.contrast.insecure Bibliotheken.2014", doc="osib.contrast", osib=osib) }} <!--- [Die unglückliche Realität unsicherer Bibliotheken](https:// cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf) --->
- {{ osib_link(link="osib.cvedetails.search", osib=osib) }} <!--- [MITRE Common Vulnerabilities and Exposures (CVE)-Suche](https://www.cvedetails.com/version- search.php) --->
- {{ osib_link(link="osib.nist.nvd", osib=osib) }} <!--- [National Vulnerability Database (NVD)](https://nvd.nist.gov/) --->
- {{ osib_link(link="osib.retirejs", osib=osib) }} <!--- [Retire.js zur Erkennung bekanntermaßen anfälliger JavaScript-Bibliotheken](https://github.com/retirejs/retire.js/ ) --->
- {{ osib_link(link="osib.github.advisories", osib=osib) }} <!--- [GitHub Advisory Database](https://github.com/advisories) --->
- {{ osib_link(link="osib.rubysec", osib=osib) }} <!--- [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/) --->
- {{ osib_link(link="osib.safecode.publications.Software Integrity Controls.0.pdf", doc="osib.safecode", osib=osib) }} <!--- [SAFECode Software Integrity Controls \[PDF \]](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf) --->


## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.937", doc="", osib=osib) }} <!-- [CWE-937: OWASP Top 10 2013: Verwendung von Komponenten mit bekannten Schwachstellen](https ://cwe.mitre.org/data/definitions/937.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.1035", doc="", osib=osib) }} <!-- [CWE-1035: 2017 Top 10 A9: Verwendung von Komponenten mit bekannten Schwachstellen](https ://cwe.mitre.org/data/definitions/1035.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.1104", doc="", osib=osib) }} <!-- [CWE-1104: Verwendung nicht gewarteter Drittanbieterkomponenten](https://cwe .mitre.org/data/definitions/1104.html) ->
