![OWASP Logo](../assets/TOP_10_logo_Final_Logo_Colour.png)

# Die zehn kritischsten Sicherheitsrisiken für Webanwendungen

# Einführung

Willkommen zur 8. Ausgabe der OWASP Top 10!

Ein großes Dankeschön an alle, die Daten und Einschätzungen in der Umfrage beigetragen haben. Ohne diese Beiträge wäre diese Ausgabe nicht möglich gewesen. **HERZLICHEN DANK!**


## Die OWASP Top 10:2025 im Überblick



* [A01:2025 - Mangelhafte Zugriffskontrolle](A01_2025-Broken_Access_Control.md)
* [A02:2025 - Sicherheitsrelevante Fehlkonfiguration](A02_2025-Security_Misconfiguration.md)
* [A03:2025 - Schwachstellen in der Software-Lieferkette](A03_2025-Software_Supply_Chain_Failures.md)
* [A04:2025 - Fehlerhafter Einsatz von Kryptographie](A04_2025-Cryptographic_Failures.md)
* [A05:2025 - Injection](A05_2025-Injection.md)
* [A06:2025 - Unsicheres Anwendungsdesign](A06_2025-Insecure_Design.md)
* [A07:2025 - Fehlerhafte Authentifizierung](A07_2025-Authentication_Failures.md)
* [A08:2025 - Fehlerhafte Prüfung der Software- und Datenintegrität](A08_2025-Software_or_Data_Integrity_Failures.md)
* [A09:2025 - Unzureichendes Security-Logging und Alerting](A09_2025-Security_Logging_and_Alerting_Failures.md)
* [A10:2025 - Fehlerhafte Behandlung von Ausnahmezuständen](A10_2025-Mishandling_of_Exceptional_Conditions.md)


## Was sich in den Top 10 für 2025 geändert hat

Es gibt zwei neue Kategorien und eine Konsolidierung in den Top 10 für 2025. Wir haben uns bemüht, den Fokus so weit wie möglich auf die Grundursachen statt auf die Symptome zu legen. Angesichts der Komplexität von Software-Engineering und Software-Sicherheit ist es nahezu unmöglich, zehn Kategorien ohne ein gewisses Maß an Überschneidungen zu erstellen.

![Mapping](../assets/2025-mappings.png)

* **[A01:2025 - Mangelhafte Zugriffskontrolle](A01_2025-Broken_Access_Control.md)** behält seine Position als schwerwiegendstes Sicherheitsrisiko für Webanwendungen. Die Daten zeigen, dass im Durchschnitt 3,73 % der getesteten Anwendungen mindestens eine der 40 CWEs dieser Kategorie aufweisen. Wie durch die gestrichelte Linie in der obigen Abbildung angezeigt, wurde Server-Side Request Forgery (SSRF) in diese Kategorie integriert.
* **[A02:2025 - Sicherheitsrelevante Fehlkonfiguration](A02_2025-Security_Misconfiguration.md)** steigt von Platz 5 in 2021 auf Platz 2 in 2025. Fehlkonfigurationen sind in den Daten dieser Ausgabe häufiger vertreten. 3,00 % der getesteten Anwendungen wiesen mindestens eine der 16 CWEs dieser Kategorie auf. Dies ist nicht überraschend, da Software-Engineering zunehmend mehr Anwendungsverhalten über Konfigurationen steuert.
* **[A03:2025 - Schwachstellen in der Software-Lieferkette](A03_2025-Software_Supply_Chain_Failures.md)** ist eine Erweiterung von [A06:2021-Unsichere oder veraltete Komponenten](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) auf einen breiteren Umfang von Kompromittierungen innerhalb oder über das gesamte Ökosystem von Software-Abhängigkeiten, Build-Systemen und Verteilungsinfrastruktur. Diese Kategorie wurde in der Community-Umfrage mit Abstand als größtes Anliegen eingestuft. Sie umfasst 5 CWEs und ist in den gesammelten Daten wenig vertreten, was wir auf Herausforderungen beim Testen zurückführen. Sie weist die wenigsten Vorkommen in den Daten auf, aber auch die höchsten durchschnittlichen Exploit- und Impact-Scores aus CVEs.
* **[A04:2025 - Fehlerhafter Einsatz von Kryptographie](A04_2025-Cryptographic_Failures.md)** fällt um zwei Plätze von Platz 2 auf Platz 4. Die Daten zeigen, dass im Durchschnitt 3,80 % der Anwendungen mindestens eine der 32 CWEs dieser Kategorie aufweisen. Diese Kategorie führt häufig zur Offenlegung sensibler Daten oder zur Kompromittierung des Systems.
* **[A05:2025 - Injection](A05_2025-Injection.md)** fällt um zwei Plätze von Platz 3 auf Platz 5. Injection ist eine der am häufigsten getesteten Kategorien mit der größten Anzahl von CVEs, die den 38 CWEs dieser Kategorie zugeordnet sind. Sie umfasst ein breites Spektrum – von Cross-Site Scripting (hohe Häufigkeit/geringe Auswirkung) bis hin zu SQL Injection (geringe Häufigkeit/hohe Auswirkung).
* **[A06:2025 - Unsicheres Anwendungsdesign](A06_2025-Insecure_Design.md)** fällt um zwei Plätze von Platz 4 auf Platz 6, da Sicherheitsrelevante Fehlkonfiguration und Schwachstellen in der Software-Lieferkette vorbeigezogen sind. Diese Kategorie wurde 2021 eingeführt, und wir sehen spürbare Verbesserungen in der Branche bei der Bedrohungsmodellierung und einem stärkeren Fokus auf sicheres Design.
* **[A07:2025 - Fehlerhafte Authentifizierung](A07_2025-Authentication_Failures.md)** behält seine Position auf Platz 7 mit einer leichten Namensänderung (zuvor „[Fehlerhafte Identifikation und Authentifizierung](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)”), um die 36 CWEs dieser Kategorie besser widerzuspiegeln. Die Kategorie bleibt wichtig, aber die zunehmende Nutzung standardisierter Frameworks für die Authentifizierung wirkt sich positiv auf die Häufigkeit von Authentifizierungsfehlern aus.
* **[A08:2025 - Fehlerhafte Prüfung der Software- und Datenintegrität](A08_2025-Software_or_Data_Integrity_Failures.md)** bleibt auf Platz 8. Diese Kategorie konzentriert sich auf das Versagen, Vertrauensgrenzen einzuhalten und die Integrität von Software, Code und Daten auf einer niedrigeren Ebene als die Schwachstellen in der Software-Lieferkette zu überprüfen.
* **[A09:2025 - Unzureichendes Security-Logging und Alerting](A09_2025-Security_Logging_and_Alerting_Failures.md)** behält seine Position auf Platz 9. Leichte Namensänderung (zuvor „[Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)”), um die Bedeutung der Alarmierungsfunktion für geeignete Reaktionen auf relevante Log-Ereignisse hervorzuheben. Hervorragendes Logging ohne Alerting hat nur minimalen Wert bei der Erkennung von Sicherheitsvorfällen. Diese Kategorie ist in den Daten stets unterrepräsentiert und wurde erneut durch die Community-Umfrage in die Liste gewählt.
* **[A10:2025 - Fehlerhafte Behandlung von Ausnahmezuständen](A10_2025-Mishandling_of_Exceptional_Conditions.md)** ist eine neue Kategorie für 2025. Diese Kategorie enthält 24 CWEs mit Fokus auf fehlerhafte Fehlerbehandlung, logische Fehler, „Failing Open” sowie andere verwandte Szenarien, die aus abnormalen Zuständen resultieren, mit denen Systeme konfrontiert werden können.


## Methodik

Diese Ausgabe der Top 10 bleibt datengestützt, aber nicht blind datengetrieben. Wir haben 12 Kategorien anhand der eingereichten Daten eingestuft und zwei weitere durch die Ergebnisse der Community-Umfrage aufgenommen. Wir tun dies aus einem wesentlichem Grund: Die Analyse der eingereichten Daten ist im Wesentlichen ein Blick in die Vergangenheit. Sicherheitsforscher:innen im Bereich Anwendungssicherheit widmen ihre Zeit der Identifizierung neuer Schwachstellen und der Entwicklung neuer Testmethoden. Es dauert Wochen bis Jahre, bis diese Tests in Werkzeuge und Prozesse integriert sind. Bis eine Schwachstelle zuverlässig in großem Maßstab getestet werden kann, können Jahre vergangen sein. Es gibt auch wichtige Risiken, die wir möglicherweise nie zuverlässig testen können und die daher in den Daten fehlen. Um diesen Blickwinkel auszugleichen, nutzen wir eine Community-Umfrage, um Praktiker:innen aus der Anwendungssicherheit und Softwareentwicklung an vorderster Front zu befragen, was sie als wesentliche Risiken betrachten, die in den Testdaten unterrepräsentiert sein könnten.


## Aufbau der Kategorien

Einige Kategorien haben sich gegenüber der vorherigen Ausgabe der OWASP Top 10 geändert. Im Folgenden finden Sie eine übergeordnete Zusammenfassung der Kategorieänderungen.

In dieser Ausgabe haben wir Daten ohne Einschränkung auf bestimmte CWEs angefragt, wie wir es bereits für die Ausgabe 2021 getan haben. Wir fragten nach der Anzahl der getesteten Anwendungen für ein bestimmtes Jahr (ab 2021) und nach der Anzahl der Anwendungen, bei denen mindestens ein CWE im Test gefunden wurde. Dieses Format ermöglicht es uns, zu erfassen, wie häufig die einzelnen CWEs in der Gesamtzahl der Anwendungen vorkommen. Wir ignorieren die Häufigkeit für unsere Zwecke; obwohl sie in anderen Situationen notwendig sein kann, verdeckt sie nur die tatsächliche Verbreitung in der Anwendungspopulation. Ob eine Anwendung vier oder 4.000 Vorkommen eines CWEs aufweist, ist für die Berechnung der Top 10 nicht relevant. Insbesondere da manuelle Tester:innen eine Schwachstelle in der Regel nur einmal vermerken, unabhängig davon, wie oft sie in einer Anwendung vorkommt, während automatisierte Test-Frameworks jedes Vorkommen als einzigartig aufführen. Wir sind von etwa 30 CWEs im Jahr 2017 auf fast 400 CWEs im Jahr 2021 und auf 589 CWEs in dieser Ausgabe gestiegen. Wir planen, in Zukunft zusätzliche Datenanalysen als Ergänzung durchzuführen. Dieser deutliche Anstieg der CWE-Anzahl erfordert Änderungen in der Strukturierung der Kategorien.

Wir haben mehrere Monate damit verbracht, CWEs zu gruppieren und zu kategorisieren, und hätten noch weitere Monate damit fortfahren können. Irgendwann mussten wir aufhören. Es gibt sowohl CWEs für Grundursachen als auch für Symptome – Grundursachen-Typen sind beispielsweise „Fehlerhafter Einsatz von Kryptographie" und „Fehlkonfiguration", während Symptomtypen wie „Offenlegung sensibler Daten" und „Denial of Service" zu nennen sind. Wir haben beschlossen, uns wann immer möglich auf die Grundursache zu konzentrieren, da dies sinnvoller für die Identifizierung und Behebung ist. Sich auf die Grundursache statt auf das Symptom zu konzentrieren ist kein neues Konzept; die Top 10 war schon immer eine Mischung aus Symptomen und Grundursachen. CWEs sind ebenfalls eine solche Mischung – wir gehen nun bewusster damit um. In dieser Ausgabe gibt es durchschnittlich 25 CWEs pro Kategorie, mit einem Minimum von 5 CWEs für A03:2025 und A09:2025 bis hin zu 40 CWEs in A01:2025. Wir haben beschlossen, die Anzahl der CWEs pro Kategorie auf 40 zu begrenzen. Diese aktualisierte Kategoriestruktur bietet zusätzliche Vorteile für Schulungen, da Unternehmen sich auf CWEs konzentrieren können, die für eine bestimmte Programmiersprache oder ein Framework relevant sind.

Wir wurden gefragt, warum wir nicht zu einer Liste von 10 CWEs als Top 10 wechseln, ähnlich den MITRE Top 25 Most Dangerous Software Weaknesses. Es gibt zwei Hauptgründe für die Verwendung mehrerer CWEs in Kategorien. Erstens existieren nicht alle CWEs in allen Programmiersprachen oder Frameworks, was Probleme für Werkzeuge und Schulungsprogramme verursacht. Zweitens gibt es mehrere CWEs für häufige Schwachstellen – etwa für Injection, Command Injection, Cross-Site Scripting, hartcodierte Passwörter, fehlende Validierung, Pufferüberläufe und viele weitere. Je nach Organisation oder Tester:innen werden unterschiedliche CWEs verwendet. Durch die Verwendung einer Kategorie mit mehreren CWEs können wir das Bewusstsein für die verschiedenen Schwachstellentypen unter einem gemeinsamen Kategorienamen schärfen. In dieser Ausgabe der Top 10 2025 gibt es 248 CWEs in den 10 Kategorien. Zum Zeitpunkt dieser Veröffentlichung enthält die [herunterladbare Auflistung von MITRE](https://cwe.mitre.org) insgesamt 968 CWEs.


## Verwendung der Daten zur Kategorienauswahl

Wie bereits für die Ausgabe 2021 haben wir CVE-Daten für *Ausnutzbarkeit* und *(technische) Auswirkung* herangezogen. In der National Vulnerability Database (NVD) gibt es ca. 175.000 Datensätze (gegenüber 125.000 in 2021) mit CVEs. Zudem gibt es 643 eindeutige CWEs, die CVEs zugeordnet sind (gegenüber 241 in 2021). Für die Top Ten 2025 haben wir die durchschnittlichen Ausnutzbarkeits- und Auswirkungs-Scores wie folgt berechnet: Alle CVEs mit CVSS-Scores wurden nach CWE gruppiert, und sowohl Exploit- als auch Impact-Scores wurden gewichtet. Für Details siehe [Was sind Sicherheitsrisiken für Anwendungen?](0x02_2025-What_are_Application_Security_Risks.md)

## Warum wir eine Community-Umfrage nutzen

Die Ergebnisse in den Daten beschränken sich weitgehend auf das, was die Branche automatisiert testen kann. Erfahrene AppSec-Fachleute berichten von Dingen, die sie finden, und Trends, die sie sehen, die noch nicht in den Daten erfasst sind. Es braucht Zeit, Testmethoden für bestimmte Schwachstellentypen zu entwickeln, und dann noch mehr Zeit, bis diese Tests automatisiert und für eine große Anzahl von Anwendungen ausgeführt werden. Alles, was wir finden, blickt in die Vergangenheit und könnte Trends aus dem letzten Jahr übersehen, die noch nicht in den Daten vorhanden sind.

Daher wählen wir nur acht der zehn Kategorien aus den Daten, da diese unvollständig sind. Die anderen zwei Kategorien stammen aus der Top-10-Community-Umfrage. Sie ermöglicht den Praktiker:innen an vorderster Front, für die aus ihrer Sicht größten Risiken zu stimmen, die möglicherweise nicht in den Daten enthalten sind (und dies möglicherweise nie sein werden).


## Vielen Dank an unsere Datenspender

Die folgenden Organisationen (sowie mehrere anonyme Spender) haben freundlicherweise Daten für über 2,8 Millionen Anwendungen gespendet und damit den größten und umfassendsten Datensatz zur Anwendungssicherheit ermöglicht. Ohne diese Beiträge wäre dies nicht möglich gewesen.

* Accenture (Prague)
* Anonymous (multiple)
* Bugcrowd
* Contrast Security
* CryptoNet Labs
* Intuitor SoftTech Services
* Orca Security
* Probely
* Semgrep
* Sonar
* usd AG
* Veracode
* Wallarm

## Hauptautor:innen
* Andrew van der Stock - X: [@vanderaj](https://x.com/vanderaj)
* Brian Glas - X: [@infosecdad](https://x.com/infosecdad)
* Neil Smithline - X: [@appsecneil](https://x.com/appsecneil)
* Tanya Janca - X: [@shehackspurple](https://x.com/shehackspurple)
* Torsten Gigler - Mastodon: [@torsten_gigler@infosec.exchange](https://infosec.exchange/@torsten_gigler)

## Deutsche Übersetzung
* Tobias Heide - [LinkedIn](https://www.linkedin.com/in/tobias-heide/)
* Rico Komenda - [LinkedIn](https://www.linkedin.com/in/ricokomenda)
* Martina Kraus - [LinkedIn](https://www.linkedin.com/in/martina-kraus-398493108/)
* Lilith Pendzich - [LinkedIn](https://www.linkedin.com/in/lilithp)

## Fehler melden und Pull Requests stellen

Korrekturen und Probleme bitte hier melden:

### Projektlinks:
* [Homepage](https://owasp.org/www-project-top-ten/)
* [GitHub repository](https://github.com/OWASP/Top10)


