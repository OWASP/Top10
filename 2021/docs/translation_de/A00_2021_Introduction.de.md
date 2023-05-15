# Einführung

## Willkommen bei den OWASP Top 10 – 2021

![OWASP Top 10 Logo](./assets/TOP_10_logo_Final_Logo_Color.png){:class="img-responsive"}

Willkommen zur neuesten Ausgabe der OWASP Top 10! Die OWASP Top 10 2021 sind völlig neu, mit einem neuen Grafikdesign und einer einseitigen Infografik, die Sie ausdrucken oder auf unserer Homepage herunterladen können.

Ein großes Dankeschön an alle, die ihre Zeit und Daten für diese Iteration beigetragen haben. Ohne Sie wäre diese Folge nicht zustande gekommen. **DANKE SCHÖN!**

## Was sich in den Top 10 für 2021 geändert hat

Es gibt drei neue Kategorien, vier Kategorien mit Namens- und Umfangsänderungen und eine gewisse Konsolidierung in den Top 10 für 2021. Wir haben bei Bedarf Namen geändert, um uns auf die Grundursache statt auf das Symptom zu konzentrieren.

![Zuordnung](assets/mapping.png)

- **A01:2021-Broken Access Control** steigt vom fünften Platz in die Kategorie mit dem schwerwiegendsten Sicherheitsrisiko für Webanwendungen auf; Die beigesteuerten Daten zeigen, dass im Durchschnitt 3,81 % der getesteten Anwendungen eine oder mehrere Common Weakness Enumerations (CWEs) aufwiesen, wobei mehr als 318.000 CWEs in dieser Risikokategorie vorkamen. Die 34 der Broken Access Control zugeordneten CWEs traten in Anwendungen häufiger auf als jede andere Kategorie.
- **A02:2021-Cryptographic Failures** rückt um eine Position nach oben auf Platz 2, früher bekannt als **A3:2017-Sensible Data Exposure**, was eher ein allgemeines Symptom als eine Grundursache war. Der erneuerte Name konzentriert sich auf Fehler im Zusammenhang mit der Kryptographie, wie dies bereits implizit der Fall war. Diese Kategorie führt häufig zur Offenlegung vertraulicher Daten oder zur Kompromittierung des Systems.
- **A03:2021-Injection** gleitet nach unten in die dritte Position. 94 % der Anträge wurden auf irgendeine Form der Injektion getestet, mit einer maximalen Inzidenzrate von 19 %, einer durchschnittlichen Inzidenzrate von 3,37 %, und die 33 dieser Kategorie zugeordneten CWEs weisen mit 274.000 Vorkommen die zweithäufigsten Vorfälle bei Anträgen auf. Cross-Site Scripting ist in dieser Ausgabe nun Teil dieser Kategorie.
- **A04:2021-Unsicheres Design** ist eine neue Kategorie für 2021, die sich auf Risiken im Zusammenhang mit Designfehlern konzentriert. Wenn wir uns als Branche wirklich nach links bewegen wollen, brauchen wir mehr Bedrohungsmodellierung, sichere Entwurfsmuster und -prinzipien sowie Referenzarchitekturen. Ein unsicheres Design kann nicht durch eine perfekte Implementierung behoben werden, da die erforderlichen Sicherheitskontrollen per Definition nie zur Abwehr bestimmter Angriffe geschaffen wurden.
- **A05:2021-Security Misconfiguration** rückt von Platz 6 in der vorherigen Ausgabe nach oben; 90 % der Anwendungen wurden auf irgendeine Form von Fehlkonfiguration getestet, mit einer durchschnittlichen Inzidenzrate von 4,5 %, und über 208.000 Vorkommen von CWEs wurden dieser Risikokategorie zugeordnet. Angesichts der zunehmenden Verlagerung hin zu hoch konfigurierbarer Software ist es nicht verwunderlich, dass diese Kategorie aufsteigt. Die frühere Kategorie für **A4:2017-XML External Entities (XXE)** ist jetzt Teil dieser Risikokategorie.
- **A06:2021-Vulnerable and Outdated Components** trug zuvor den Titel Using Components with Known Vulnerabilities und ist die Nummer 2 in der Top-10-Community-Umfrage, verfügte aber auch über genügend Daten, um es durch Datenanalyse in die Top 10 zu schaffen. Diese Kategorie steigt von Platz 9 im Jahr 2017 an und ist ein bekanntes Problem, dessen Risiko wir nur schwer testen und bewerten können. Es handelt sich um die einzige Kategorie, in der den enthaltenen CWEs keine Common Vulnerability and Exposures (CVEs) zugeordnet sind, sodass in ihren Bewertungen ein Standard-Exploit und eine Auswirkungsgewichtung von 5,0 berücksichtigt werden.
- **A07:2021-Identifizierungs- und Authentifizierungsfehler** hieß früher „Broken Authentication“ und rutscht von der zweiten Position ab und umfasst jetzt CWEs, die eher mit Identifizierungsfehlern zusammenhängen. Diese Kategorie ist immer noch ein fester Bestandteil der Top 10, aber die zunehmende Verfügbarkeit standardisierter Frameworks scheint hilfreich zu sein.
- **A08:2021-Software- und Datenintegritätsfehler** ist eine neue Kategorie für 2021, die sich auf Annahmen im Zusammenhang mit Software-Updates, kritischen Daten und CI/CD-Pipelines ohne Überprüfung der Integrität konzentriert. Eine der am höchsten gewichteten Auswirkungen aus den Daten des Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS), die den 10 CWEs in dieser Kategorie zugeordnet sind. **A8:2017-Unsichere Deserialisierung** ist jetzt Teil dieser größeren Kategorie.
- **A09:2021-Sicherheitsprotokollierungs- und Überwachungsfehler** war zuvor **A10:2017-Unzureichende Protokollierung und Überwachung** und wurde aus der Top-10-Community-Umfrage (Platz 3) hinzugefügt und rückt von Platz 10 auf. Diese Kategorie wurde um weitere Arten von Fehlern erweitert, ist schwierig zu testen und wird in den CVE/CVSS-Daten nicht gut repräsentiert. Fehler in dieser Kategorie können sich jedoch direkt auf die Sichtbarkeit, Vorfallwarnung und Forensik auswirken.
– **A10:2021-Server-Side Request Forgery** wurde aus der Top-10-Community-Umfrage (#1) hinzugefügt. Die Daten zeigen eine relativ niedrige Inzidenzrate mit einer überdurchschnittlichen Testabdeckung sowie überdurchschnittlichen Bewertungen für Exploit- und Impact-Potenzial. Diese Kategorie stellt das Szenario dar, in dem uns die Mitglieder der Sicherheitsgemeinschaft mitteilen, dass dies wichtig ist, auch wenn dies derzeit nicht in den Daten dargestellt ist.

## Methodik

Diese Ausgabe der Top 10 ist datengesteuerter denn je, aber nicht blind datengesteuert. Wir haben acht der zehn Kategorien aus den bereitgestellten Daten und zwei Kategorien aus der Top-10-Community-Umfrage auf hohem Niveau ausgewählt. Wir tun dies aus einem grundlegenden Grund: Der Blick auf die beigesteuerten Daten ist ein Blick in die Vergangenheit. AppSec-Forscher nehmen sich Zeit, um neue Schwachstellen und neue Möglichkeiten zu finden, diese zu testen. Es braucht Zeit, diese Tests in Tools und Prozesse zu integrieren. Bis wir eine Schwachstelle in großem Maßstab zuverlässig testen können, sind wahrscheinlich Jahre vergangen. Um diese Ansicht auszugleichen, nutzen wir eine Community-Umfrage, um Anwendungssicherheits- und Entwicklungsexperten an vorderster Front zu befragen, was ihrer Meinung nach wesentliche Schwachstellen sind, die die Daten möglicherweise noch nicht aufzeigen.

Wir haben einige wichtige Änderungen vorgenommen, um die Top 10 weiter auszubauen.

## Wie die Kategorien aufgebaut sind

Einige Kategorien haben sich gegenüber der vorherigen Ausgabe der OWASP Top Ten geändert. Hier finden Sie eine allgemeine Zusammenfassung der Kategorieänderungen.

Frühere Datenerfassungsbemühungen konzentrierten sich auf eine vorgeschriebene Teilmenge von etwa 30 CWEs mit einem Feld, in dem nach zusätzlichen Erkenntnissen gefragt wurde. Wir haben gelernt, dass sich Unternehmen in erster Linie auf die 30 CWEs konzentrieren und nur selten weitere CWEs hinzufügen, die sie sehen. In dieser Iteration haben wir es geöffnet und nur nach Daten gefragt, ohne Einschränkung für CWEs. Wir fragten nach der Anzahl der getesteten Anwendungen für ein bestimmtes Jahr (ab 2017) und nach der Anzahl der Anwendungen, bei denen beim Testen mindestens eine Instanz eines CWE gefunden wurde. Mit diesem Format können wir verfolgen, wie weit die einzelnen CWEs in der Anwendungspopulation verbreitet sind. Wir ignorieren die Frequenz für unsere Zwecke; Während es in anderen Situationen notwendig sein kann, verschleiert es nur die tatsächliche Prävalenz in der Anwendungspopulation. Ob eine Anwendung vier Instanzen eines CWE oder 4.000 Instanzen hat, ist nicht Teil der Berechnung für die Top 10. Wir sind von etwa 30 CWEs auf fast 400 CWEs gestiegen, um sie im Datensatz zu analysieren. Wir planen, in Zukunft ergänzend zusätzliche Datenanalysen durchzuführen. Dieser deutliche Anstieg der Zahl der CWEs erfordert Änderungen in der Strukturierung der Kategorien.

Wir haben mehrere Monate damit verbracht, CWEs zu gruppieren und zu kategorisieren, und hätten noch weitere Monate damit fortfahren können. Irgendwann mussten wir anhalten. Es gibt sowohl *Grundursache*- als auch *Symptomtypen von CWEs, wobei *Grundursache*-Typen wie „Kryptografischer Fehler“ und „Fehlkonfiguration“ im Gegensatz zu *Symptomtypen* wie „Sensitive Data Exposure“ und „Denial of Service“ stehen. Wir haben uns entschieden, uns wann immer möglich auf die *Grundursache* zu konzentrieren, da dies sinnvoller ist, um Hinweise zur Identifizierung und Behebung zu geben. Sich auf die *Grundursache* statt auf das *Symptom* zu konzentrieren, ist kein neues Konzept; Die Top Ten waren eine Mischung aus *Symptom* und *Grundursache*. CWEs sind auch eine Mischung aus *Symptom* und *Grundursache*; Wir gehen einfach bewusster damit um und fordern es heraus. In dieser Folge gibt es durchschnittlich 19,6 CWEs pro Kategorie, wobei die Untergrenzen bei 1 CWE für **A10:2021-Server-Side Request Forgery (SSRF)** bis 40 CWEs in **A04:2021-Insecure Design* liegen. *. Diese aktualisierte Kategoriestruktur bietet zusätzliche Schulungsvorteile, da sich Unternehmen auf CWEs konzentrieren können, die für eine Sprache/ein Framework sinnvoll sind.

## Wie die Daten zur Auswahl von Kategorien verwendet werden

Im Jahr 2017 haben wir Kategorien nach Inzidenzrate ausgewählt, um die Wahrscheinlichkeit zu bestimmen, und sie dann durch Teamdiskussion basierend auf jahrzehntelanger Erfahrung nach *Ausnutzbarkeit*, *Erkennbarkeit* (auch *Wahrscheinlichkeit*) und *Technische Auswirkungen* eingestuft. Für 2021 möchten wir nach Möglichkeit Daten zur *Ausnutzbarkeit* und *(technischen) Auswirkungen* verwenden.

Wir haben OWASP Dependency Check heruntergeladen und die CVSS-Exploit- und Impact-Scores extrahiert, gruppiert nach verwandten CWEs. Da alle CVEs über CVSSv2-Ergebnisse verfügen, war einiges an Recherche und Mühe erforderlich, aber es gibt Mängel in CVSSv2, die CVSSv3 beheben sollte. Ab einem bestimmten Zeitpunkt wird allen CVEs auch ein CVSSv3-Score zugewiesen. Darüber hinaus wurden die Bewertungsbereiche und Formeln zwischen CVSSv2 und CVSSv3 aktualisiert.

In CVSSv2 könnten sowohl *Exploit* als auch *(Technical) Impact* bis zu 10,0 betragen, aber die Formel würde sie auf 60 % für *Exploit* und 40 % für *Impact* senken. In CVSSv3 war das theoretische Maximum auf 6,0 für *Exploit* und 4,0 für *Impact* begrenzt. Unter Berücksichtigung der Gewichtung verschob sich die Impact-Bewertung nach oben, im Durchschnitt fast eineinhalb Punkte in CVSSv3, und die Ausnutzbarkeit sank im Durchschnitt um fast einen halben Punkt.

Es gibt 125.000 Datensätze einer CVE, die einer CWE in den aus der OWASP-Abhängigkeitsprüfung extrahierten Daten der National Vulnerability Database (NVD) zugeordnet sind, und es gibt 241 eindeutige CWEs, die einer CVE zugeordnet sind. 62.000 CWE-Karten haben einen CVSSv3-Score, der etwa der Hälfte der Bevölkerung im Datensatz entspricht.

Für die Top Ten 2021 haben wir die durchschnittlichen *Exploit*- und *Impact*-Werte wie folgt berechnet. Wir haben alle CVEs mit CVSS-Scores nach CWE gruppiert und sowohl die *Exploit*- als auch die *Impact*-Scores mit dem Prozentsatz der Bevölkerung mit CVSSv3 + der verbleibenden Population mit CVSSv2-Scores gewichtet, um einen Gesamtdurchschnitt zu erhalten. Wir haben diese Durchschnittswerte den CWEs im Datensatz zugeordnet, um sie als *Exploit*- und *(Technical) Impact*-Bewertung für die andere Hälfte der Risikogleichung zu verwenden.

## Warum nicht nur reine statistische Daten?

Die Ergebnisse in den Daten beschränken sich in erster Linie auf das, was wir automatisiert testen können. Sprechen Sie mit einem erfahrenen AppSec-Experten und er wird Ihnen von Dingen erzählen, die er gefunden hat, und von Trends, die er sieht, die noch nicht in den Daten enthalten sind. Es braucht Zeit, um Testmethoden für bestimmte Schwachstellentypen zu entwickeln, und dann noch mehr Zeit, bis diese Tests automatisiert und für eine große Anzahl von Anwendungen ausgeführt werden. Alles, was wir finden, blickt zurück in die Vergangenheit und könnte Trends aus dem letzten Jahr übersehen, die in den Daten nicht vorhanden sind.

Daher wählen wir aus den Daten nur acht von zehn Kategorien aus, da diese unvollständig sind. Die anderen beiden Kategorien stammen aus der Top-10-Community-Umfrage. Es ermöglicht den Praktikern an vorderster Front, für die aus ihrer Sicht größten Risiken zu stimmen, die möglicherweise nicht in den Daten enthalten sind (und möglicherweise nie in Daten zum Ausdruck kommen).

## Warum Inzidenzrate statt Häufigkeit?

Es gibt drei Hauptdatenquellen. Wir identifizieren sie als Human-Assisted Tooling (HaT), Tool-Assisted Human (TaH) und Raw Tooling.

Tooling und HaT sind Hochfrequenz-Suchgeneratoren. Die Tools suchen nach bestimmten Schwachstellen und versuchen unermüdlich, jede Instanz dieser Schwachstelle zu finden. Dabei werden für einige Schwachstellentypen hohe Fundzahlen generiert. Schauen Sie sich Cross-Site Scripting an, bei dem es sich typischerweise um eine von zwei Varianten handelt: Es handelt sich entweder um einen kleineren, isolierten Fehler oder um ein systemisches Problem. Wenn es sich um ein systemisches Problem handelt, kann die Zahl der Befunde bei einer einzelnen Anwendung in die Tausende gehen. Diese hohe Häufigkeit übertönt die meisten anderen in Berichten oder Daten gefundenen Schwachstellen.

TaH hingegen wird ein breiteres Spektrum an Schwachstellentypen finden, jedoch aus Zeitgründen viel seltener. Wenn Menschen eine Anwendung testen und so etwas wie Cross-Site Scripting sehen, finden sie normalerweise drei oder vier Instanzen und stoppen. Sie können einen systemischen Befund ermitteln und diesen mit einer Empfehlung zur anwendungsweiten Behebung verfassen. Es besteht keine Notwendigkeit (oder Zeit), jede Instanz zu finden.

Angenommen, wir nehmen diese beiden unterschiedlichen Datensätze und versuchen, sie nach Häufigkeit zusammenzuführen. In diesem Fall werden die Tooling- und HaT-Daten die genaueren (aber umfassenderen) TaH-Daten übertönen und sind ein guter Grund dafür, dass so etwas wie Cross-Site Scripting in vielen Listen so hoch eingestuft wird, obwohl die Auswirkungen im Allgemeinen gering bis mäßig sind. Das liegt an der schieren Menge an Erkenntnissen. (Cross-Site Scripting lässt sich auch relativ einfach testen, daher gibt es auch viele weitere Tests dafür.)

Im Jahr 2017 haben wir stattdessen die Verwendung der Inzidenzrate eingeführt, um einen neuen Blick auf die Daten zu werfen und Tooling- und HaT-Daten sauber mit TaH-Daten zusammenzuführen. Die Inzidenzrate fragt, wie viel Prozent der Anwendungspopulation mindestens eine Instanz eines Schwachstellentyps aufwies. Es ist uns egal, ob es einmalig oder systemisch war. Das ist für unsere Zwecke irrelevant; Wir müssen lediglich wissen, wie viele Anwendungen mindestens eine Instanz hatten, was dazu beiträgt, einen klareren Überblick über die Testergebnisse über mehrere Testtypen hinweg zu erhalten, ohne dass die Daten in hochfrequenten Ergebnissen übergehen. Dies entspricht einer risikobezogenen Sichtweise, da ein Angreifer nur eine Instanz benötigt, um eine Anwendung über die Kategorie erfolgreich anzugreifen.

## Wie sieht Ihr Datenerfassungs- und Analyseprozess aus?

Wir haben den OWASP-Top-10-Datenerfassungsprozess auf dem Open Security Summit 2017 formalisiert. OWASP-Top-10-Führungskräfte und die Community haben zwei Tage damit verbracht, einen transparenten Datenerfassungsprozess zu formalisieren. Die Ausgabe 2021 ist das zweite Mal, dass wir diese Methodik verwenden.

Wir veröffentlichen einen Aufruf zur Einreichung von Daten über die uns zur Verfügung stehenden Social-Media-Kanäle, sowohl im Projekt als auch im OWASP. Auf der OWASP-Projektseite listen wir die Datenelemente und die Struktur auf, nach denen wir suchen, und wie wir sie einreichen. Im GitHub-Projekt haben wir Beispieldateien, die als Vorlagen dienen. Wir arbeiten bei Bedarf mit Organisationen zusammen, um die Struktur und Zuordnung zu CWEs herauszufinden.

Wir erhalten Daten von Organisationen, die Anbieter nach Branchen testen, Bug-Bounty-Anbietern und Organisationen, die interne Testdaten beisteuern. Sobald wir die Daten haben, laden wir sie zusammen und führen eine grundlegende Analyse dessen durch, was CWEs den Risikokategorien zuordnen. Es gibt Überschneidungen zwischen einigen CWEs und andere sind sehr eng miteinander verbunden (z. B. kryptografische Schwachstellen). Alle Entscheidungen im Zusammenhang mit den übermittelten Rohdaten werden dokumentiert und veröffentlicht, um offen und transparent zu machen, wie wir die Daten normalisiert haben.

Wir betrachten die acht Kategorien mit den höchsten Inzidenzraten für die Aufnahme in die Top 10. Wir schauen uns auch die Ergebnisse der Top 10-Community-Umfrage an, um zu sehen, welche davon möglicherweise bereits in den Daten vorhanden sind. Die beiden besten Stimmen, die noch nicht in den Daten vorhanden sind, werden für die anderen beiden Plätze in den Top 10 ausgewählt. Nachdem alle zehn ausgewählt wurden, haben wir verallgemeinerte Faktoren für Ausnutzbarkeit und Wirkung angewendet; um dabei zu helfen, die Top 10 2021 in einer risikobasierten Reihenfolge zu platzieren.

## Datenfaktoren

Für jede der Top-10-Kategorien sind Datenfaktoren aufgeführt. Sie bedeuten Folgendes:

- Zugeordnete CWEs: Die Anzahl der CWEs, die vom Top-10-Team einer Kategorie zugeordnet wurden.
- Inzidenzrate: Die Inzidenzrate ist der Prozentsatz der Anwendungen, die für diesen CWE anfällig sind, aus der Bevölkerung, die von dieser Organisation in diesem Jahr getestet wurde.
- Gewichteter Exploit: Der Exploit-Subscore aus CVSSv2- und CVSSv3-Scores, zugewiesen an CVEs, zugeordnet zu CWEs, normalisiert und auf einer 10-Punkte-Skala platziert.
- Gewichteter Impact: Der Impact-Subscore aus den CVSSv2- und CVSSv3-Scores, die CVEs zugeordnet sind, CWEs zugeordnet, normalisiert und auf einer 10-Punkte-Skala platziert werden.
- (Test-)Abdeckung: Der Prozentsatz der Anwendungen, die von allen Organisationen für ein bestimmtes CWE getestet wurden.
- Gesamtzahl der Vorkommen: Gesamtzahl der Anwendungen, bei denen die CWEs einer Kategorie zugeordnet wurden.
- CVEs insgesamt: Gesamtzahl der CVEs in der NVD-Datenbank, die den einer Kategorie zugeordneten CWEs zugeordnet wurden.


## Vielen Dank an unsere Datenlieferanten

Die folgenden Organisationen (zusammen mit einigen anonymen Spendern) haben freundlicherweise Daten für über 500.000 Anwendungen gespendet, um dies zum größten und umfassendsten Datensatz zur Anwendungssicherheit zu machen. Ohne Sie wäre dies nicht möglich.

- AppSec Labs
- Cobalt.io
- Kontrastsicherheit
- GitLab
- HackerOne
- HCL-Technologien
- Mikrofokus
- PenTest-Tools
- Leerzeichen
- Quadratisch
- Veracode
- WhiteHat (NTT)

## Vielen Dank an unseren Sponsor

Das OWASP Top 10 2021-Team dankt Secure Code Warrior und Just Eat für die finanzielle Unterstützung.

[![Secure Code Warrior](assets/securecodewarrior.png){ width="256" }](https://securecodewarrior.com)

[![Just Eats](assets/JustEat.png){ width="256" }](https://www.just-eat.co.uk/)
