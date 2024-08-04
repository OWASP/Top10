
source: "https://owasp.org/Top10/A00_2021_Introduction/"
title:  "A00_2021_Einführung"
id:     "Einführung"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".index" -%}
{%- set parent_2017 = extra.osib.document ~ ".2017" -%}
# Einführung

## Willkommen bei den OWASP Top 10 – 2021

![OWASP Top 10 Logo](./assets/TOP_10_logo_Final_Logo_Colour.png){:class="img-responsive"}

Willkommen zur neuesten Ausgabe der OWASP Top 10! Die OWASP Top 10:2021 sind völlig neu, mit einem neuen Grafikdesign mit Piktogrammen je Risiko und Mobilgeräte-freundlichen Webseiten. <!---- einer verfügbaren einseitigen Infografik, die Sie ausdrucken oder auf unserer Homepage herunterladen können. --->

Ein großes Dankeschön an alle, die mit ihrer Zeit und Daten für diese Ausgabe beigetragen haben. Ohne Sie wäre diese Version nicht zustande gekommen. **HERZLICHEN DANK!**

## Was sich in den Top 10 für 2021 geändert hat

Es gibt drei neue Kategorien, vier Kategorien mit Änderungen im Namen teilweise auch im Umfang (im englischen Original, siehe auch [Vorwort der deutschen Version](../0x00-notice/#vorwort-der-deutschen-version)) und eine gewisse Konsolidierung in den Top 10 für 2021. Wir haben bei Bedarf Namen geändert, um uns auf die jeweilige <b>Grundursache statt auf Symptome</b> zu konzentrieren.

![Zuordnung](assets/mapping.png)

- **[A01:2021-Mangelhafte Zugriffskontrolle](A01_2021-Broken_Access_Control.md)** steigt von der {{ osib_link(link=parent_2017 ~ ".5", text= "fünften Position", doc="", Latest=0) }} in die Kategorie mit dem schwerwiegendsten Sicherheitsrisiko für Webanwendungen auf. Die uns zur Verfügung gestellten Daten zeigen, dass im Durchschnitt 3,81% der getesteten Anwendungen eine oder mehrere Common Weakness Enumerations (CWEs) dieser Kategorie aufweisen. Insgesamt wurden mehr als 318.000 CWEs in dieser Risikokategorie genannt. Die 34 CWE-Typen, die wir der 'mangelhaften Zugriffskontrolle' zuordneten, traten in Anwendungen häufiger auf, als die jeder anderen Kategorie.
- **[A02:2021-Fehlerhafter Einsatz von Kryptographie](A02_2021-Cryptographic_Failures.md)** steigt mit neuem Namen um eine Position auf Nummer 2 auf. Bisher hieß diese Kategorie <!--- A3:2017-Sensitive Data Exposure-->**{{ osib_link(link=parent_2017 ~ ".3", doc="", Latest=0) }}**, was eher ein (allgemeines) Symptom, als die Grundursache war. Der neue Name fokussiert auf Fehler im Zusammenhang mit der Kryptographie, wie dies bereits implizit der Fall war. Diese Kategorie führt häufig zur Offenlegung vertraulicher Daten oder zur Kompromittierung des Systems.
- **[A03:2021-Injection](A03_2021-Injection.md)** {{ osib_link(link=parent_2017 ~ ".1", text="steigt von der ersten", doc= "", Latest=0) }} auf die dritte Position ab. 94% der Anwendungen wurden auf eine Art von 'Injection' getestet, mit einer maximalen Inzidenzrate von 19% und einer durchschnittlichen Rate von 3,37%. Die 33 CWE-Typen dieser Kategorie weisen mit einem Vorkommen von insgesamt 274.000 Nennungen die zweithäufigsten Vorfälle bei Webanwendungen auf. 'Cross-Site Scripting' (XSS) wurde in dieser Ausgabe der Top 10 nun Teil dieser Kategorie.
- **[A04:2021-Unsicheres Anwendungsdesign](A04_2021-Insecure_Design.md)** ist eine neue Kategorie dieser Version, die sich mit Risiken im Zusammenhang mit Designfehlern bei Anwendungen beschäftigt. Um die IT-Sicherheit früher im Software-Entwicklungsprosess zu berücksichtigen, brauchen wir mehr Bedrohungsmodellierung, sichere Entwurfsmuster und -prinzipien sowie Referenzarchitekturen. Ein unsicheres Design kann nicht durch eine perfekte Implementierung behoben werden, da die erforderlichen Sicherheitsmaßnahmen per Definition nie zur Abwehr bestimmter Angriffe berücksichtigt und implementiert wurden.
- **[A05:2021-Sicherheitsrelevante Fehlkonfiguration](A05_2021-Security_Misconfiguration.md)** wechselt von {{ osib_link(link=parent_2017 ~ ".6", text="Position 6 in der vorherigen Ausgabe", doc="", Latest=0) }} einen Platz nach oben. 90% der Anwendungen wurden auf irgendeine Art von Fehlkonfiguration getestet, mit einer durchschnittlichen Inzidenzrate von 4,5% und über 208.000 CWEs, die dieser Risikokategorie zugeordnet wurden. Angesichts der zunehmenden Verlagerung <!--- hin ---> zu hoch konfigurierbarer Software, ist es nicht verwunderlich, dass diese Kategorie aufsteigt. Die frühere Kategorie für <!--- **A4:2017-XML External Entities (XXE)** -->**{{ osib_link(link=parent_2017 ~ ".4", doc="", Latest=0) }}** ist jetzt auch Teil dieses Riikos.
- **[A06:2021-Verwundbare oder veraltete Komponenten](A06_2021-Vulnerable_and_Outdated_Components.md)** trug zuvor den Titel "{{ osib_link(link=parent_2017 ~ ".9", doc="", Latest=0) }}" <!--- Using Components with Known Vulnerabilities ---> und ist Nr. 2 in der Top-10-Community-Umfrage, verfügte jedoch über genügend Nennungen in den gespendeten Daten, um es bereits darüber in die Top 10 zu schaffen. Diese Kategorie steigt von {{ osib_link(link=parent_2017 ~ ".9", text="Position 9 im Jahr 2017", doc="", Latest=0) }} auf das 6. Risiko auf. Es handelt sich hierbei um ein bekanntes Problem, dessen Risiko wir nur schwer testen und bewerten können. Es ist die einzige Kategorie, bei der die zugeorteten CWEs von keiner 'Common Vulnerability and Exposure' (CVE) referenziert wird, sodass in ihren Bewertungen ein mittlerer Standard-Score von 5,0 für Exploit und in der Auswirkung berücksichtigt werden.
- **[A07:2021-Fehlerhafte Authentifizierung](A07_2021-Identification_and_Authentication_Failures.md)** fällt von der {{ osib_link(link=parent_2017 ~ ".2", text="zweiten Position", doc="", Latest=0) }} auf Platz 7 zurück. Das Risiko enthält jetzt CWEs, die eher mit Identifikationsfehlern zusammenhängen. Diese Kategorie ist immer noch ein fester Bestandteil der Top 10, aber die zunehmende Verfügbarkeit standardisierter Frameworks scheint hilfreich zu sein.
- **[A08:2021-Fehlerhafte Prüfung der Software- und Datenintegrität](A08_2021-Software_and_Data_Integrity_Failures.md)** ist eine weitere, neue Kategorie in 2021, die sich mit uneingeschränktem Vertrauen im Zusammenhang mit Software-Updates, kritischen Daten und CI/CD-Pipelines ohne Überprüfung der Integrität befasst. Die 10 CWE-Typen dieser Kategorie werden von 'Common Vulnerability and Exposures' (CVEs) mit den höchsten 'Common Vulnerability Scoring System' (CVSS)-Scores referenziert. **{{ osib_link(link=parent_2017 ~ ".8", doc="", Latest=0) }}**<!---**A8:2017-Insecure Deserialization**--> ist jetzt ein Teil dieser umfangreicher gewordenen Kategorie.
- **[A09:2021-Unzureichendes Logging und Sicherheitsmonitoring](A09_2021-Security_Logging_and_Monitoring_Failures.md)** hieß früher **{{ osib_link(link=parent_2017 ~ ".10", doc="", Latest=0) }}**<!--- **A10:2017-Insufficient Logging & Monitoring** -->, wurde auf Basis der Top-10-Community-Umfrage (Nr. 3) hinzugefügt und rückt von Platz 10 um eine Postiton auf. Diese Kategorie wurde um weitere Risikoarten erweitert, ist schwierig zu testen und wird in den CVE/CVSS-Daten nicht gut repräsentiert. Fehler in dieser Kategorie können sich jedoch direkt auf die Sichtbarkeit, Vorfallwarnung und Forensik aller Schwachstellen der Anwendung auswirken.
- **[A10:2021-Server-Side Request Forgery](A10_2021-Server-Side_Request_Forgery_(SSRF).md)** wurde aus der Top-10-Community-Umfrage (Nr. 1) hinzugefügt. Die Daten zeigen eine relativ niedrige Inzidenzrate bei einer überdurchschnittlichen Testabdeckung sowie überdurchschnittlichen Bewertungen für Exploit- und Impact-Potenzial. Diese Kategorie stellt ein Szenario dar, dass die Experten der OWASP-Community als wichtig erachten, auch wenn dies derzeit noch nicht durch Daten belegbar ist.

## Methodik

Diese Ausgabe der Top 10 ist datengestützer denn je, aber nicht mit blinden Vertrauen. Wir haben acht der zehn Kategorien aus den gespendeten Daten und zwei Kategorien aus der Experten-Umfrage in der OWASP-Community mit den höchsten Bewertungen ausgewählt. Wir tun dies aus einer grundsätzlichen, methodischen Überlegung: Der Blick auf die erhaltenen Daten ist ein Blick in die Vergangenheit. IT-Sicherheitsforschende nehmen sich Zeit, um neue Schwachstellen und neue Möglichkeiten zu finden, diese zu testen. Es braucht Zeit, diese Tests in Tools und Prozesse zu integrieren. Bis eine Schwachstelle in großem Maßstab zuverlässig getestet wird, sind wahrscheinlich Jahre vergangen. Um diesen Umstand auszugleichen, nutzen wir eine Community-Umfrage, um Expertinnen und Experten für Anwendungssicherheit und Software-Entwicklung an vorderster Front zu befragen, was ihrer Meinung nach wesentliche Schwachstellen sind, die die Auswertung der Datenstatistik möglicherweise noch nicht aufzeigt.

Wir haben einige, wichtige Änderungen vorgenommen, um die Top 10 weiter zu entwickeln.

## Wie die Kategorien aufgebaut sind

Einige Kategorien haben sich gegenüber der vorherigen Ausgabe der OWASP Top Ten von 2017 geändert. Hier finden Sie eine allgemeine Zusammenfassung der Kategorieänderungen.

Frühere Datenerfassungen konzentrierten sich auf eine vorgegebene Teilmenge von etwa 30 CWE-Typen. In einem Freitextfeld wurde nach zusätzlichen Erkenntnissen gefragt. Wir haben gelernt, dass sich Unternehmen in erster Linie auf diese 30 CWE-Typen konzentrieren und nur selten weitere CWEs ergänzten, die sie gefunden hatten. In dieser Ausgabe haben wir das Verfahren geöffnet und nur nach Daten gefragt, ohne Einschränkung auf bestimmte CWE-Typen. Wir fragten nach der Anzahl der getesteten Anwendungen für ein bestimmtes Jahr (ab 2017) und nach der Anzahl der Anwendungen, bei den die CWEs jeweils beim Testen mindestens einmal gefunden wurden. Mit dieser Vorgehensweise können wir erkennen, wie oft die einzelnen CWE-Typen jeweils in den Anwendungen vorkommen. Wir ignorieren dabei für unsere Zwecke bewusst die Häufigkeit von Schwachstellen je Anwendung. Während es in anderen Situationen sinnvoll und notwendig sein kann, würde sie hier nur das tatsächliche Vorkommen in der Anwendungspopulation verschleiern. Ob in einer Anwendung ein CWE-Typ vier Mal vorkommt oder 4.000 Mal, ist für die Risikoberechnung der Top 10 nicht relevant. Durch dieses Vorgehen ist die Datenbasis von etwa 30 CWE-Typen auf fast 400 gestiegen, die wir für diese Ausgabe analysiert haben. Wir planen, in Zukunft weitere zusätzliche Datenanalysen durchzuführen.

Dieser deutliche Anstieg der CWE-Typen erfordert Änderungen in der Strukturierung der Kategorien. Wir haben mehrere Monate damit verbracht, CWE-Typen zu gruppieren und zu kategorisieren, und hätten noch weitere Monate damit fortfahren können. Irgendwann mussten wir zu einem Ergebnis kommen. Es gibt sowohl CWEs, die sich auf *Grundursachen* beziehen, alsauch solche, die sich auf *Symptome* beziehen. Beispiele für *Grundursache*-Typen sind „Kryptografischer Fehler“ und „Fehlkonfiguration“, für *Symptomtypen* können „Sensitive Data Exposure“ (Verlust der Vertraulichkeit sensibler Daten) und „Denial of Service“ (mutwillige Dienstblockade) genannt werden. Wir haben uns entschieden, uns - wann immer möglich - auf die *Grundursache* zu konzentrieren, da dies sinnvoller ist, um Hinweise zur Identifizierung und Behebung zu geben. Sich auf die *Grundursache* statt auf das *Symptom* zu konzentrieren, ist kein neues Konzept. Die Top Ten waren bisher eine Mischung aus *Symptomen* und *Grundursachen*. CWEs sind ebenfalls eine Mischung aus *Symptomen* und *Grundursachen*. Wir gehen einfach bewusster damit um und sprechen es aus.<br>In dieser Version gibt es durchschnittlich 19,6 CWE-Typen pro Top10-Kategorie, wobei das Minimum bei 1 CWE für [**A10:2021-Server-Side Request Forgery**](A10_2021-Server-Side_Request_Forgery_(SSRF).md) und das Maximum bei 40 CWEs in [**A04:2021-Unsicheres Anwendungsdesign**](A04_2021-Insecure_Design.md) liegt. Diese aktualisierte Kategoriestruktur bietet zusätzliche Vorteile bei Schulungen, da sich Unternehmen jeweils auf die CWEs konzentrieren können, die für eine Programmiersprache/ein Framework besonders sinnvoll erscheinen.

## Wie die Daten zur Auswahl und Priorisierung der Kategorien verwendet werden

Im Jahr 2017 haben wir die Top10-Kategorien zunächst nach der Häufigkeit ihres Vorkommens in den Daten klassifiziert, um die *Verbreitung* zu bestimmen. Die weiteren Risikofaktoren *Ausnutzbarkeit*, *Auffindbarkeit* und *technische Auswirkungen* haben wir dann durch Teamdiskussionen basierend auf CVSS-Scores und jahrzehntelanger Erfahrung eingestuft. In 2021 wollten wir neben der, aus den aktuellen Daten abgeleiteten *Verbreitung*, nach Möglichkeit auch zur Einwertung der Faktoren *Ausnutzbarkeit* und *(technische) Auswirkungen* ausschließlich Daten verwenden.

Wir haben OWASP Dependency Check heruntergeladen, die CVSS-Exploit- und Impact-Scores extrahiert und sie nach den verwandten CWE-Typen gruppiert. Es war einiges an Recherche und Aufwand erforderlich, da zwar alle CVEs über CVSSv2-Einwertungen verfügen, bei den jedoch teilweise noch Mängel vorhanden sind, die erst durch CVSSv3 beheben wurden. Ab einem bestimmten Zeitpunkt haben alle CVEs auch ein CVSSv3-Score erhalten. Darüber hinaus wurden die Bewertungsskalen und Formeln zwischen CVSSv2 und CVSSv3 verändert.

In CVSSv2 konnten sowohl die Kategorie *Exploit* als auch *(Technical) Impact* Werte bis zu 10,0 betragen, aber die Formel würde sie auf 60% für *Exploit* und 40% für *Impact* begrenzen. In CVSSv3 ist das theoretische Maximum für *Exploit* auf 6,0 und für *Impact* auf 4,0 begrenzt. Unter Berücksichtigung der Gewichtung in der Formel von CVSSv3 erhöhte sich der Einfluss der *Impact*-Bewertung, im Durchschnitt um fast eineinhalb Punkte, der für *Exploit* sank im Durchschnitt um fast einen halben Punkt.

Im OWASP Dependency Check gibt es 125.000 Datensätze der National Vulnerability Database (NVD) in der CVEs, einer CWE zugeordnet sind, und es gibt 241 CWEs, die mindestens einer CVE zugeordnet sind. 62.000 CWEs haben einen CVSSv3-Score, was in etwa der Hälfte des Datenbestands entspricht.

Für die Top Ten 2021 haben wir die durchschnittlichen *Exploit*- und *Impact*-Werte wie folgt berechnet. Wir haben alle CVEs mit CVSS-Scores nach CWE gruppiert und sowohl die *Exploit*- alsauch die *Impact*-Scores jeweils getrennt für die CVEs mit CVSSv3 und die mit ausschließlich CVSSv2-Einwertungen berechnet. Die Einzelwerte wurden normalisiert und zu einem Gesamt-Mittelwert zusammengefasst, der die Anzahl der jeweiligen CVSS-Bewertungen berücksichtigt. Die Ergebnisse haben wir als (gewichtete) 'durchschnittliche Ausnutzbarkeit' bzw. (gewichtete) 'durchschnittliche Auswirkung' bezeichnet und als Risikofaktoren verwendet.
<!---- Die genaue Berechnungsformel für die Normalisierung ist angefragt --->
<!---- war: Für die Top Ten 2021 haben wir die durchschnittlichen *Exploit*- und *Impact*-Werte wie folgt berechnet. Wir haben alle CVEs mit CVSS-Scores nach CWE gruppiert und sowohl die *Exploit*- als auch die *Impact*-Scores mit dem Prozentsatz der Bevölkerung mit CVSSv3 + der verbleibenden Population mit CVSSv2-Scores gewichtet, um einen Gesamtdurchschnitt zu erhalten. Wir haben diese Durchschnittswerte den CWEs im Datensatz zugeordnet, um sie als *Exploit*- und *(Technical) Impact*-Bewertung für die andere Hälfte der Risikogleichung zu verwenden. ---->

## Warum nicht nur reine statistische Daten?

Die Ergebnisse in den gespendeten Daten beschränken sich in erster Linie auf das, was automatisiert getestet werden kann. Sprechen Sie mit erfahrenen AppSec-Expertinnen und Experten und sie werden Ihnen von Dingen erzählen, die sie gefunden haben, und von Trends, die sie sehen, die jedoch noch nicht in den Daten enthalten sind. Es braucht Zeit, um Testmethoden für bestimmte Schwachstellentypen zu entwickeln, und dann noch mehr Zeit, bis diese Tests automatisiert und für eine große Anzahl von Anwendungen ausgeführt werden. Alles, was wir finden, blickt zurück in die Vergangenheit und könnte Trends aus dem letzten Jahr übersehen, die in den Daten nicht vorhanden sind.

Daher wählen wir aus den Daten nur acht von zehn Kategorien aus, da sie unvollständig sind. Die anderen beiden Kategorien stammen aus der Top-10-Community-Umfrage. Sie ermöglicht den Praktikerinnen und Praktikern an vorderster Front für die, aus ihrer Sicht größten Risiken zu stimmen, die möglicherweise noch nicht in den Daten enthalten sind oder darüber nie abgeleitet werden können.

## Warum Inzidenzrate statt Häufigkeit?

Es gibt drei Hauptdatenquellen. Wir bezeichnen sie als Human-Assisted Tooling (HaT), Tool-Assisted Human (TaH) und Raw Tooling.

Raw Tooling und HaT sind Massen-Suchgeneratoren. Die Tools suchen nach bestimmten Schwachstellen und versuchen unermüdlich, jede Instanz dieser Schwachstelle zu finden. Dabei werden für einige Schwachstellentypen hohe Fundzahlen generiert. Schauen Sie sich Cross-Site Scripting an, bei dem es sich typischerweise um eine von zwei Varianten handelt: Es handelt sich entweder um einen kleineren, isolierten Fehler oder um ein systemisches Problem. Wenn es sich um ein systemisches Problem handelt, kann die Zahl der Befunde bei einer einzigen Anwendung in die Tausende gehen. Diese hohe Häufigkeit übertönt die meisten anderen, in Berichten oder in Daten gefundenen Schwachstellen.

TaH hingegen wird ein breiteres Spektrum an Schwachstellentypen finden, diese jedoch aus Zeitgründen viel seltener. Wenn Menschen eine Anwendung testen und so etwas wie Cross-Site Scripting sehen, finden sie normalerweise drei oder vier Instanzen und brechen die Suche ab. Sie können ein systemisches Problem erkennen und die Schwachstelle mit einer Empfehlung zur anwendungsweiten Behebung versehen. Es ist weder die Notwendigkeit noch die Zeit vorhanden, jedes (einzelne) Vorkommen zu finden.

Angenommen, wir würden diese beiden unterschiedlichen Datensätze zusammenführen und sie nach der Häufigkeit auswerten. Dann würden die Raw Tooling- und HaT-Daten die genaueren (aber umfassenderen) TaH-Daten übertönen.  Wir sehen dies als Grund dafür, dass beispielsweise 'Cross-Site Scripting' in vielen Listen so hoch eingestuft wird, obwohl die Auswirkungen im Allgemeinen gering bis mäßig sind. Das liegt an der schieren Menge an Fundstellen (Cross-Site Scripting lässt sich auch relativ einfach testen, daher gibt es auch viele Tests dafür).

Im Jahr 2017 haben wir stattdessen die Verwendung der Inzidenzrate eingeführt, um einen neuen Blick auf die Daten zu werfen und Raw Tooling- und HaT-Daten angemessen mit TaH-Daten zusammenzuführen. Die Inzidenzrate bewertet, wie viele Prozent der Anwendungen mindestens ein Vorkommen eines Schwachstellentyps aufweist. Es ist uns egal, ob es einmalig oder systemisch war. Das ist für unsere Zwecke irrelevant. Wir müssen lediglich wissen, wie viele Anwendungen mindestens eine Instanz hatten, was dazu beiträgt, einen klareren Überblick über die Testergebnisse über mehrere, unterschiedliche Testtypen hinweg zu erhalten, ohne dass die Daten von Massen-Suchgeneratoren die Ergebnisse dominieren. Dies entspricht auch einer risikoorientierten Sichtweise, da Angreifende nur eine Instanz benötigen, um eine Anwendung über eine Kategorie erfolgreich anzugreifen.

## Wie sieht Ihr Datenerfassungs- und Analyseprozess aus?

Wir haben den OWASP-Top-10-Datenerfassungsprozess auf dem Open Security Summit 2017 formalisiert. OWASP Top 10 Co-Leader und die Community haben zwei Tage damit verbracht, einen transparenten Datenerfassungsprozess zu formalisieren. Die aktuelle Ausgabe 2021 ist die zweite Edition, in der wir diese Methodik verwenden.

Wir haben zunächst einen Aufruf zur Spende von Daten über die, uns zur Verfügung stehenden Social-Media-Kanäle veröffentlicht, sowohl über Projekt- alsauch über OWASP-Kanäle. Auf der OWASP-Projektseite listenten wir die Datenelemente und die Struktur auf, die wir benötigten, und wie die Daten erfasst und eingereicht werden konnten. Im GitHub-Projekt hatten wir Beispieldaten als Vorlage zur Verfügung gestellt. Bei Bedarf haben wir die Organisationen unterstützt, um die Struktur und Zuordnung zu CWEs herauszufinden.

Die Datenspenden stammen von den unterschiedlichsten Organisationen, darunter welche, die Anbieter nach Branchen testen, Bug-Bounty-Anbietern und Organisationen, die interne Testergebnisse beigesteuert haben. Die eingereichten Daten wurden zuerst grundlegend analysiert und hinsichtlich der zugeordneten CWEs auf Plausibilität geüprüft und den Risikokategorien zugeordnet. Es gibt Überschneidungen zwischen einigen CWEs und andere sind sehr eng miteinander verbunden (z.B. kryptografische Schwachstellen). Alle Entscheidungen im Zusammenhang mit der Analyse der übermittelten Rohdaten wurden dokumentiert und veröffentlicht, um offen und transparent zu machen, wie wir die Daten normalisiert haben.

Die acht Kategorien mit den höchsten Inzidenzraten wurden in die Top 10 aufgenommen. Wir schauen uns auch die Ergebnisse der Top 10-Community-Umfrage an, um zu sehen, welche davon möglicherweise bereits in den Daten vorhanden waren. Die beiden Kategorien mit den meisten Stimmen, die nicht in den acht datengestützten Kategorien vorhanden waren, wurden für die beiden verbliebenen Plätze der Top 10 ausgewählt. Für die zehn ausgewählten Kategorien wurden jeweils neber der Inzidenzrate die weiteren Faktoren für Ausnutzbarkeit, *Expolit* und die (technische) Auswirkung, *Impact* berücksichtigt, um die Top 10:2021 in nach ihren Risiken zu ordnen.

## Datenfaktoren

Für die Top-10-Kategorien sind jeweils Datenfaktoren aufgeführt. Sie bedeuten Folgendes:

- Zugeordnete CWEs: Die Anzahl der CWEs, die der Kategorie vom Top-10-Team zugeordnet wurden.
- Häufigkeit: Die Inzidenzrate ist der Prozentsatz der Anwendungen, die für CWEs der Kategorie anfällig sind, bezogen auf die Summe aller Anwendungen, die von einer Organisation im jeweilgen Jahr getestet wurden.
- Durchschn. Ausnutzbarkeit: Der Exploit-Subscore aus CVSSv2- und CVSSv3-Scores von CVEs, die die CWEs der Kategorie referenziert haben, normalisiert auf eine 10-Punkte-Skala.
- Durchschn. Auswirkungen: Der Impact-Subscore aus CVSSv2- und CVSSv3-Scores von CVEs, die die CWEs der Kategorie referenziert haben, normalisiert auf eine 10-Punkte-Skala
- (Test-)Abdeckung: Der Prozentsatz der Anwendungen, die von allen Organisationen, die auf die CWEs der Kategorie getestet wurden.
- Gesamtanzahl: Gesamtzahl der Anwendungen, bei denen CWEs der Kategorie zugeordnet wurden.
- CVEs insgesamt: Gesamtzahl der CVEs in der NVD-Datenbank, die den CWEs der Kategorie zugeordnet wurden.

## Vielen Dank an unsere Daten-Spender

Die folgenden Organisationen (und weitere anonyme Spender) haben freundlicherweise Daten für über 500.000 Anwendungen gespendet, um dies zum größten und umfassendsten Datensatz zur Anwendungssicherheit zu machen. Ohne ihn wären diese Top 10 nicht möglich gewesen.

- AppSec Labs
- Cobalt.io
- Contrast Security
- GitLab
- HackerOne
- HCL Technologies
- Micro Focus
- PenTest-Tools
- Probely
- Sqreen
- Veracode
- WhiteHat (NTT)

## Vielen Dank an unsere weiteren Sponsoren

Das OWASP Top 10 2021-Team dankt Secure Code Warrior und Just Eat für die finanzielle Unterstützung.

[![Secure Code Warrior](assets/securecodewarrior.png){ width="256" }](https://securecodewarrior.com)

[![Just Eats](assets/JustEat.png){ width="256" }](https://www.just-eat.co.uk/)
