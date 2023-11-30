# Wie baue ich mit den Top 10 ein Programm zur Anwendungssicherheit auf?

Die OWASP Top 10 waren ursprünglich nie konzipiert als Grundlage für ein Programm zur Anwendungssicherheit (AppSec). 
Für viele Organisationen, die gerade erst mit Anwendungssicherheit beginnen, ist ein definierter Startpunkt jedoch elementar.
Die OWASP Top 10 2021 stellen eine gute Baseline für Checklisten dar; sie alleine sind jedoch nicht hinreichend.

## Schritt 1. Identifizieren Sie Gaps und Ziele ihres Programms zur Anwendungssicherheit

Viele Programme zur Anwendungssicherheit übernehmen sich häufig
und versuchen in zu großen Schritten ihr Ziel zu erreichen.
Solche Ansätze sind bereits zum Scheitern verurteilt.
CISOs und Verantwortlichen der Anwendungssicherheit empfehlen wir,
das [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) einzusetzen,
um Schwächen und Verbesserungspotentiale über einen Zeitraum von 1-3 Jahren zu identifizieren.
Der erste Schritt bedeutet, die Ist-Situation zu bewerten,
*jene* Gaps in Bezug auf Governance, Entwurf, Implementierung, Qualitätssicherung und Betrieb zu identifizieren,
die *umgehend* geschlossen werden müssen,
und die Prioritäten in der Umsetzung oder Verbesserung der 15 OWASP SAMM Sicherheitsmaßnahmen zu setzen.
OWASP SAMM kann dabei helfen, 
die Sicherheitslage ihrer Anwendungen zu messen und diese zu verbessern.

## Schritt 2. Ebnen Sie den Weg für einen Sicheren Entwicklungs-Lebenszyklus (SDLC)

Lange den "Einhörnern" vorbehalten, stellt das Konzept eines "Geebneten Weges" die einfachste Möglichkeit dar,
einen größtmöglichen Effekt zu erzielen
und ihre Ressourcen für Anwendungssicherheit mit der jährlich steigenden Entwicklungsgeschwindigkeit zu skalieren.

Das Konzept des Geebneten Weges ist,
dass der einfachste Weg gleichzeitig der sicherste Weg sein muss.
Es verlangt eine Kultur der Partnerschaft zwischen Entwicklungs- und Security-Teams —
idealerweise ist es ein und dasselbe Team.
Der Geebnete Weg zielt darauf ab,
kontinuierlich zu verbessern, zu messen sowie unsichere Optionen zu erkennen und zu ersetzen.
Auf dem Geebneten Weg soll eine unternehmensweite Bibliothek mit einsatzbereiten sicheren Alternativen angeboten werden
— sowie Werkzeuge, um Verbesserungspotentiale zu identifizieren.

Der Geebnete Weg kann umfangreich scheinen,
aber er sollte inkrementell über einen Zeitraum aufgebaut werden.
Es gibt weitere Formen eines AppSec-Programms,
insbesondere den Microsoft Agile Secure Development Lifecycle.
Nicht jede Methodik für ein AppSec-Programm passt zu jedem Unternehmen.

## Schritt 3. Setzen Sie den Geebneten Weg gemeinsam mit Ihren Entwicklungs-Teams um

Der Geebnete Weg wird einvernehmlich und mit direkter Beteiligung
der relevanten Entwicklungs- und Betriebsteams aufgebaut.
Der Geebnete Weg sollte an den strategischen Zielen des Unternehmens ausgerichtet werden
und soll dazu beitragen, schneller sicherere Anwendungen zu liefern.
Den Geebneten Weg zu entwickeln sollte ein ganzheitliche Aufgabe sein,
die das gesamte Unternehmen bzw. die gesamte Anwendungslandschaft umfasst
— nicht als "Pro-Anwendung-Pflaster" wie früher.

## Schritt 4. Migrieren Sie alle zukünftigen und bestehenden Anwendungen zum Geebneten Weg

Fügen Sie ihrem Entwicklungsprozess Werkzeuge hinzu,
die Abweichungen vom Geebneten Weg erkennen,
und informieren Sie Entwicklungsteams,
wie diese die Sicherheit ihrer Anwendungen durch Elemente des Geebneten Weges verbessern können.
Sobald eine Komponente des Geebneten Weges umgesetzt wird,
sollten Organisationen Continuous Integration einsetzen,
um bestehenden und neu eingecheckten Code auf unerlaubte Alternativen zu untersuchen
und Warnungen auszugeben oder den Build oder Check-in zurückzuweisen.
Damit wird verhindert,
dass sich unsichere Optionen über die Zeit im Code einschleichen,
was sonst zu technischen Schulden und einer unsicheren Anwendung führt.
Solche Warnungen sollten auf eine sichere Alternative verweisen,
damit das Entwicklungsteam direkt die korrekte Lösung erhält.
Das Team kann dann schnell ein Refactoring durchführen
und die Komponente des Geebneten Weges umsetzen.

## Schritt 5. Stellen Sie sicher, dass der Geebnete Weg die OWASP Top 10 mitigiert

Jedes Element des Geebneten Weges sollte ein signifikantes Problem aus den OWASP Top 10 adressieren,
z.B. automatisch Komponenten mit bekannten Schwachstellen erkennen oder beheben,
ein IDE-Plugin für Statische Code-Analyse anbieten, um Injections zu erkennen,
oder noch besser eine Bibliothek anbieten, die bewiesenermaßen sicher gegen Injections ist.
Je mehr einsatzbereite Alternativen den Teams bereitgestellt werden desto besser.
Eine essentielle Aufgabe des AppSec-Teams ist,
dass die Sicherheit dieser Komponenten kontinuierlich evaluiert und verbessert wird.
Sobald diese verbessert werden sollten Konsumenten über einen Kommunikationsweg auf ein Update hingewiesen werden,
das bevorzugt automatisch erfolgen, mindestens aber auf einem Dashboard hervorgehoben werden sollte.


## Schritt 6. Bauen Sie ihr Programm zu einem ausgereiften AppSec-Programm aus

Sie dürfen nicht bei den OWASP Top 10 aufhören.
Sie decken nur 10 Risikokategorien ab.
Wir legen allen Organsiation deutlich nahe,
den Application Security Verification Standard zu übernehmen
und zunehmend Komponenten des Geebneten Weges und Tests für Level 1, 2 und 3 hinzu zu nehmen,
abhängig vom Risikoniveau der Anwendung.


## Weitere Schritte

Alle guten Programme zur Anwendungssicherheit gehen über das Minimum hinaus.
Alle Beteiligten müssen weiterarbeiten, um die Schwachstellen in den Anwendungen jemals in den Griff zu bekommen.

-   **Konzeptuelle Integrität**. Ausgereifte AppSec-Programme müssen über ein Konzept sicherer Architektur verfügen,
egal ob eine formale Cloud- oder Enterprise-Architektur oder Bedrohungsanalyse.

-   **Automatisierung und Skalierung**.
    Ausgereifte AppSec-Programme versuchen möglichst viele Liefergegenstände zu automatisieren:
Skripte um komplexe Penetrationstest-Schritte zu emulieren,
Statische Codeanalyse direkt den Entwicklungsteams bereitstellen,
Unterstützung für Entwicklungsteams um sicherheitsspezifische Unit- und Integrationstests zu verfassen, etc.

-   **Kultur**.
    Ausgereifte AppSec-Programme versuchen, unsicheres Design auszuschließen
und technische Schulden in Bestands-Code dadurch zu eliminieren,
dass sie Bestandteil der Entwicklung sind und nicht daneben stehen.
AppSec-Teams, die Entwicklungsteams als "die" und "wir" betrachten, sind zum Scheitern verurteilt.

-   **Kontinuierliche Verbesserung**.
    Ausgereifte AppSec-Programme versuchen, sich permanent zu verbessern.
Falls etwas nicht funktioniert, darf es nicht weiterverfolgt werden.
Falls etwas klobig ist oder nicht skaliert, muss es verbessert werden.
Falls etwas nicht von den Entwicklungsteams eingesetzt wird oder nur begrenzten Einfluss hat, sollte etwas Anderes getan werden.
Nur weil wir seit den 1970ern Tests wie die Schreibtischkontrolle durchgeführt haben,
heißt das nicht, dass es eine gute Idee ist.
Messen und evaluieren Sie und bauen Sie dann auf oder verbessern Sie.
