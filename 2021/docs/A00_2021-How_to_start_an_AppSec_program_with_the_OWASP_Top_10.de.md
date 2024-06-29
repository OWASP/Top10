# Wie man ein Programm für Anwendungssicherheit mit den OWASP Top 10 aufbaut 

Die OWASP Top 10 war nie als Grundlage für ein Programm zur Anwendungssicherheit (AppSec) gedacht. 
Für viele Organisationen, die sich gerade am Anfang ihrer Reise in die Anwendungssicherheit befinden, ist es jedoch wichtig, irgendwo anzufangen.
Die OWASP Top 10 2021 bilden einen guten Ausgangspunkt für Checklisten usw., sind aber an sich nicht ausreichend.

## Schritt 1. Identifizieren Sie die Lücken und Ziele Ihres AppSec-Programms

Viele Anwendungssicherheitsprogramme (AppSec) übernehmen sich häufig und versuchen in zu großen Schritten ihr Ziel zu erreichen. Diese Bemühungen sind zum Scheitern verurteilt. Wir empfehlen CISOs und AppSec-Führungskräften dringend, das [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) einzusetzen, um Schwachstellen und Verbesserungspotenziale über einen Zeitraum von 1-3 Jahren zu identifizieren. Der erste Schritt besteht darin, den aktuellen Stand der Dinge zu bewerten: *Jene* Schwächen in den Bereichen Governance, Design, Implementierung, Verifizierung und Betrieb zu identifizieren, die sofort behoben werden müssen, und jene, die noch warten können, und die Implementierung oder Verbesserung der 15 OWASP SAMM-Sicherheitspraktiken zu priorisieren. OWASP SAMM kann beim Aufbau und Messen von Verbesserungen bei Ihren Software Assurance-Bemühungen hilfreich sein.

## Schritt 2. Ebnen Sie den Weg für einen sicheren Entwicklungs-Lebenszyklus (SDLC)

Das Konzept des geebneten Weges, das traditionell den sogenannten "Einhörnern" vorbehalten war, ist der einfachste Weg, um die größte Wirkung zu erzielen und die AppSec-Ressourcen mit der Geschwindigkeit des Entwicklungsteams zu skalieren, die von Jahr zu Jahr zunimmt.

Das Konzept des geebneten Weges lautet: "Der einfachste Weg ist auch der sicherste Weg" und sollte eine Kultur tiefer Partnerschaften zwischen dem Entwicklungsteam und dem Sicherheitsteam beinhalten, vorzugsweise so, dass sie ein und dasselbe Team sind. Der geebnete Weg hat zum Ziel, unsichere Alternativen kontinuierlich zu verbessern, zu messen, zu erkennen und zu ersetzen, indem eine unternehmensweite Bibliothek von sicheren Ersatzlösungen zur Verfügung gestellt wird, mit Werkzeugen, die dabei helfen zu erkennen, wo Verbesserungen durch die Übernahme des geebneten Weges möglich sind. Auf diese Weise können vorhandene Entwicklungstools unsichere Builds aufzeigen und den Entwicklungsteams helfen, sich selbst von unsicheren Alternativen zu lösen.

Der geebnete Weg mag anstrengend erscheinen, aber er sollte im Laufe der Zeit schrittweise aufgebaut werden. Es gibt noch andere Formen von Appsec-Programmen, insbesondere den Agile Secure Development Lifecycle von Microsoft. Nicht jede Appsec-Programm-Methodik passt zu jedem Unternehmen.

## Stufe 3. Realisierung des geebneten Wegs mit Ihren Entwicklungsteams

Der geebnete Weg wird mit dem Einverständnis und der direkten Beteiligung der zuständigen Entwicklungs- und Betriebsteams umgesetzt. Der Weg sollte strategisch auf das Unternehmen abgestimmt sein und dazu beitragen, sichere Anwendungen schneller bereitzustellen. Die Entwicklung des Weges sollte eine ganzheitliche Maßnahme sein, die das gesamte Unternehmens- oder Anwendungsökosystem abdeckt, und nicht nur ein einzelnes anwendungsbezogenes Notpflaster wie in vergangenen Zeiten.

## Stufe 4. Migrieren Sie alle zukünftigen und bestehenden Anwendungen auf den geebneten Weg

Fügen Sie Tools zur Erkennung von geebneten Wegen hinzu, während Sie sie entwickeln, und stellen Sie den Entwicklungsteams Informationen zur Verfügung, damit sie die Sicherheit ihrer Anwendungen verbessern können, indem sie Elemente des geebneten Weges direkt übernehmen können. Sobald ein Aspekt des geebneten Weges übernommen wurde, sollten Unternehmen Prüfungen zur kontinuierlichen Integration implementieren, die bestehenden und Check-Ins von neuem Code auf verbotene Alternativen untersuchen und beim Build oder Check-In Warnungen ausgeben oder diese ablehnen. Auf diese Weise wird verhindert, dass sich im Laufe der Zeit unsichere Optionen in den Code einschleichen, wodurch technische Altlasten und eine fehlerhafte, unsichere Anwendung vermieden werden. Solche Warnhinweise sollten auf die sichere Alternative verweisen, damit das Entwicklungsteam sofort die richtige Antwort erhält. So kann das Entwicklungsteam sofort die Korrektur vornehmen und die Komponente für den geebneten Weg rasch übernehmen.

## Schritt 5. Nachprüfen, ob der geebnete Weg die in den OWASP Top 10 genannten Probleme behoben hat

Die Komponenten des geebneten Weges sollten sich mit einem wichtigen Aspekt der OWASP Top 10 befassen, z. B. mit der automatischen Erkennung oder Beseitigung von Sicherheitslücken in Komponenten, mit einem IDE-Plugin für die statische Codeanalyse zur Erkennung von Injections oder - noch besser - mit der Verwendung einer Bibliothek, die als sicher gegen Injections bekannt ist. Je mehr dieser sicheren Drop-in-Ersatzlösungen den Teams zur Verfügung gestellt werden, desto besser. Eine wichtige Aufgabe des Appsec-Teams ist es, dafür zu sorgen, dass die Sicherheit dieser Komponenten kontinuierlich bewertet und verbessert wird. Sobald die Sicherheit verbessert wurde, sollte eine Kommunikation mit den Nutzern der Komponente stattfinden, die darauf aufmerksam macht, dass ein Upgrade durchgeführt werden sollte, vorzugsweise automatisch, aber wenn nicht, sollte dies zumindest auf einem Dashboard oder ähnlichem deutlich gemacht werden.


## Stufe 6. Bauen Sie Ihr Programm zu einem ausgereiften AppSec-Programm aus

Sie dürfen nicht bei den OWASP Top 10 aufhören. Diese decken nur 10 Risikokategorien ab. Wir empfehlen Unternehmen dringend, den Application Security Verification Standard zu übernehmen und schrittweise Komponenten und Tests für die Stufen 1, 2 und 3 hinzuzufügen, je nach Risikoniveau der entwickelten Anwendungen.


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

- **Kontinuierliche Verbesserung**. 
Ausgereifte AppSec-Programme versuchen, sich ständig zu verbessern. Wenn etwas nicht funktioniert, dann beenden Sie es. Wenn etwas klobig ist oder nicht skaliert , muss es verbessert werden. Falls etwas von den Entwicklungsteams nicht verwendet wird und keine oder nur geringe Auswirkungen hat, sollte etwas anderes gemacht werden. Nur weil wir seit den 1970er Jahren Tests wie Schreibtischchecks durchgeführt haben, heißt das nicht, dass es eine gute Idee ist. Messen und bewerten Sie, und entwickeln oder verbessern Sie dann.
