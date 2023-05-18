# So starten Sie ein AppSec-Programm mit den OWASP Top 10

Bisher waren die OWASP Top 10 nie als Grundlage für ein AppSec-Programm konzipiert. Allerdings ist es für viele Unternehmen, die gerade erst am Anfang ihrer Reise zur Anwendungssicherheit stehen, unerlässlich, irgendwo anzufangen.
Die OWASP Top 10 2021 sind ein guter Anfang als Grundlage für Checklisten usw., aber sie allein reichen nicht aus.

## Stufe 1. Identifizieren Sie die Lücken und Ziele Ihres Appsec-Programms

Viele Anwendungssicherheitsprogramme (AppSec) übernehmen sich häufig und versuchen in zu großen Schritten ihr Ziel zu erreichen. Diese Bemühungen sind zum Scheitern verurteilt. Wir empfehlen CISOs und AppSec-Führungskräften nachdrücklich, das [OWASP Software Assurance Maturity Model (SAMM)] (https://owaspsamm.org) zu verwenden, um über einen Zeitraum von ein bis drei Jahren Schwachstellen und Bereiche mit Verbesserungspotenzial zu identifizieren. Der erste Schritt besteht darin, zu bewerten, wo Sie sich gerade befinden, die Lücken in Governance, Design, Implementierung, Verifizierung und Betrieb zu identifizieren, die Sie sofort beheben müssen, im Vergleich zu denen, die warten können, und der Implementierung oder Verbesserung der fünfzehn OWASP SAMM-Sicherheitspraktiken Priorität einzuräumen. OWASP SAMM kann Ihnen dabei helfen, Verbesserungen in Ihren Software-Assurance-Bemühungen aufzubauen und zu messen.

## Stufe 2. Erarbeiten Sie eine gepflasterte Strasse für einen sicheren Entwicklungslebenszyklus

Das Konzept der gepflasterten Straße ist traditionell eine Domäne sogenannter Einhörner und stellt die einfachste Möglichkeit dar, die größtmögliche Wirkung zu erzielen und AppSec-Ressourcen mit der Geschwindigkeit des Entwicklungsteams zu skalieren, die jedes Jahr nur zunimmt.

Das Konzept der gepflasterten Straße lautet „Der einfachste Weg ist auch der sicherste Weg“ und sollte eine Kultur intensiver Partnerschaften zwischen dem Entwicklungsteam und dem Sicherheitsteam beinhalten, vorzugsweise so, dass sie ein und dasselbe Team sind. Die asphaltierte Straße zielt darauf ab, unsichere Alternativen kontinuierlich zu verbessern, zu messen, zu erkennen und zu ersetzen, indem sie über eine unternehmensweite Bibliothek von Drop-in-gesicherten Ersatzteilen verfügt, mit Werkzeugen, die dabei helfen, zu erkennen, wo durch die Einführung der asphaltierten Straße Verbesserungen erzielt werden können. Dies ermöglicht es vorhandenen Entwicklungstools, über unsichere Builds zu berichten und Entwicklungsteams dabei zu helfen, unsichere Alternativen selbst zu korrigieren.

Die asphaltierte Straße scheint eine große Herausforderung zu sein, aber sie sollte im Laufe der Zeit schrittweise gebaut werden. Es gibt andere Formen von Appsec-Programmen, insbesondere den Microsoft Agile Secure Development Lifecycle. Nicht jede Methodik eines Appsec-Programms passt zu jedem Unternehmen.

## Stufe 3. Setzen Sie den gepflasterten Weg mit Ihren Entwicklungsteams um

Gepflasterte Straßen werden mit Zustimmung und direkter Beteiligung der zuständigen Entwicklungs- und Betriebsteams gebaut. Der gepflasterte Weg sollte strategisch auf das Unternehmen ausgerichtet sein und dazu beitragen, sicherere Anwendungen schneller bereitzustellen. Die Entwicklung der gepflasterten Straße sollte eine ganzheitliche Übung sein, die das gesamte Unternehmens- oder Anwendungsökosystem abdeckt, und nicht wie früher eine pro-App-Lösung.

## Stufe 4. Migrieren Sie alle kommenden und vorhandenen Anwendungen auf die asphaltierte Straße

Fügen Sie bei der Entwicklung Tools zur Erkennung befestigter Straßen hinzu und stellen Sie Entwicklungsteams Informationen zur Verfügung, um die Sicherheit ihrer Anwendungen zu verbessern, indem sie Elemente der befestigten Straße direkt übernehmen können. Sobald ein Aspekt der asphaltierten Straße übernommen wurde, sollten Organisationen kontinuierliche Integrationsprüfungen implementieren, die vorhandenen Code und Check-Ins überprüfen, die verbotene Alternativen verwenden, und den Build oder Check-In warnen oder ablehnen. Dadurch wird verhindert, dass sich unsichere Optionen im Laufe der Zeit in den Code einschleichen, wodurch technische Schulden und eine fehlerhafte unsichere Anwendung vermieden werden. Solche Warnungen sollten auf die sichere Alternative verweisen, damit das Entwicklungsteam sofort die richtige Antwort erhält. Sie können die befestigte Straßenkomponente schnell umgestalten und übernehmen.

## Stufe 5. Testen Sie, ob die asphaltierte Straße die in den OWASP Top 10 festgestellten Probleme gemildert hat

Gepflasterte Straßenkomponenten sollten ein wichtiges Problem der OWASP Top 10 ansprechen, zum Beispiel die Frage, wie anfällige Komponenten automatisch erkannt oder repariert werden können, oder ein IDE-Plugin für die statische Codeanalyse, um Injektionen zu erkennen, oder noch besser, eine Bibliothek zu verwenden, die bekanntermaßen sicher gegen Injektionen ist. Je mehr dieser sicheren Ersatzprodukte den Teams zur Verfügung gestellt werden, desto besser. Eine wichtige Aufgabe des appsec-Teams besteht darin, dafür zu sorgen, dass die Sicherheit dieser Komponenten kontinuierlich evaluiert und verbessert wird. Sobald sie verbessert sind, sollte ein Kommunikationsweg mit den Verbrauchern der Komponente darauf hinweisen, dass ein Upgrade erfolgen sollte, vorzugsweise automatisch, wenn nicht, wird es zumindest auf einem Dashboard oder ähnlichem hervorgehoben.

## Stufe 6. Bauen Sie Ihr Programm in ein ausgereiftes AppSec-Programm um

Sie dürfen nicht bei den OWASP Top 10 stehen bleiben. Sie deckt nur 10 Risikokategorien ab. Wir empfehlen Organisationen nachdrücklich, den Application Security Verification Standard zu übernehmen und je nach Risikostufe der entwickelten Anwendungen nach und nach befestigte Straßenkomponenten und Tests für Level 1, 2 und 3 hinzuzufügen.

## Darüber hinausgehen

Alle großartigen AppSec-Programme gehen über das Nötigste hinaus. Jeder muss weitermachen, wenn wir die Appsec-Schwachstellen jemals in den Griff bekommen wollen.

- **Konzeptionelle Integrität**. Ausgereifte AppSec-Programme müssen ein Konzept einer Sicherheitsarchitektur enthalten, sei es eine formelle Cloud- oder Unternehmenssicherheitsarchitektur oder eine Bedrohungsmodellierung

- **Automatisierung und Skalierung**. Ausgereifte AppSec-Programme versuchen, so viele ihrer Ergebnisse wie möglich zu automatisieren, indem sie Skripte verwenden, um komplexe Penetrationstestschritte zu emulieren, statische Code-Analysetools, die den Entwicklungsteams direkt zur Verfügung stehen, Entwicklerteams bei der Erstellung von Appsec-Einheits- und Integrationstests unterstützen und vieles mehr.

- **Kultur**. Ausgereifte AppSec-Programme versuchen, das unsichere Design auszubauen und die technischen Schulden des vorhandenen Codes zu beseitigen, indem sie Teil des Entwicklungsteams und nicht daneben stehen. AppSec-Teams, die Entwicklungsteams als „wir“ und „sie“ betrachten, sind zum Scheitern verurteilt.

-   **Ständige Verbesserung**. Ausgereifte AppSec-Programme streben danach, sich ständig zu verbessern. Wenn etwas nicht funktioniert, hören Sie damit auf. Wenn etwas schwerfällig oder nicht skalierbar ist, arbeiten Sie daran, es zu verbessern. Wenn etwas von den Entwicklungsteams nicht verwendet wird und keine oder nur begrenzte Auswirkungen hat, machen Sie etwas anderes. Nur weil wir seit den 1970er Jahren Tests wie "Desk checks" durchführen, heißt das nicht, dass es eine gute Idee ist. Messen, bewerten und dann aufbauen oder verbessern.
