# A06:2025 Unsicheres Design ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style=”height:80px;width:80px” align=”right”}


## Hintergrund.

Unsicheres Design rutscht zwei Plätze von #4 auf #6 im Ranking ab, da **[A02:2025-Sicherheitsrelevante Fehlkonfiguration](A02_2025-Security_Misconfiguration.md)** und **[A03:2025-Schwachstellen in der Software-Lieferkette](A03_2025-Software_Supply_Chain_Failures.md)** es überholt haben. Diese Kategorie wurde 2021 eingeführt, und wir haben beachtliche Verbesserungen in der Branche im Zusammenhang mit Bedrohungsmodellierung und einer stärkeren Gewichtung auf sicheres Design beobachtet. Diese Kategorie konzentriert sich auf Risiken im Zusammenhang mit Design- und Architekturfehlern, mit einem Aufruf zu häufigerem Gebrauch von Bedrohungsmodellierung, sicheren Designmustern und Referenzarchitekturen. Dies umfasst Fehler in der Geschäftslogik einer Anwendung, z. B. das Fehlen der Definition unerwünschter oder unerwarteter Zustandsänderungen innerhalb einer Anwendung. Als Community müssen wir über “Shift-Left” im Coding-Bereich hinausgehen und uns auf Aktivitäten vor dem Coding konzentrieren, wie das Verfassen von Anforderungen und das Anwendungsdesign, die für die Prinzipien von Secure by Design entscheidend sind (siehe z. B. **[Aufbau eines modernen Programms zur Anwendungssicherheit](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**)


## Punktetabelle.


<table>
<tr>
   <td>Zugeordnete CWEs
   </td>
   <td>Max. Häufigkeit
   </td>
   <td>Durchschn. Häufigkeit
   </td>
   <td>Max. Abdeckung
   </td>
   <td>Durchschn. Abdeckung
   </td>
   <td>Durchschn. gewichtete Ausnutzbarkeit
   </td>
   <td>Durchschn. gewichtete Auswirkung
   </td>
   <td>Gesamtanzahl
   </td>
   <td>Summe CVEs
   </td>
</tr>
  <tr>
   <td>39
   </td>
   <td>22.18%
   </td>
   <td>1.86%
   </td>
   <td>88.76%
   </td>
   <td>35.18%
   </td>
   <td>6.96
   </td>
   <td>4.05
   </td>
   <td>729,882
   </td>
   <td>7,647
   </td>
  </tr>
</table>



## Beschreibung.

Unsicheres Design ist eine umfassende Kategorie, die verschiedene Schwachstellen umfasst und als „fehlendes oder ineffektives Design von Schutzmechanismen” beschrieben wird. Unsicheres Anwendungsdesign ist nicht die Ursache für alle anderen Top-10-Risikokategorien. Es gilt zu beachten, dass es einen Unterschied zwischen unsicherem Design und unsicherer Implementierung gibt. Designfehler und Implementierungsfehler unterscheiden sich aus gutem Grund, da sie unterschiedliche Ursachen haben, zu unterschiedlichen Zeitpunkten im Entwicklungsprozess stattfinden und unterschiedliche Abhilfemaßnahmen erfordern. Ein sicheres Design kann immer noch Implementierungsfehler enthalten, die zu ausnutzbaren Schwachstellen führen. Ein unsicheres Design lässt sich nicht durch eine perfekte Implementierung beheben, da die notwendigen Sicherheitskontrollen von vornherein nicht zur Abwehr bestimmter Angriffe vorgesehen waren. Ein Faktor, der zu einem unsicheren Design beiträgt, ist das Fehlen eines Geschäftsrisikoprofils, das der entwickelten Software oder dem System zugrunde liegt, was dazu führt, dass das erforderliche Maß an Sicherheitsdesign nicht bestimmt wird.


### Anforderungs- und Ressourcenmanagement

Legen Sie zusammen mit den Geschäftseinheiten die fachlichen Anforderungen an die Anwendung fest, einschließlich des Schutzbedarfs hinsichtlich Vertraulichkeit, Integrität, Verfügbarkeit und Authentizität aller Datenbestände, sowie die vorgesehene Geschäftslogik. Berücksichtigen Sie, wie exponiert Ihre Anwendung sein wird und ob sie eine Mandantentrennung benötigt (zusätzlich zu der, die für die Zugriffskontrolle notwendig ist). Stellen Sie die technischen Anforderungen zusammen, einschließlich funktionaler und nicht funktionaler Sicherheitsanforderungen. Planen Sie das Budget für alle Design-, Entwicklungs-, Test- und Betriebsaktivitäten, unter Berücksichtigung der Sicherheit.


### Sicheres Design

Sicheres Design ist sowohl eine Denkweise als auch eine Vorgehensweise, die kontinuierlich Bedrohungen analysiert und sicherstellt, dass der Code robust entwickelt und getestet wird, um bekannte Angriffsmethoden zu verhindern. Die Bedrohungsmodellierung sollte in Backlog Refinement Terminen oder vergleichbaren Aktivitäten integriert werden. Dabei sollten Änderungen im Datenfluss, in der Zugriffskontrolle und anderen Sicherheitsmaßnahmen überprüft werden. Bestimmen Sie in der Story-Entwicklung den korrekten Ablauf und die Fehlerzustände, stellen Sie sicher, dass diese von den verantwortlichen und betroffenen Parteien gut verstanden und vereinbart werden. Analysieren Sie Annahmen und Bedingungen für erwartete sowie fehlgeschlagene Prozesse, um sicherzustellen, dass diese angemessen und die erwünschten sind. Bestimmen Sie, wie Annahmen überprüft und Bedingungen erzwungen werden können, die für das korrekte Verhalten erforderlich sind. Stellen Sie sicher, dass die Ergebnisse in der Story dokumentiert sind. Lernen Sie aus Fehlern und bieten Sie positive Anreize, um kontinuierliche Verbesserungen voranzutreiben. Sicheres Design ist weder ein Add-on noch ein Werkzeug, das Sie einer Anwendung hinzufügen können.


### Sicherer Entwicklungslebenszyklus

Sichere Software erfordert einen sicheren Entwicklungslebenszyklus, ein sicheres Designmuster, eine Paved-Road-Methodik, eine sichere Komponentenbibliothek, geeignete Werkzeuge, Bedrohungsmodellierung und Incident-Post-Mortems, die zur Verbesserung des Prozesses genutzt werden. Kontaktieren Sie Ihre Sicherheitsspezialist:innen zu Beginn eines Softwareprojekts, während des gesamten Projekts und für die laufende Softwarewartung. Erwägen Sie die Nutzung des [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/), um Ihre Bemühungen zur sicheren Softwareentwicklung zu strukturieren.

Oft wird die Eigenverantwortung von Entwickler:innen nicht ausreichend gewürdigt. Fördern Sie eine Kultur des Bewusstseins, der Verantwortung und der proaktiven Risikominderung. Regelmäßiger Austausch über Sicherheit (z. B. während Bedrohungsmodellierungs-Sitzungen) kann eine Denkweise erzeugen, die Sicherheit in alle wichtigen Designentscheidungen einbezieht.


## Prävention und Gegenmaßnahmen.

* Entwickeln und nutzen Sie einen sicheren Entwicklungslebenszyklus mit Unterstützung durch AppSec-Expert:innen bei der Bewertung und Gestaltung von Sicherheits- und Datenschutzkontrollen.
* Erstellen und verwenden Sie eine Bibliothek mit sicheren Entwurfsmustern und bewährten, erprobten Komponenten.
* Verwenden Sie Bedrohungsmodellierung für kritische Bereiche wie Authentifizierung, Zugriffskontrolle, Geschäftslogik und wichtige Abläufe.
* Verwenden Sie Bedrohungsmodellierung als Schulungswerkzeug, um ein Sicherheitsbewusstsein zu schaffen
* Integrieren Sie Sicherheitsvorgaben und -kontrollen in den User Stories.
* Implementieren Sie Plausibilitätsprüfungen auf allen Ebenen Ihrer Anwendung, vom Frontend bis zum Backend.
* Schreiben Sie Unit- und Integrationstests, um zu validieren, dass alle kritischen Abläufe resistent gegen das Bedrohungsmodell sind. Stellen Sie Anwendungs- und Missbrauchsfälle für jede Ebene Ihrer Anwendung zusammen.
* Trennen Sie die Ebenen basierend auf Gefährdungs- und Schutzbedarf auf System- und Netzwerkebene.
* Stellen Sie sicher, dass die Trennung der Mandanten konsequent auf allen Ebenen erfolgt.


## Beispielhafte Angriffsszenarien.

**Szenario Nr. 1:** Ein Workflow zur Wiederherstellung von Zugangsdaten kann „Fragen und Antworten” enthalten, was jedoch gemäß NIST 800-63b, dem OWASP ASVS und den OWASP Top 10 nicht zulässig ist. Fragen und Antworten können nicht als vertrauenswürdiger Identitätsnachweis betrachtet werden, als mehr als eine Person die Antworten kennen kann. Diese Funktionalität sollte entfernt und durch ein sichereres Design ersetzt werden.

**Szenario Nr. 2:** Eine Kinokette bietet Gruppenbuchungsrabatte an und verlangt erst bei mehr als fünfzehn Besucher:innen eine Anzahlung. Angreifer:innen könnten dieses System ausnutzen und testen, ob sie einen Angriffsvektor in der Geschäftslogik der Anwendung finden könne, z. B. indem sie versuchen, mit wenigen Anfragen sechshundert Sitzplätze in allen Kinos gleichzeitig zu reservieren, was zu erheblichen Einnahmeverlusten führen könnte.

**Szenario Nr. 3:** Die E-Commerce-Website einer Einzelhandelskette ist nicht vor Bots geschützt, die von Scalpern betrieben werden, die High-End-Grafikkarten kaufen, um sie auf Auktionsplattformen weiterzuverkaufen. Dies sorgt für schreckliche Publicity bei den Grafikkartenherstellern und Besitzer:innen von Einzelhandelsketten und sorgt für anhaltende Frustration bei Enthusiast:innen, die diese Karten nicht erwerben können. Sorgfältiges Anti-Bot-Design sowie Automatismen, die z. B. Käufe ablehnen, die innerhalb weniger Sekunden nach Verfügbarkeit getätigt werden, können helfen, unechte Käufe zu identifizieren und solche Transaktionen zu verhindern.


## Referenzen.

* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## Liste der zugeordneten CWEs

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)

* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization (‘Race Condition’)](https://cwe.mitre.org/data/definitions/362.html)

* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)

* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)

* [CWE-444 Inconsistent Interpretation of HTTP Requests (‘HTTP Request Smuggling’)](https://cwe.mitre.org/data/definitions/444.html)

* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)

* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)

* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

* [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)

* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)

* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)
