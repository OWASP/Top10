# A04:2021 – Unsicheres Design ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## Überblick

Eine neue Kategorie für 2021 konzentriert sich auf Risiken im Zusammenhang mit Design- und Architekturfehlern und fordert einen stärkeren Einsatz von Bedrohungsmodellen, sicheren Designmustern und Referenzarchitekturen. Als Community müssen wir über die „Linksverschiebung“ im Codierungsbereich hinausgehen und Aktivitäten vorab codieren, die für die Prinzipien von „Secure by Design“ von entscheidender Bedeutung sind. Zu den bemerkenswerten Common Weakness Enumerations (CWEs) gehören *CWE-209: Generierung einer Fehlermeldung mit vertraulichen Informationen*, *CWE-256: Ungeschützte Speicherung von Anmeldeinformationen*, *CWE-501: Verletzung der Vertrauensgrenze* und *CWE-522: Unzureichend Geschützte Anmeldeinformationen*.

## Beschreibung

Unsicheres Design ist eine weit gefasste Kategorie, die verschiedene Schwächen darstellt und als „fehlendes oder ineffektives Kontrolldesign“ ausgedrückt wird. Unsicheres Design ist nicht die Ursache für alle anderen Top-10-Risikokategorien. Es gibt einen Unterschied zwischen unsicherem Design und unsicherer Implementierung. Wir unterscheiden aus gutem Grund zwischen Designfehlern und Implementierungsfehlern, denn sie haben unterschiedliche Ursachen und Abhilfemaßnahmen. Ein sicheres Design kann immer noch Implementierungsfehler aufweisen, die zu Schwachstellen führen, die ausgenutzt werden können. Ein unsicheres Design kann nicht durch eine perfekte Implementierung behoben werden, da die erforderlichen Sicherheitskontrollen per Definition nie zur Abwehr bestimmter Angriffe geschaffen wurden. Einer der Faktoren, die zu einem unsicheren Design beitragen, ist das Fehlen eines Geschäftsrisikoprofils, das der zu entwickelnden Software oder dem zu entwickelnden System innewohnt, und daher das Versäumnis, zu bestimmen, welches Maß an Sicherheitsdesign erforderlich ist.

### Anforderungs- und Ressourcenmanagement

Erfassen und verhandeln Sie die Geschäftsanforderungen für eine Anwendung mit dem Unternehmen, einschließlich der Schutzanforderungen hinsichtlich Vertraulichkeit, Integrität, Verfügbarkeit und Authentizität aller Datenbestände und der erwarteten Geschäftslogik. Berücksichtigen Sie, wie exponiert Ihre Anwendung sein wird und ob Sie (zusätzlich zur Zugangskontrolle) eine Trennung der Mieter benötigen. Stellen Sie die technischen Anforderungen zusammen, einschließlich funktionaler und nichtfunktionaler Sicherheitsanforderungen. Planen und verhandeln Sie das Budget für alle Design-, Bau-, Test- und Betriebsaktivitäten, einschließlich Sicherheitsaktivitäten.

### Sicheres Design

Sicheres Design ist eine Kultur und Methodik, die Bedrohungen kontinuierlich bewertet und sicherstellt, dass Code robust entworfen und getestet wird, um bekannte Angriffsmethoden zu verhindern. Die Bedrohungsmodellierung sollte in Verfeinerungssitzungen (oder ähnliche Aktivitäten) integriert werden; Suchen Sie nach Änderungen im Datenfluss und in der Zugriffskontrolle oder anderen Sicherheitskontrollen. Bestimmen Sie bei der Entwicklung der User Story die korrekten Ablauf- und Fehlerzustände und stellen Sie sicher, dass sie von den verantwortlichen und betroffenen Parteien gut verstanden und vereinbart werden. Analysieren Sie Annahmen und Bedingungen für erwartete und fehlgeschlagene Abläufe und stellen Sie sicher, dass diese immer noch korrekt und wünschenswert sind. Bestimmen Sie, wie Sie die Annahmen validieren und Bedingungen durchsetzen können, die für ordnungsgemäßes Verhalten erforderlich sind. Stellen Sie sicher, dass die Ergebnisse in der User Story dokumentiert sind. Lernen Sie aus Fehlern und bieten Sie positive Anreize, um Verbesserungen voranzutreiben. Sicheres Design ist weder ein Add-on noch ein Tool, das Sie einer Software hinzufügen können.

### Sicherer Entwicklungslebenszyklus

Sichere Software erfordert einen sicheren Entwicklungslebenszyklus, eine Art sicheres Entwurfsmuster, eine bewährte Methodik, eine sichere Komponentenbibliothek, Tools und Bedrohungsmodellierung. Wenden Sie sich zu Beginn eines Softwareprojekts während der gesamten Projektlaufzeit und Wartung Ihrer Software an Ihre Sicherheitsspezialisten. Erwägen Sie die Nutzung des [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org), um Ihre Bemühungen zur sicheren Softwareentwicklung zu strukturieren.

## Wie man etwas vorbeugt

- Erstellen und nutzen Sie einen sicheren Entwicklungslebenszyklus mit AppSec-Experten, um bei der Bewertung und Gestaltung von Sicherheits- und Datenschutzkontrollen zu helfen

- Erstellen und verwenden Sie eine Bibliothek mit sicheren Entwurfsmustern oder gebrauchsfertigen Komponenten für befestigte Straßen

- Nutzen Sie Bedrohungsmodellierung für kritische Authentifizierung, Zugriffskontrolle, Geschäftslogik und Schlüsselflüsse

- Integrieren Sie Sicherheitssprache und -kontrollen in User Stories

- Integrieren Sie Plausibilitätsprüfungen auf jeder Ebene Ihrer Anwendung (vom Frontend bis zum Backend).

- Schreiben Sie Unit- und Integrationstests, um zu validieren, dass alle kritischen Flüsse gegen das Bedrohungsmodell resistent sind. Stellen Sie Anwendungsfälle *und* Missbrauchsfälle für jede Ebene Ihrer Anwendung zusammen.

- Trennen Sie die Ebenen je nach Gefährdungs- und Schutzbedarf auf System- und Netzwerkebene

- Trennen Sie die Mieter konsequent auf allen Ebenen

- Begrenzen Sie den Ressourcenverbrauch pro Benutzer oder Dienst

## Beispielangriffsszenarien

**Szenario Nr. 1:** Ein Workflow zur Wiederherstellung von Anmeldeinformationen kann „Fragen und Antworten“ enthalten, was durch NIST 800-63b, das OWASP ASVS und die OWASP Top 10 verboten ist. Fragen und Antworten können nicht als Identitätsnachweis vertrauenswürdig sein Mehr als eine Person kann die Antworten kennen, weshalb sie verboten sind. Dieser Code sollte entfernt und durch ein sichereres Design ersetzt werden.

**Szenario Nr. 2:** Eine Kinokette gewährt Gruppenbuchungsrabatte und hat maximal fünfzehn Besucher, bevor eine Anzahlung verlangt wird. Angreifer könnten diesen Ablauf modellieren und testen, ob sie mit wenigen Anfragen sechshundert Sitzplätze und alle Kinos auf einmal buchen könnten, was zu massiven Einnahmeverlusten führen würde.

**Szenario Nr. 3:** Die E-Commerce-Website einer Einzelhandelskette ist nicht vor Bots geschützt, die von Scalpern betrieben werden, die High-End-Grafikkarten kaufen, um Auktionswebsites weiterzuverkaufen. Dies sorgt für schreckliche Publicity bei den Grafikkartenherstellern und Besitzern von Einzelhandelsketten und sorgt für anhaltendes böses Blut bei Enthusiasten, die diese Karten nicht um jeden Preis bekommen können. Sorgfältiges Anti-Bot-Design und Domänenlogikregeln, wie z. B. Käufe, die innerhalb weniger Sekunden nach der Verfügbarkeit getätigt werden, können unechte Käufe identifizieren und solche Transaktionen ablehnen.

## Verweise

- [OWASP-Spickzettel: Sichere Designprinzipien](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

- [OWASP SAMM: Design:Sicherheitsarchitektur](https://owaspsamm.org/model/design/security-architecture/)

- [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)

- [NIST – Richtlinien zu Mindeststandards für die Entwicklerverifizierung von Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

- [Das Bedrohungsmodellierungsmanifest](https://threatmodelingmanifesto.org)

- [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## Liste der zugeordneten CWEs

[CWE-73 Externe Kontrolle von Dateinamen oder Pfad](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 zulässige Liste zulässiger Eingaben](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209-Erzeugung einer Fehlermeldung mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Offenlegung sensibler Informationen aufgrund inkompatibler Richtlinien](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Unsachgemäßer Umgang mit zusätzlichen Parametern](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Ungeschützte Speicherung von Anmeldeinformationen](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Speichern von Passwörtern in einem wiederherstellbaren Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Falsche Berechtigungszuweisung](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Unsachgemäße Berechtigungsverwaltung](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Unsachgemäßer Umgang mit unzureichenden Berechtigungen oder Privilegien](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Fehlende Verschlüsselung sensibler Daten](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Klartextspeicherung sensibler Informationen](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Klartextspeicherung in einer Datei oder auf der Festplatte](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Klartextspeicherung sensibler Informationen im Speicher](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Ungeschützter Primärkanal](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430-Bereitstellung eines falschen Handlers](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Uneingeschränktes Hochladen von Dateien mit gefährlichem Typ](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inkonsistente Interpretation von HTTP-Anfragen („HTTP Request Smuggling“)](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Falschdarstellung kritischer Informationen](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 Externe Kontrolle des angenommenen unveränderlichen Webparameters](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Unzureichend geschützte Anmeldeinformationen](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Verwendung von Webbrowser-Cache mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Verwendung dauerhafter Cookies mit sensiblen Informationen](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Nicht serialisierbares Objekt in Sitzung gespeichert](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Verwendung der GET-Anfragemethode mit sensiblen Abfragezeichenfolgen](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Clientseitige Durchsetzung der serverseitigen Sicherheit](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 Externe Kontrolle kritischer Zustandsdaten](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Abhängigkeit vom Dateinamen oder der Erweiterung einer extern bereitgestellten Datei](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 vertraut HTTP-Berechtigungsmethoden auf der Serverseite](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Unzureichende Kompartimentierung](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Vertrauen in Sicherheit durch Unklarheit](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657-Verstoß gegen sichere Designprinzipien](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Unsachgemäße Kontrolle der Interaktionshäufigkeit](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Abhängigkeit von nicht vertrauenswürdigen Eingaben bei einer Sicherheitsentscheidung](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840-Geschäftslogikfehler](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Unsachgemäße Durchsetzung von Verhaltensabläufen](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Verwendung impliziter Absichten für sensible Kommunikation](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Unsachgemäße Einschränkung gerenderter UI-Ebenen oder Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Unsachgemäße Verwendung des Validierungsrahmens](https://cwe.mitre.org/data/definitions/1173.html)
