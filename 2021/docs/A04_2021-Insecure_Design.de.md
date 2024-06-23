---
source: "https://owasp.org/Top10/A04_2021-Insecure_Design/"
title:  "A04:2021 – Unsicheres Anwendungsdesign"
id:     "A04:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".4" -%}
#A04:2021 – Unsicheres Anwendungsdesign ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name ="Unsicheres Design", lang=lang, source=source, parent=parent) }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19 %             | 3.00 %              | 6.46                 | 6.78                | 77.25 %       | 42.51 %       | 262,407           | 2,691      |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Eine neue Kategorie für 2021 konzentriert sich auf Risiken im Zusammenhang mit Design- und Architekturfehlern und fordert einen stärkeren Einsatz von Bedrohungsmodellen, sicheren Designmustern und Referenzarchitekturen. Als Community müssen wir über die „Linksverschiebung“ im Codierungsbereich hinausgehen und Aktivitäten vorab codieren, die für die Prinzipien von „Secure by Design“ von entscheidender Bedeutung sind. Zu den bemerkenswerten Common Weakness Enumerations (CWEs) gehören *CWE-209: Generierung einer Fehlermeldung mit vertraulichen Informationen*, *CWE-256: Ungeschützte Speicherung von Anmeldeinformationen*, *CWE-501: Verletzung der Vertrauensgrenze* und *CWE-522: Unzureichend Geschützte Anmeldeinformationen*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Unsicheres Design ist eine weit gefasste Kategorie, die verschiedene Schwächen darstellt und als „fehlendes oder ineffektives Kontrolldesign“ ausgedrückt wird. Unsicheres Design ist nicht die Ursache für alle anderen Top-10-Risikokategorien. Es gibt einen Unterschied zwischen unsicherem Design und unsicherer Implementierung. Wir unterscheiden aus gutem Grund zwischen Designfehlern und Implementierungsfehlern, denn sie haben unterschiedliche Ursachen und Abhilfemaßnahmen. Ein sicheres Design kann immer noch Implementierungsfehler aufweisen, die zu Schwachstellen führen, die ausgenutzt werden können. Ein unsicheres Design kann nicht durch eine perfekte Implementierung behoben werden, da die erforderlichen Sicherheitskontrollen per Definition nie zur Abwehr bestimmter Angriffe geschaffen wurden. Einer der Faktoren, die zu einem unsicheren Design beitragen, ist das Fehlen eines Geschäftsrisikoprofils, das der zu entwickelnden Software oder dem zu entwickelnden System innewohnt, und daher das Versäumnis, zu bestimmen, welches Maß an Sicherheitsdesign erforderlich ist.

### Anforderungs- und Ressourcenmanagement

Erfassen und verhandeln Sie die Geschäftsanforderungen für eine Anwendung mit dem Unternehmen, einschließlich der Schutzanforderungen hinsichtlich Vertraulichkeit, Integrität, Verfügbarkeit und Authentizität aller Datenbestände und der erwarteten Geschäftslogik. Berücksichtigen Sie, wie exponiert Ihre Anwendung sein wird und ob Sie (zusätzlich zur Zugangskontrolle) eine Trennung der Mieter benötigen. Stellen Sie die technischen Anforderungen zusammen, einschließlich funktionaler und nichtfunktionaler Sicherheitsanforderungen. Planen und verhandeln Sie das Budget für alle Design-, Bau-, Test- und Betriebsaktivitäten, einschließlich Sicherheitsaktivitäten.

### Sicheres Design

Sicheres Design ist eine Kultur und Methodik, die Bedrohungen kontinuierlich bewertet und sicherstellt, dass Code robust entworfen und getestet wird, um bekannte Angriffsmethoden zu verhindern. Die Bedrohungsmodellierung sollte in Verfeinerungssitzungen (oder ähnliche Aktivitäten) integriert werden; Suchen Sie nach Änderungen im Datenfluss und in der Zugriffskontrolle oder anderen Sicherheitskontrollen. Bestimmen Sie bei der Entwicklung der User Story die korrekten Ablauf- und Fehlerzustände und stellen Sie sicher, dass sie von den verantwortlichen und betroffenen Parteien gut verstanden und akzeptiert werden. Analysieren Sie Annahmen und Bedingungen für erwartete und fehlgeschlagene Abläufe und stellen Sie sicher, dass diese immer noch korrekt und wünschenswert sind. Bestimmen Sie, wie Sie die Annahmen validieren und Bedingungen durchsetzen können, die für ordnungsgemäßes Verhalten erforderlich sind. Stellen Sie sicher, dass die Ergebnisse in der User Story dokumentiert sind. Lernen Sie aus Fehlern und bieten Sie positive Anreize, um Verbesserungen voranzutreiben. Sicheres Design ist weder ein Add-on noch ein Tool, das Sie einer Software hinzufügen können.

### Sicherer Entwicklungslebenszyklus

Sichere Software erfordert einen sicheren Entwicklungslebenszyklus, eine Art sicheres Entwurfsmuster, eine bewährte Methodik, eine sichere Komponentenbibliothek, Tools und Bedrohungsmodellierung. Wenden Sie sich zu Beginn eines Softwareprojekts während der gesamten Projektlaufzeit und Wartung Ihrer Software an Ihre Sicherheitsspezialisten. Erwägen Sie die Nutzung des [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org), um Ihre Bemühungen zur sicheren Softwareentwicklung zu strukturieren.

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

- Erstellen und nutzen Sie einen sicheren Entwicklungslebenszyklus mit AppSec-Experten, um bei der Bewertung und Gestaltung von Sicherheits- und Datenschutzkontrollen zu helfen

- Erstellen und verwenden Sie eine Bibliothek mit sicheren Entwurfsmustern oder gebrauchsfertigen Komponenten für befestigte Straßen

- Nutzen Sie Bedrohungsmodellierung für kritische Authentifizierung, Zugriffskontrolle, Geschäftslogik und Schlüsselflüsse

- Integrieren Sie Sicherheitssprache und -kontrollen in User Stories

- Integrieren Sie Plausibilitätsprüfungen auf jeder Ebene Ihrer Anwendung (vom Frontend bis zum Backend).

- Schreiben Sie Unit- und Integrationstests, um zu validieren, dass alle kritischen Flüsse gegen das Bedrohungsmodell resistent sind. Stellen Sie Anwendungsfälle *und* Missbrauchsfälle für jede Ebene Ihrer Anwendung zusammen.

- Trennen Sie die Ebenen je nach Gefährdungs- und Schutzbedarf auf System- und Netzwerkebene

- Trennen Sie die Mieter konsequent auf allen Ebenen

- Begrenzen Sie den Ressourcenverbrauch pro Benutzer oder Dienst

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Ein Workflow zur Wiederherstellung von Anmeldeinformationen kann „Fragen und Antworten“ enthalten, was durch NIST 800-63b, das OWASP ASVS und die OWASP Top 10 verboten ist. Fragen und Antworten können nicht als identitätsnachweis vertrauenswürdig sein Mehr als eine Person kann die Antworten kennen, weshalb sie verboten sind. Dieser Code sollte entfernt und durch ein sichereres Design ersetzt werden.

**Szenario Nr. 2:** Eine Kinokette gewährt Gruppenbuchungsrabatte und hat maximal fünfzehn Besucher, bevor eine Anzahlung verlangt wird. Angreifer könnten diesen Ablauf modellieren und testen, ob sie mit wenigen Anfragen sechshundert Sitzplätze und alle Kinos auf einmal buchen könnten, was zu massiven Einnahmeverlusten führen würde.

**Szenario Nr. 3:** Die E-Commerce-Website einer Einzelhandelskette ist nicht vor Bots geschützt, die von Scalpern betrieben werden, die High-End-Grafikkarten kaufen, um Auktionswebsites weiterzuverkaufen. Dies sorgt für schreckliche Publicity bei den Grafikkartenherstellern und Besitzern von Einzelhandelsketten und sorgt für anhaltendes böses Blut bei Enthusiasten, die diese Karten nicht um jeden Preis bekommen können. Sorgfältiges Anti-Bot-Design und Domänenlogikregeln, wie z. B. Käufe, die innerhalb weniger Sekunden nach der Verfügbarkeit getätigt werden, können unechte Käufe identifizieren und solche Transaktionen ablehnen.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Secure Product Design", osib=osib) }} <!-- [OWASP Spickzettel: Sicheres Produktdesign](https://cheatsheetseries. owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.samm.2-0." ~ "Design.Security Architecture", osib=osib) }} <!-- [OWASP SAMM:: Design Security Architecture](https:/ /owaspsamm.org/model/design/security-architecture/) -->
- {{ osib_link(link="osib.owasp.samm.2-0." ~ "Design.Threat Assessment", osib=osib) }} <!-- [OWASP SAMM:: Design Threat Assessment](https:/ /owaspsamm.org/model/design/threat-assessment/) -->
- {{ osib_link(link="osib.nist.publications.guidelines Minimum Standards Developer Verification Software", osib=osib) }} <!--- [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https:/ /www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software) --->
- {{ osib_link(link="osib.threatmodelingmanifesto", doc="", osib=osib) }} <!--- [Das Bedrohungsmodellierungsmanifest](https://threatmodelingmanifesto.org) --->
- {{ osib_link(link="osib.hysnsec.awesome Threat Modelling", doc="", osib=osib) }} <!---[Awesome Threat Modeling](https://github.com/hysnsec/awesome -Bedrohungsmodellierung) --->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.73", doc="", osib=osib) }} <!-- [CWE-73: Externe Kontrolle von Dateinamen oder Pfad](https://cwe.mitre.org/data/definitions/73.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.183", doc="", osib=osib) }} <!-- [CWE-183: Zulässige Liste zulässiger Eingaben](https://cwe.mitre.org/data/definitions/183.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.209", doc="", osib=osib) }} <!-- [CWE-209: Generierung einer Fehlermeldung mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/209.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.213", doc="", osib=osib) }} <!-- [CWE-213: Offenlegung sensibler Informationen aufgrund inkompatibler Richtlinien](https://cwe.mitre.org/data/definitions/213.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.235", doc="", osib=osib) }} <!-- [CWE-235: Unsachgemäßer Umgang mit zusätzlichen Parametern](https://cwe.mitre.org/data/definitions/235.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.256", doc="", osib=osib) }} <!-- [CWE-256: Ungeschützte Speicherung von Anmeldeinformationen](https://cwe.mitre.org/data/definitions/256.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.257", doc="", osib=osib) }} <!-- [CWE-257: Speichern von Passwörtern in einem wiederherstellbaren Format](https://cwe.mitre.org/data/definitions/257.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.266", doc="", osib=osib) }} <!-- [CWE-266: Falsche Berechtigungszuweisung](https://cwe.mitre. org/data/definitions/266.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.269", doc="", osib=osib) }} <!-- [CWE-269: Unsachgemäße Berechtigungsverwaltung](https://cwe.mitre.org/data/definitions/269.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.280", doc="", osib=osib) }} <!-- [CWE-280: Unsachgemäßer Umgang mit unzureichenden Berechtigungen oder Privilegien](https://cwe.mitre.org/data/definitions/280.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.311", doc="", osib=osib) }} <!-- [CWE-311: Fehlende Verschlüsselung sensibler Daten](https://cwe.mitre.org/data/definitions/311.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.312", doc="", osib=osib) }} <!-- [CWE-312: Klartextspeicherung sensibler Informationen](https://cwe.mitre.org/data/definitions/312.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.313", doc="", osib=osib) }} <!-- [CWE-313: Klartextspeicherung in einer Datei oder auf der Festplatte](https://cwe.mitre.org/data/definitions/313.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.316", doc="", osib=osib) }} <!-- [CWE-316: Klartextspeicherung sensibler Informationen im Speicher](https://cwe.mitre.org/data/definitions/316.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.419", doc="", osib=osib) }} <!-- [CWE-419: Ungeschützter Primärkanal](https://cwe.mitre.org/data/definitions/419.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.430", doc="", osib=osib) }} <!-- [CWE-430: Bereitstellung eines falschen Handlers](https://cwe.mitre.org/data/definitions/430.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.434", doc="", osib=osib) }} <!-- [CWE-434: Uneingeschränktes Hochladen von Dateien mit gefährlichem Typ](https://cwe.mitre.org/data/definitions/434.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.444", doc="", osib=osib) }} <!-- [CWE-444: Inkonsistente Interpretation von HTTP-Anfragen ('HTTP Request Smuggling')] (https://cwe.mitre.org/data/definitions/444.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.451", doc="", osib=osib) }} <!-- [CWE-451: Falsche Darstellung kritischer Informationen durch die Benutzeroberfläche](https://cwe.mitre.org/data/definitions/451.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.472", doc="", osib=osib) }} <!-- [CWE-472: Externe Kontrolle von angenommen-unveränderlichen Webparametern](https://cwe.mitre.org/data/definitions/472.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.501", doc="", osib=osib) }} <!-- [CWE-501: Trust Boundary Violation](https://cwe.mitre. org/data/definitions/501.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.522", doc="", osib=osib) }} <!-- [CWE-522: Unzureichend geschützte Anmeldeinformationen](https://cwe.mitre.org/data/definitions/522.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.525", doc="", osib=osib) }} <!-- [CWE-525: Verwendung von Webbrowser-Cache mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/525.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.539", doc="", osib=osib) }} <!-- [CWE-539: Verwendung dauerhafter Cookies mit sensiblen Informationen](https://cwe.mitre.org/data/definitions/539.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.579", doc="", osib=osib) }} <!-- [CWE-579: J2EE Bad Practices: Nicht serialisierbares Objekt in Sitzung gespeichert](https://cwe.mitre.org/data/definitions/579.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.598", doc="", osib=osib) }} <!-- [CWE-598: Verwendung der GET-Anfragemethode mit sensiblen Abfragezeichenfolgen](https://cwe.mitre.org/data/definitions/598.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.602", doc="", osib=osib) }} <!-- [CWE-602: Clientseitige Durchsetzung serverseitiger Sicherheit](https://cwe.mitre.org/data/definitions/602.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.642", doc="", osib=osib) }} <!-- [CWE-642: Externe Kontrolle kritischer Zustandsdaten](https://cwe.mitre.org/data/definitions/642.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.646", doc="", osib=osib) }} <!-- [CWE-646: Abhängigkeit vom Dateinamen oder der Erweiterung einer extern bereitgestellten Datei]( https://cwe.mitre.org/data/definitions/646.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.650", doc="", osib=osib) }} <!-- [CWE-650: Vertrauenswürdige HTTP-Berechtigungsmethoden auf der Serverseite](https://cwe.mitre.org/data/definitions/650.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.653", doc="", osib=osib) }} <!-- [CWE-653: Unzureichende Kompartimentierung](https://cwe.mitre.org/data/definitions/653.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.656", doc="", osib=osib) }} <!-- [CWE-656: Vertrauen in Sicherheit durch Unklarheit](https://cwe.mitre.org/data/definitions/656.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.657", doc="", osib=osib) }} <!-- [CWE-657: Verletzung sicherer Designprinzipien](https://cwe.mitre.org/data/definitions/657.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.799", doc="", osib=osib) }} <!-- [CWE-799: Unsachgemäße Kontrolle der Interaktionshäufigkeit](https://cwe.mitre.org/data/definitions/799.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.807", doc="", osib=osib) }} <!-- [CWE-807: Abhängigkeit von nicht vertrauenswürdigen Eingaben bei einer Sicherheitsentscheidung](https://cwe.mitre.org/data/definitions/807.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.840", doc="", osib=osib) }} <!-- [CWE-840: Geschäftslogikfehler](https://cwe.mitre.org/data/definitions/840.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.841", doc="", osib=osib) }} <!-- [CWE-841: Unsachgemäße Durchsetzung des Verhaltensworkflows](https://cwe.mitre.org/data/definitions/841.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.927", doc="", osib=osib) }} <!-- [CWE-927: Verwendung impliziter Absichten für sensible Kommunikation](https://cwe.mitre.org/data/definitions/927.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.1021", doc="", osib=osib) }} <!-- [CWE-1021: Unsachgemäße Einschränkung gerenderter UI-Ebenen oder Frames](https://cwe.mitre.org/data/definitions/1021.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.1173", doc="", osib=osib) }} <!-- [CWE-1173: Unsachgemäße Verwendung des Validierungs-Frameworks](https://cwe.mitre.org/data/definitions/1173.html) -->
