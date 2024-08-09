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

Eine der neuen Kategorie für 2021 konzentriert sich auf Risiken im Zusammenhang mit Design- und Architekturfehlern und fordert einen stärkeren Einsatz von Bedrohungsmodellierung, sicheren Design Pattern und Referenzarchitekturen. Als Community sollten wir uns nicht nur auf den "Shift-Left"-Ansatz während der Entwicklung fokussieren, sondern auch auf die vorangehenden Aktivitäten, die für die Prinzipien von „Secure by Design“ wesentlich sind. Bemerkenswerte Common Weakness Enumerations (CWEs) sind *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation*, and *CWE-522: Insufficiently Protected Credentials*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Unsicheres Design ist eine umfassende Kategorie, die verschiedene Schwachstellen umfasst und als „fehlendes oder ineffektives Design von Schutzmechanismen“ beschrieben wird.Unsicheres Anwendungsdesign ist nicht die Ursache für alle anderen Top-10-Risikokategorien. Es gibt einen Unterschied zwischen unsicherem Design und unsicherer Implementierung. Designfehler und Implementierungsfehler unterscheiden sich aus gutem Grund, da sie unterschiedliche Ursachen und Mitigationen erfordern. Ein sicheres Design kann immer noch Implementierungsfehler enthalten, die zu ausnutzbaren Schwachstellen führen. Ein unsicheres Design lässt sich nicht durch eine perfekte Implementierung beheben, da die notwendigen Sicherheitskontrollen von vornherein nicht zur Abwehr bestimmter Angriffe vorgesehen waren. Ein Faktor, der zu einem unsicheren Design beiträgt, ist das Fehlen eines Geschäftsrisikoprofils, das der entwickelten Software oder dem System zugrunde liegt, was dazu führt, dass das erforderliche Maß an Sicherheitsdesign nicht bestimmt wird.

### Anforderungs- und Ressourcenmanagement

Legen Sie zusammen mit den Geschäftseinheiten die fachlichen Anforderungen an die Anwendung fest, einschließlich des Schutzbedarfs hinsichtlich Vertraulichkeit, Integrität, Verfügbarkeit und Authentizität aller Datenbestände, sowie die vorgesehene Geschäftslogik. Berücksichtigen Sie, wie exponiert Ihre Anwendung sein wird und ob Sie (zusätzlich zur Zugangskontrolle) eine Mandantentrennung benötigt. Stellen Sie die technischen Anforderungen zusammen, einschließlich funktionaler und nicht funktionaler Sicherheitsanforderungen. Planen Sie das Budget für alle Design-, Entwicklungs-, Test- und Betriebsaktivitäten, unter Berücksichtigung der Sicherheit.


### Sicheres Design

Sicheres Design ist sowohl eine Denkweise als auch eine Vorgehensweise, die kontinuierlich Bedrohungen analysiert und sicherstellt, dass der Code robust entwickelt und getestet wird, um bekannte Angriffsmethoden zu verhindern. Die Bedrohungsmodellierung sollte in *Backlog Refinement* Terminen oder vergleichbaren Aktivitäten integriert werden. Dabei sollten Änderungen im Datenfluss, in der Zugriffskontrolle und anderen Sicherheitsmaßnahmen überprüft werden. Identifizieren Sie während der Entwicklung der User Story die richtigen Ablauf- und Fehlerzustände und stellen Sie sicher, dass sie gut verstanden sind und die Verantwortlichen und sonstigen Beteiligten dazu übereinstimmen. Analysieren Sie Annahmen und Bedingungen für erwartete sowie fehlgeschlagene Prozesse, um sicherzustellen, dass diese weiterhin angemessen und die erwünschten sind. Bestimmen Sie, wie Annahmen überprüft und Bedingungen erzwingt werden können, die für das korrekte Verhalten erforderlich sind. Stellen Sie sicher, dass die Ergebnisse in der User Story dokumentiert sind. Lernen Sie aus Fehlern und bieten Sie positive Anreize, um kontinuierliche Verbesserungen voranzutreiben. Sicheres Design ist weder ein Add-on noch ein Tool, das Sie einer Software hinzufügen können.

### Sicherer Entwicklungslebenszyklus

Sichere Software erfordert einen sicheren Entwicklungslebenszyklus, dein Einsatz von sicheren Entwurfsmustern, eine bewährte Methodik, sichere Komponentenbibliotheken, geeignete Tools und Bedrohungsmodellierung. Wenden Sie sich zu Beginn eines Softwareprojekts während der gesamten Projektlaufzeit und Wartung Ihrer Software an Ihre Sicherheitsspezialisten. Erwägen Sie die Nutzung des [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org), um Ihre Bemühungen zur sicheren Softwareentwicklung zu strukturieren.

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

- Entwickeln und nutzen Sie einen sicheren Entwicklungslebenszyklus mit Unterstützung durch AppSec-Experten bei der Bewertung und Gestaltung von Sicherheits- und Datenschutzkontrollen.

- Erstellen und verwenden Sie eine Bibliothek mit sicheren Entwurfsmustern und bewährten, erprobten Komponenten.

- Verwenden Sie Bedrohungsmodellierung für kritische Bereiche wie Authentifizierung, Zugriffskontrolle, Geschäftslogik und wichtige Abläufe.

- Integrieren Sie Sicherheitsvorgaben und -kontrollen in den User Stories.

- Implementieren Sie Plausibilitätsprüfungen auf allen Ebenen Ihrer Anwendung, vom Frontend bis zum Backend.

- Schreiben Sie Unit- und Integrationstests, um zu validieren, dass alle kritischen Abläufe resistent gegen das Bedrohungsmodell sind. Stellen Sie Anwendungs- *und* Missbrauchsfälle für jede Ebene Ihrer Anwendung zusammen.

- Trennen Sie die Ebenen basierend auf Gefährdungs- und Schutzbedarf auf System- und Netzwerkebene.

- Stellen Sie sicher, dass die Trennung der Mandanten konsequent auf allen Ebenen erfolgt.

- Begrenzen Sie den Ressourcenverbrauch pro Mitglied oder Dienst

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Ein Workflow zur Wiederherstellung von Anmeldeinformationen kann „Fragen und Antworten“ enthalten, was jedoch gemäß NIST 800-63b, dem OWASP ASVS und den OWASP Top 10 nicht zulässig ist. Fragen und Antworten können nicht als vertrauenswürdiger Identitätsnachweis  betrachtet werden. Mehr als eine Person kann die Antworten kennen, weshalb sie verboten sind. Dieser Code sollte entfernt und durch ein sichereres Design ersetzt werden.

**Szenario Nr. 2:** Eine Kinokette bietet Gruppenbuchungsrabatte an und verlangt erst bei mehr als fünfzehn Besuchern eine Anzahlung. Angreifende könnten dieses System ausnutzen, indem sie versuchen, mit wenigen Anfragen sechshundert Sitzplätze in allen Kinos gleichzeitig zu reservieren, was zu erheblichen Einnahmeverlusten führen könnte.

**Szenario Nr. 3:** Die E-Commerce-Website einer Einzelhandelskette ist nicht vor Bots geschützt, die von Scalpern betrieben werden, die High-End-Grafikkarten kaufen, um sie auf Auktionsplattformen weiterzuverkaufen. Dies sorgt für schreckliche Publicity bei den Grafikkartenherstellern und Besitzern von Einzelhandelsketten und sorgt für anhaltende Frustration bei Enthusiasten, die diese Karten nicht erwerben können. Sorgfältiges Anti-Bot-Design sowie Automatismen, die z. B. Käufe ablehnen, die innerhalb weniger Sekunden nach Verfügbarkeit getätigt werden, können helfen, unechte Käufe zu identifizieren und solche Transaktionen zu verhindern.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Secure Product Design", osib=osib) }} <!-- [OWASP Spickzettel: Sicheres Produktdesign](https://cheatsheetseries. owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.samm.2-0." ~ "Design.Security Architecture", osib=osib) }} <!-- [OWASP SAMM:: Design Security Architecture](https:/ /owaspsamm.org/model/design/security-architecture/) -->
- {{ osib_link(link="osib.owasp.samm.2-0." ~ "Design.Threat Assessment", osib=osib) }} <!-- [OWASP SAMM:: Design Threat Assessment](https:/ /owaspsamm.org/model/design/threat-assessment/) -->
- {{ osib_link(link="osib.nist.publications.guidelines Minimum Standards Developer Verification Software", osib=osib) }} <!--- [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https:/ /www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software) --->
- {{ osib_link(link="osib.threatmodelingmanifesto", doc="", osib=osib) }} <!--- [Das Bedrohungsmodellierungsmanifest](https://threatmodelingmanifesto.org) --->
- {{ osib_link(link="osib.hysnsec.awesome Threat Modelling", doc="", osib=osib) }} <!---[Awesome Threat Modeling](https://github.com/hysnsec/awesome -Bedrohungsmodellierung) --->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.73", doc="", osib=osib) }} <!-- [CWE-73: Externe Kontrolle von Dateinamen oder Pfad](https://cwe.mitre.org/data/definitions/73.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.183", doc="", osib=osib) }} <!-- [CWE-183: Zulässige Liste zulässiger Eingaben](httpss://cwe.mitre.org/data/definitions/183.html) -->
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
