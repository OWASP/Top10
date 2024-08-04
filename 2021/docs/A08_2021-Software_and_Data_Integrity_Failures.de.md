---
source: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
title:  "A08:2021 – Fehlerhafte Prüfung der Software- und Datenintegrität"
id:     "A08:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".8" -%}
#A08:2021 – Fehlerhafte Prüfung der Software- und Datenintegrität ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id= id, name="Software- und Datenintegritätsfehler", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.8") }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67 %             | 2.05 %              | 6.94                 | 7.94                | 75.04 %       | 45.35 %       | 47,972            | 1,152      |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Bei der neuen Kategorie für 2021 liegt der Schwerpunkt auf Annahmen in Bezug auf Software-Updates, relevante Daten und CI/CD-Pipelines ohne Überprüfung der Integrität. Eine der am höchsten gewichteten Auswirkungen von Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) Daten. Zu den erwähnenswerten Common Weakness Enumerations (CWEs) gehören:
*CWE-829: Inclusion of Functionality from Untrusted Control Sphere*,
*CWE-494: Download of Code Without Integrity Check* und
*CWE-502: Deserialization of Untrusted Data*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Software- und Datenintegritätsfehler beziehen sich auf Code und Infrastruktur, die keine Schutzmaßnahmen gegen Integritätsverletzungen bieten. Ein Beispiel hierfür ist, wenn eine Anwendung auf Plugins, Bibliotheken oder Module aus nicht vertrauenswürdigen Quellen, Repositories und Content Delivery Networks (CDNs) angewiesen ist. Eine unsichere CI/CD-Pipeline kann das Potenzial für unbefugten Zugriff, bösartigen Code oder Systemkompromittierung bieten. Schließlich enthalten viele Anwendungen heute eine automatische Update-Funktion, bei der Updates ohne ausreichende Integritätsprüfung heruntergeladen und auf die zuvor vertrauenswürdige Anwendung angewendet werden. Angreifende könnten ihre eigenen Updates hochladen, die dann auf alle Installationen verbreitet und ausgeführt werden. Ein weiteres Beispiel besteht darin, dass Objekte oder Daten in eine Struktur kodiert oder serialisiert werden, die Angreifende sehen und ändern können, und die durch eine unsichere Deserialisierung verwundbar sind.

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

- Verwenden Sie digitale Signaturen oder ähnliche Mechanismen, um sicherzustellen, dass die Software oder Daten aus der erwarteten Quelle stammen und nicht verändert wurden.

- Stellen Sie sicher, dass Bibliotheken und Abhängigkeiten, wie z. B. npm oder Maven, vertrauenswürdige Repositories nutzen. Wenn Sie ein höheres Risikoprofil haben, sollten Sie in Erwägung ziehen, ein internes Repository zu hosten, das als vertrauenswürdig gilt und überprüft wurde.

- Stellen Sie sicher, dass ein Software-Supply-Chain-Sicherheitstool wie OWASP Dependency Check oder OWASP CycloneDX verwendet wird, um zu überprüfen, dass Komponenten keine bekannten Schwachstellen enthalten.

- Stellen Sie sicher, dass es einen Überprüfungsprozess für Code- und Konfigurationsänderungen gibt, um das Risiko zu minimieren, dass bösartiger Code oder bösartige Konfigurationen in Ihre Software-Pipeline eingeschleust werden.

- Stelle Sie sicher, dass Ihre CI/CD-Pipeline über eine angemessene Trennung, Konfiguration und Zugriffskontrolle verfügt, um die Integrität des Codes zu gewährleisten, der den Build- und Bereitstellungsprozess durchläuft.

- Stellen Sie sicher, dass unsignierte oder unverschlüsselte serialisierte Daten nicht an nicht vertrauenswürdige Clients ohne eine Form der Integritätsprüfung oder digitalen Signatur gesendet werden, um dadurch eine Manipulation oder ein erneutes Versenden der serialisierten Daten zu erkennen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1: Update ohne Signierung:** Viele Heimrouter, Set-Top-Boxen, Geräte-Firmware und Andere verifizieren Updates nicht über signierte Firmware. Unsignierte Firmware ist ein wachsendes Ziel für Angreifende, und es wird erwartet, dass es in Zukunft noch schlimmer werden wird. Dies ist besonders besorgniserregend, da es in vielen Fällen keinen anderen Mechanismus zur Behebung gibt, als die Fehler in einer zukünftigen Version zu beheben und zu warten, bis die vorherigen Versionen veraltet sind.

**Szenario #2 SolarWinds bösartiges Update**: Nationalstaaten sind dafür bekannt, dass sie Update-Mechanismen angreifen. Ein bemerkenswerter Angriff war vor kurzem der SolarWinds-Orion-Angriff. Das Unternehmen, das die Software entwickelt, verfügte über sichere Build- und Update-Integritätsprozesse. Dennoch konnten diese unterwandert werden, und das Unternehmen verteilte über mehrere Monate hinweg ein sehr gezieltes bösartiges Update an mehr als 18.000 Organisationen, von denen etwa 100 betroffen waren. Dies ist eine der weitreichendsten und bedeutendsten Sicherheitsverletzungen dieser Art in der Geschichte.

**Szenario #3 Unsichere Deserialisierung:** Eine React-Anwendung ruft eine Reihe von Spring Boot Microservices auf. Als funktionale Programmierer versuchten sie sicherzustellen, dass ihr Code unveränderlich ist. Die Lösung, die sie gefunden haben, besteht darin, den Mitgliedszustand zu serialisieren und ihn mit jeder Anfrage hin und her zu schicken. Eine angreifende Person bemerkt die "`rO0" Java-Objektsignatur (in base64) und verwendet das Java Serial Killer-Tool, um Remote-Code-Ausführung auf dem Anwendungsserver zu erlangen.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.cheatsheetseries.0.software Supply Chain Security", osib=osib) }} <!-- \[OWASP Cheat Sheet: Software Supply Chain Security\](In Kürze erhältlich) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.Secure Build and Deployment", osib=osib) }} <!--- \[OWASP Cheat Sheet: Secure Build and Deployment\](In Kürze verfügbar) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.Infrastructure as Code Security", osib=osib) }} <!--- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.deserialization", osib=osib) }} <!-- [OWASP Cheat Sheet: Deserialisierung](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet) -->
- {{ osib_link(link="osib.safecode.publication.software Integrity Controls.pdf", osib=osib) }} <!--- [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf) -->
- {{ osib_link(link="osib.npr.news.SolarWinds Hack", osib=osib) }} <!--- [Ein „schlimmster Albtraum“-Cyberangriff: Die unerzählte Geschichte des SolarWinds-Hacks](<https:/ /www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>) -->
- {{ osib_link(link="osib.codecov.bash uploader compromise", doc="osib.codecov", osib=osib) }} <!--- [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update) -->
- {{ osib_link(link="osib.julien vehent.securing devops", doc="osib.julien vehent", osib=osib) }} <!--- [DevOps sichern von Julien Vehent](https://www.manning.com/books/securing-devops) -->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.345", doc="", osib=osib) }} <!-- [CWE-345: Unzureichende Überprüfung der Datenauthentizität](https://cwe.mitre.org/data/definitions/345.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.353", doc="", osib=osib) }} <!-- [CWE-353: Fehlende Unterstützung für Integritätsprüfung](https://cwe.mitre.org/data/definitions/353.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.426", doc="", osib=osib) }} <!-- [CWE-426: Nicht vertrauenswürdiger Suchpfad](https://cwe.mitre.org/data/definitions/426.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.494", doc="", osib=osib) }} <!-- [CWE-494: Download von Code ohne Integritätsprüfung](https://cwe.mitre.org/data/definitions/494.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.502", doc="", osib=osib) }} <!-- [CWE-502: Deserialisierung nicht vertrauenswürdiger Daten](https://cwe.mitre.org/data/definitions/502.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.565", doc="", osib=osib) }} <!-- [CWE-565: Abhängigkeit von Cookies ohne Validierung und Integritätsprüfung](https://cwe.mitre.org/data/definitions/565.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.784", doc="", osib=osib) }} <!-- [CWE-784: Abhängigkeit von Cookies ohne Validierung und Integritätsprüfung in einer Sicherheitsentscheidung] (https://cwe.mitre.org/data/definitions/784.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.829", doc="", osib=osib) }} <!-- [CWE-829: Einbeziehung der Funktionalität aus der nicht vertrauenswürdigen Kontrollsphäre](https://cwe.mitre.org/data/definitions/829.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.830", doc="", osib=osib) }} <!-- [CWE-830: Einbindung von Webfunktionen aus einer nicht vertrauenswürdigen source](https://cwe.mitre.org/data/definitions/830.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.915", doc="", osib=osib) }} <!-- [CWE-915: Unsachgemäß kontrollierte Änderung dynamisch bestimmter Objektattribute](https://cwe.mitre.org/data/definitions/915.html) -->
