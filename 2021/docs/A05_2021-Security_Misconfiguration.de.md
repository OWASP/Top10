---
source: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
title: "A05:2021 – Sicherheitsrelevante Fehlkonfiguration"
id: "A05:2021"
lang:	"de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".5" -%}
#A05:2021 – Sicherheitsrelevante Fehlkonfiguration ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name ="Sicherheitsfehlkonfiguration", lang=lang, source=source, parent=parent, merged_from=[extra.osib.document ~ ".2017.4", extra.osib.document ~ ".2017.6"]) }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 8.12                 | 6.56                | 89.58%       | 44.84%       | 208,387           | 789        |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Im Vergleich zu Platz 6 in der vorherigen Ausgabe wurden 90 % der Anwendungen auf irgendeine Form von Fehlkonfiguration getestet, mit einer durchschnittlichen Inzidenzrate von 4 % und über 208.000 Vorkommen einer Common Weakness Enumeration (CWE) in dieser Risikokategorie. Angesichts der zunehmenden Verlagerung hin zu hoch konfigurierbarer Software ist es nicht verwunderlich, dass diese Kategorie aufsteigt. Bemerkenswerte enthaltene CWEs sind *CWE-16 Configuration* und *CWE-611 Unproper Restriction of XML External Entity Reference*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Die Anwendung besitzt möglicherweise Schwachstellen, wenn folgendes zutrifft:

– Mangelhafte Sicherheitshärtung des Anwendungsstacks oder ungeeignet konfigurierte Berechtigungen von Clouddiensten.

- Nicht benötigte Features sind aktiviert oder installiert (z.B. unnötige Ports, Dienste, Seiten, Nutzer oder Rechte).

- Standardnutzer und -passwörter sind aktiviert, bzw. unverändert.

- Die Fehlerbehandlung gibt Stack-Traces oder andere interne technische Fehlermeldungen an den Nutzer preis.

– Für aktualisierte Systeme sind die neuesten Sicherheitsfeatures deaktiviert oder nicht sicher konfiguriert.

- Die Sicherheitseinstellungen in den Anwendungsservern und -frameworks (z.B. Struts, Spring, ASP.NET), Bibliotheken, Datenbanken etc. sind nicht auf sichere Werte gesetzt.

– Der Server sendet keine Sicherheits-Header oder -Direktiven, bzw. diese sind nicht sicher konfiguriert

- Die Software ist veraltet oder verwundbar (siehe [A06:2021-Unsichere oder veraltete Komponenten](A06_2021-Vulnerable_and_Outdated_Components.de.md)). Ohne einen abgestimmten und reproduzierbaren Prozess sind Systeme einem höheren Risiko ausgesetzt!

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Es sollten sichere Installationsprozesse implementiert werden, darunter:

- Ein wiederholbarer Härtungsprozess ermöglicht die schnelle und einfache Bereitstellung einer anderen Umgebung, die entsprechend abgesichert ist. Entwicklungs-, Qualitätssicherungs- und Produktionsumgebungen sollten alle identisch konfiguriert sein, wobei in jeder Umgebung unterschiedliche Anmeldeinformationen verwendet werden sollten. Dieser Prozess sollte automatisiert werden, um den Aufwand für die Einrichtung einer neuen sicheren Umgebung zu minimieren.

- Eine minimale Plattform ohne unnötige Funktionen, Komponenten, Dokumentation und Beispiele. Entfernen Sie Funktionen und Frameworks die Sie nicht verwenden oder installieren Sie diese erst gar nicht.

– Überprüfen und Aktualisieren der Konfigurationen, die für alle Sicherheitshinweise, Updates und Patches im Rahmen des Patch-Verwaltungsprozesses geeignet sind (siehe [A06:2021-Unsichere oder veraltete Komponenten](A06_2021-Vulnerable_and_Outdated_Components.de.md)). Überprüfen Sie die Cloud-Speicherberechtigungen (z. B. S3-Bucket-Berechtigungen).

– Eine segmentierte Anwendungsarchitektur sorgt durch Segmentierung, Containerisierung oder Cloud-Sicherheitsgruppen (ACLs) für eine effektive und sichere Trennung zwischen Komponenten oder Mandanten.

- Senden von Sicherheitsanweisungen an Clients, z. B. Sicherheitsheader.

- Ein automatisierter Prozess zur Überprüfung der Wirksamkeit der Konfigurationen und Einstellungen in allen Umgebungen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Mögliche-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Der Anwendungsserver wird mit Beispielanwendungen geliefert, die nicht vom Produktionsserver entfernt wurden. Diese Beispielanwendungen weisen bekannte Sicherheitslücken auf, die Angreifer nutzen, um den Server zu gefährden. Angenommen, eine dieser Anwendungen ist die Admin-Konsole und die Standardkonten wurden nicht geändert. In diesem Fall meldet sich der Angreifer mit Standardkennwörtern an und übernimmt die Kontrolle.

**Szenario Nr. 2:** Die Directory Listings wurden auf dem Server nicht deaktiviert. Ein Angreifer entdeckt, dass er Verzeichnisse einfach auflisten kann. Der Angreifer findet die kompilierten Java-Klassen und lädt sie herunter, dekompiliert sie und betreibt Reverse Engineering, um den Code anzuzeigen. Der Angreifer findet dann einen schwerwiegenden Fehler in der Zugriffskontrolle in der Anwendung.

**Szenario Nr. 3:** Die Konfiguration des Anwendungsservers ermöglicht die Rückgabe detaillierter Fehlermeldungen, z. B. Stack-Traces, an Benutzer. Dadurch werden möglicherweise vertrauliche Informationen oder zugrunde liegende Fehler wie Komponentenversionen offengelegt, die bekanntermaßen anfällig sind.

**Szenario Nr. 4:** Ein Cloud-Dienstanbieter (CSP) enthält Standardfreigaben, die aus dem Internet für andere Cloud-Nutzer erreichbar sind und ermöglicht dadurch Zugriff auf sensitive Daten in der Cloud.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.wstg.4-2.4.2", osib=osib) }} <!-- [OWASP-Testhandbuch: Konfigurationsmanagement](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README) -->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.8", osib=osib) }} <!-- [OWASP-Testhandbuch: Testen auf Fehlercodes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling) -->
- {{ osib_link(link="osib.owasp.asvs.4-0.14", osib=osib) }} <!--- [Application Security Verification Standard V14-Konfiguration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md) --->
- {{ osib_link(link="osib.nist.csrc.sp.800-123", osib=osib) }} <!--- [NIST-Leitfaden zur allgemeinen Serverhärtung](https://csrc.nist.gov/publications/detail/sp/800-123/final) --->
- {{ osib_link(link="osib.cis.benchmarks", osib=osib) }} <!--- [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/) --->
- {{ osib_link(link="osib.websecurify.aws s3 Bucket Discovery", doc="osib.websecurify", osib=osib) }} <!--- Amazon S3 Bucket Discovery und Enumeration](https://blog .websecurify.com/2017/10/aws-s3-bucket-discovery.html) --->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.2", doc="", osib=osib) }} <!-- [CWE-2: 7PK – Umgebung](https://cwe.mitre.org/data/definitions/2.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.11", doc="", osib=osib) }} <!-- [CWE-11: ASP.NET-Fehlkonfiguration: Debug-Binärdatei wird erstellt](https://cwe.mitre.org/data/definitions/11.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.13", doc="", osib=osib) }} <!-- [CWE-13: ASP.NET-Fehlkonfiguration: Passwort in der Konfigurationsdatei](https://cwe.mitre.org/data/definitions/13.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.15", doc="", osib=osib) }} <!-- [CWE-15: Externe Steuerung von System- oder Konfigurationseinstellungen](https://cwe.mitre.org/data/definitions/15.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.16", doc="", osib=osib) }} <!-- [CWE-16: Konfiguration](https://cwe.mitre.org/data/definitions/16.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.260", doc="", osib=osib) }} <!-- [CWE-260: Passwort in der Konfigurationsdatei](https://cwe.mitre.org/data/definitions/260.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.315", doc="", osib=osib) }} <!-- [CWE-315: Klartextspeicherung sensibler Informationen in einem Cookie](https://cwe.mitre.org/data/definitions/315.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.520", doc="", osib=osib) }} <!-- [CWE-520: .NET-Fehlkonfiguration: Verwendung von identitätswechsel](https://cwe.mitre.org/data/definitions/520.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.526", doc="", osib=osib) }} <!-- [CWE-526: Offenlegung sensibler Informationen durch Umgebungsvariablen](https://cwe.mitre.org/data/definitions/526.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.537", doc="", osib=osib) }} <!-- [CWE-537: Java Runtime-Fehlermeldung mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/537.html) -->

- {{ osib_link(link="osib.mitre.cwe.0.547", doc="", osib=osib) }} <!-- [CWE-547: Verwendung von hartcodierten, sicherheitsrelevanten Konstanten](https://cwe.mitre.org/data/definitions/547.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.611", doc="", osib=osib) }} <!-- [CWE-611: Unsachgemäße Einschränkung der externen XML-Entitätsreferenz](https://cwe.mitre.org/data/definitions/611.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.614", doc="", osib=osib) }} <!-- [CWE-614: Sensibles Cookie in HTTPS-Sitzung ohne „Sicheres“ Attribut](https://cwe.mitre.org/data/definitions/614.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.756", doc="", osib=osib) }} <!-- [CWE-756: Fehlende benutzerdefinierte Fehlerseite](https://cwe.mitre.org/data/definitions/756.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.776", doc="", osib=osib) }} <!-- [CWE-776: Unsachgemäße Einschränkung rekursiver Entitätsreferenzen in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.942", doc="", osib=osib) }} <!-- [CWE-942: Zulässige domänenübergreifende Richtlinie mit nicht vertrauenswürdigen Domänen](https://cwe.mitre.org/data/definitions/942.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.1004", doc="", osib=osib) }} <!-- [CWE-1004: Sensibles Cookie ohne „HttpOnly“-Flag](https://cwe.mitre.org/data/definitions/1004.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.1032", doc="", osib=osib) }} <!-- [CWE-1032: OWASP Top Ten 2017 Kategorie A6 – Sicherheitsfehlkonfiguration](https://cwe.mitre.org/data/definitions/1032.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.1174", doc="", osib=osib) }} <!-- [CWE-1174: ASP.NET-Fehlkonfiguration: Falsche Modellvalidierung](https://cwe.mitre.org/data/definitions/1174.html) -->
