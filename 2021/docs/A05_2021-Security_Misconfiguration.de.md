# A05:2021 – Sicherheitsfehlkonfiguration ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 8.12                 | 6.56                | 89.58%       | 44.84%       | 208,387           | 789        |

## Überblick

Im Vergleich zu Platz 6 in der vorherigen Ausgabe wurden 90 % der Anwendungen auf irgendeine Form von Fehlkonfiguration getestet, mit einer durchschnittlichen Inzidenzrate von 4 % und über 208.000 Vorkommen einer Common Weakness Enumeration (CWE) in dieser Risikokategorie. Angesichts der zunehmenden Verlagerung hin zu hoch konfigurierbarer Software ist es nicht verwunderlich, dass diese Kategorie aufsteigt. Bemerkenswerte enthaltene CWEs sind *CWE-16 Configuration* und *CWE-611 Unproper Restriction of XML External Entity Reference*.

## Beschreibung

Die Anwendung ist möglicherweise anfällig, wenn die Anwendung:

– Eine angemessene Sicherheitshärtung in irgendeinem Teil des Anwendungsstacks fehlt oder Berechtigungen für Cloud-Dienste falsch konfiguriert sind.

- Unnötige Funktionen aktiviert oder installiert werden (z. B. unnötige Ports, Dienste, Seiten, Konten oder Berechtigungen).

- Standardkonten und ihre Passwörter aktiviert und unverändert bleiben.

- Bei der Fehlerbehandlung den Benutzern Stack-Spuren oder andere übermäßig informative Fehlermeldungen angezeigt werden.

– Bei aktualisierten Systemen die neuesten Sicherheitsfunktionen deaktiviert oder nicht sicher konfiguriert sind.

- Die Sicherheitseinstellungen in den Anwendungsservern, Anwendungsframeworks (z. B. Struts, Spring, ASP.NET), Bibliotheken, Datenbanken usw. nicht auf sichere Werte eingestellt sind.

– Der Server keine Sicherheitsheader oder Anweisungen sendet oder diese nicht auf sichere Werte eingestellt sind.

- Die Software veraltet oder anfällig ist (siehe [A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)).

Ohne einen konzertierten, wiederholbaren Konfigurationsprozess für die Anwendungssicherheit sind Systeme einem höheren Risiko ausgesetzt.

## Gegenmaßnahmen

Es sollten sichere Installationsprozesse implementiert werden, darunter:

- Ein wiederholbarer Härtungsprozess soll die schnelle und einfache Bereitstellung einer anderen Umgebung ermöglichen, die entsprechend abgesichert ist. Entwicklungs-, Qualitätssicherungs- und Produktionsumgebungen sollten alle identisch konfiguriert sein, wobei in jeder Umgebung unterschiedliche Anmeldeinformationen verwendet werden sollten. Dieser Prozess sollte automatisiert werden, um den Aufwand für die Einrichtung einer neuen sicheren Umgebung zu minimieren.

- Eine minimale Plattform ohne unnötige Funktionen, Komponenten, Dokumentation und Beispiele. Entfernen Sie nicht verwendete Funktionen und Frameworks oder installieren Sie sie nicht.

– Die Konfigurationen sollen regelmäßig auf Sicherheitshinweise, Updates und geeignete Patches überprüft und aktualisiert werden (siehe [A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)). Überprüfen der Cloud-Speicherberechtigungen (z. B. S3-Bucket-Berechtigungen).

– Eine segmentierte Anwendungsarchitektur sorgt durch Segmentierung, Containerisierung oder Cloud-Sicherheitsgruppen (ACLs) für eine effektive und sichere Trennung zwischen Komponenten oder Mandanten.

- Senden von Sicherheitsanweisungen an Clients, z. B. Sicherheitsheader.

- Ein automatisierter Prozess zur Überprüfung der Wirksamkeit der Konfigurationen und Einstellungen in allen Umgebungen.

## Beispielangriffsszenarien

**Szenario Nr. 1:** Der Anwendungsserver wird mit Beispielanwendungen geliefert, die nicht vom Produktionsserver entfernt wurden. Diese Beispielanwendungen weisen bekannte Sicherheitslücken auf, die Angreifer ausnutzen, um den Server zu gefährden. Angenommen, eine dieser Anwendungen ist die Admin-Konsole und die Standardkonten wurden nicht geändert. In diesem Fall meldet sich der Angreifer mit Standardkennwörtern an und übernimmt die Kontrolle.

**Szenario Nr. 2:** Die Verzeichnisliste ist auf dem Server nicht deaktiviert. Ein Angreifer entdeckt, dass er einfach Verzeichnisse auflisten kann. Der Angreifer findet die kompilierten Java-Klassen und lädt sie herunter, dekompiliert sie und führt Reverse-Engineering durch, um den Code anzuzeigen. Der Angreifer findet dann einen schwerwiegenden Fehler in der Zugriffskontrolle in der Anwendung.

**Szenario Nr. 3:** Die Konfiguration des Anwendungsservers ermöglicht die Ausgabe detaillierter Fehlermeldungen, z. B. von Stack-Traces, an Benutzer. Dadurch werden möglicherweise vertrauliche Informationen oder zugrunde liegende Fehler wie Komponentenversionen offengelegt, die bekanntermaßen anfällig sind.

**Szenario Nr. 4:** Ein Cloud-Dienstanbieter (CSP) verfügt über standardmäßige Freigabeberechtigungen für das Internet durch andere CSP-Benutzer. Dies ermöglicht den Zugriff auf sensible Daten, die im Cloud-Speicher gespeichert sind.

## Referenzen

- [OWASP-Testleitfaden: Konfigurationsmanagement](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

- [OWASP-Testleitfaden: Testen auf Fehlercodes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

- [Application Security Verification Standard V14-Konfiguration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

- [NIST-Leitfaden zur allgemeinen Serverhärtung](https://csrc.nist.gov/publications/detail/sp/800-123/final)

- [CIS-Sicherheitskonfigurationsleitfäden/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

- [Amazon S3-Bucket-Erkennung und -Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Liste der zugeordneten CWEs

[CWE-2 7PK – Umwelt](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET-Fehlkonfiguration: Debug-Binärdatei erstellen](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET-Fehlkonfiguration: Passwort in der Konfigurationsdatei](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 Externe Kontrolle von System- oder Konfigurationseinstellungen](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16-Konfiguration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260-Passwort in der Konfigurationsdatei](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Klartextspeicherung sensibler Informationen in einem Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET-Fehlkonfiguration: Verwendung von Identitätswechsel](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Offenlegung sensibler Informationen durch Umgebungsvariablen](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime-Fehlermeldung mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Aufnahme vertraulicher Informationen in eine Include-Datei](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Verwendung von hartcodierten, sicherheitsrelevanten Konstanten](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Unsachgemäße Einschränkung der externen XML-Entitätsreferenz](https://cwe.mitre.org/data/definitions/611.html)

[Sensibles CWE-614-Cookie in HTTPS-Sitzung ohne „sicheres“ Attribut](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Fehlende benutzerdefinierte Fehlerseite](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Unsachgemäße Einschränkung rekursiver Entitätsreferenzen in DTDs („XML-Entitätserweiterung“)](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Zulässige domänenübergreifende Richtlinie mit nicht vertrauenswürdigen Domänen](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensibles Cookie ohne „HttpOnly“-Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Kategorie A6 – Sicherheitsfehlkonfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET-Fehlkonfiguration: Unsachgemäße Modellvalidierung](https://cwe.mitre.org/data/definitions/1174.html)
