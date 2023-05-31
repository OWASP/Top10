# A08:2021 – Software- und Datenintegritätsfehler ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 6.94                 | 7.94                | 75.04%       | 45.35%       | 47,972            | 1,152      |

## Überblick

Eine neue Kategorie für 2021 konzentriert sich auf Annahmen im Zusammenhang mit Software-Updates, kritischen Daten und CI/CD-Pipelines ohne Überprüfung der Integrität. Eine der am höchsten gewichteten Auswirkungen aus den Daten des Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS). Zu den bemerkenswerten Common Weakness Enumerations (CWEs) gehören *CWE-829: Einbeziehung von Funktionalität aus der nicht vertrauenswürdigen Kontrollsphäre*, *CWE-494: Herunterladen von Code ohne Integritätsprüfung* und *CWE-502: Deserialisierung nicht vertrauenswürdiger Daten*.

## Beschreibung

Software- und Datenintegritätsfehler beziehen sich auf Code und Infrastruktur, die keinen Schutz vor Integritätsverletzungen bieten. Ein Beispiel hierfür ist, wenn eine Anwendung auf Plugins, Bibliotheken oder Module aus nicht vertrauenswürdigen Quellen, Repositorys und Content Delivery Networks (CDNs) angewiesen ist. Eine unsichere CI/CD-Pipeline kann das Potenzial für unbefugten Zugriff, bösartigen Code oder eine Systemkompromittierung mit sich bringen. Schließlich verfügen viele Anwendungen mittlerweile über eine Funktion zur automatischen Aktualisierung, bei der Aktualisierungen ohne ausreichende Integritätsprüfung heruntergeladen und auf die zuvor vertrauenswürdige Anwendung angewendet werden. Angreifer könnten möglicherweise ihre eigenen Updates hochladen, um sie zu verteilen und auf allen Installationen auszuführen. Ein weiteres Beispiel ist die Verschlüsselung oder Serialisierung von Objekten oder Daten in einer Struktur, die ein Angreifer sehen und ändern kann und die anfällig für unsichere Deserialisierung ist.

## Gegenmaßnahmen

- Verwenden Sie digitale Signaturen oder ähnliche Mechanismen, um zu überprüfen, ob die Software oder Daten von der erwarteten Quelle stammen und nicht verändert wurden.

– Stellen Sie sicher, dass Bibliotheken und Abhängigkeiten wie npm oder Maven vertrauenswürdige Repositorys nutzen. Wenn Sie ein höheres Risikoprofil haben, sollten Sie erwägen, ein internes, nachweislich funktionierendes und überprüftes Repository zu hosten.

- Stellen Sie sicher, dass ein Software-Supply-Chain-Sicherheitstool wie OWASP Dependency Check oder OWASP CycloneDX verwendet wird, um zu überprüfen, ob Komponenten keine bekannten Schwachstellen enthalten

- Stellen Sie sicher, dass es einen Überprüfungsprozess für Code- und Konfigurationsänderungen gibt, um das Risiko zu minimieren, dass schädlicher Code oder schädliche Konfigurationen in Ihre Software-Pipeline eingeschleust werden.

– Stellen Sie sicher, dass Ihre CI/CD-Pipeline über eine ordnungsgemäße Trennung, Konfiguration und Zugriffskontrolle verfügt, um die Integrität des Codes sicherzustellen, der die Build- und Bereitstellungsprozesse durchläuft.

– Stellen Sie sicher, dass unsignierte oder unverschlüsselte serialisierte Daten nicht ohne irgendeine Form von Integritätsprüfung oder digitaler Signatur an nicht vertrauenswürdige Clients gesendet werden, um Manipulationen oder Wiedergabe der serialisierten Daten zu erkennen

## Beispielangriffsszenarien

**Szenario Nr. 1 Update ohne Signierung:** Viele Heimrouter, Set-Top-Boxen, Geräte-Firmware und andere überprüfen die Sicherheit von Updates nicht anhand der Signatur der Firmware. Unsignierte Firmware ist ein wachsendes Ziel für Angreifer und wird voraussichtlich nur noch schlimmer werden. Dies ist ein großes Problem, da es oft keinen anderen Mechanismus zur Behebung gibt, als das Problem in einer zukünftigen Version zu beheben und darauf zu warten, dass frühere Versionen veraltet sind.

**Szenario Nr. 2 bösartiges SolarWinds-Update**: Es ist bekannt, dass Nationalstaaten Update-Mechanismen angreifen, wobei ein aktueller bemerkenswerter Angriff der SolarWinds-Orion-Angriff war. Das Unternehmen, das die Software entwickelt, verfügte über sichere Build- und Update-Integritätsprozesse. Diese konnten jedoch unterwandert werden, und das Unternehmen verteilte mehrere Monate lang ein äußerst gezieltes bösartiges Update an mehr als 18.000 Organisationen, von denen etwa 100 betroffen waren. Dies ist einer der weitreichendsten und bedeutsamsten Verstöße dieser Art in der Geschichte.

**Szenario Nr. 3 Unsichere Deserialisierung:** Eine React-Anwendung ruft eine Reihe von Spring Boot-Mikrodiensten auf. Als funktionale Programmierer versuchten sie sicherzustellen, dass ihr Code unveränderlich ist. Die Lösung, die sie gefunden haben, besteht darin, den Benutzerstatus zu serialisieren und ihn bei jeder Anfrage hin und her zu übergeben. Ein Angreifer bemerkt die Java-Objektsignatur „rO0“ (in Base64) und nutzt das Java Serial Killer-Tool, um eine Remotecodeausführung auf dem Anwendungsserver zu erreichen.

## Referenzen

- \[OWASP Cheat Sheet: Software Supply Chain Security\](In Kürze erhältlich)

- \[OWASP Cheat Sheet: Sichere Erstellung und Bereitstellung\](In Kürze verfügbar)

- [OWASP-Spickzettel: Infrastruktur als Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Deserialisierung]( <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

- [SAFECode Software Integrity Controls]( https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

- [Ein „schlimmster Albtraum“-Cyberangriff: Die unerzählte Geschichte des SolarWinds-Hacks](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story -of-the-solarwinds-hack>)

- [CodeCov Bash Uploader-Kompromiss](https://about.codecov.io/security-update)

- [DevOps sichern von Julien Vehent](https://www.manning.com/books/securing-devops)

## Liste der zugeordneten CWEs

[CWE-345 Unzureichende Überprüfung der Datenauthentizität](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Fehlende Unterstützung für Integritätsprüfung](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Nicht vertrauenswürdiger Suchpfad](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494-Download von Code ohne Integritätsprüfung](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialisierung nicht vertrauenswürdiger Daten](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Abhängigkeit von Cookies ohne Validierung und Integritätsprüfung](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Abhängigkeit von Cookies ohne Validierung und Integritätsprüfung in einer Sicherheitsentscheidung](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Einbeziehung der Funktionalität aus der nicht vertrauenswürdigen Kontrollsphäre](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Einbeziehung von Webfunktionen aus einer nicht vertrauenswürdigen Quelle](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Unsachgemäß kontrollierte Änderung dynamisch bestimmter Objektattribute](https://cwe.mitre.org/data/definitions/915.html)
