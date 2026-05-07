# A03:2025 Software Supply Chain Failures ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Hintergrund.

Diese Kategorie belegte den ersten Platz in der Community-Umfrage zum Top 10, wobei genau 50 % der Teilnehmenden sie auf Rang 1 setzten. Seit ihrem ersten Erscheinen im Top 10 von 2013 als „A9 – Using Components with Known Vulnerabilities" hat sich der Risikobereich ausgeweitet und umfasst nun alle Lieferkettenfehler, nicht nur solche mit bekannten Schwachstellen. Trotz dieses erweiterten Umfangs sind Lieferkettenfehler mit nur 11 Common Vulnerability and Exposures (CVEs), die die zugehörigen CWEs aufweisen, nach wie vor schwer zu identifizieren. Werden sie jedoch getestet und in den beigetragenen Daten gemeldet, weist diese Kategorie mit 5,19 % die höchste durchschnittliche Vorfallsrate aller Kategorien auf. Die relevanten CWEs sind *CWE-477: Use of Obsolete Function, CWE-1104: Use of Unmaintained Third Party Components*, CWE-1329: *Reliance on Component That is Not Updateable*, und *CWE-1395: Dependency on Vulnerable Third-Party Component*.


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
   <td>6
   </td>
   <td>9.56%
   </td>
   <td>5.72%
   </td>
   <td>65.42%
   </td>
   <td>27.47%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>



## Beschreibung.

Fehler in der Software-Lieferkette sind Störungen oder sonstige Kompromittierungen im Prozess der Erstellung, Verteilung oder Aktualisierung von Software. Sie werden häufig durch Schwachstellen oder böswillige Änderungen in Code, Werkzeugen oder anderen Abhängigkeiten von Drittanbietern verursacht, auf die das System angewiesen ist.

Sie sind wahrscheinlich verwundbar, wenn:

* Sie die Versionen aller verwendeten Komponenten (sowohl client- als auch serverseitig) nicht sorgfältig verfolgen. Dies umfasst sowohl direkt verwendete Komponenten als auch verschachtelte (transitive) Abhängigkeiten.
* Die Software verwundbar, nicht mehr unterstützt oder veraltet ist. Dies betrifft das Betriebssystem, Web-/Anwendungsserver, Datenbankmanagementsysteme (DBMS), Anwendungen, APIs und alle Komponenten, Laufzeitumgebungen und Bibliotheken.
* Sie keine regelmäßigen Schwachstellen-Scans durchführen und keine Sicherheitsbulletins zu den von Ihnen verwendeten Komponenten abonniert haben.
* Sie keinen Änderungsmanagementprozess oder keine Nachverfolgung von Änderungen in Ihrer Lieferkette haben, einschließlich der Nachverfolgung von IDEs, IDE-Erweiterungen und -Updates, Änderungen am Code-Repository Ihrer Organisation, Sandboxen, Image- und Bibliotheks-Repositories sowie der Art und Weise, wie Artefakte erstellt und gespeichert werden usw. Jeder Teil Ihrer Lieferkette sollte dokumentiert werden, insbesondere Änderungen.
* Sie nicht jeden Teil Ihrer Lieferkette abgesichert haben, mit besonderem Fokus auf Zugangskontrolle und die Anwendung des Prinzips der minimalen Rechtevergabe.
* Ihre Lieferkettensysteme keine Aufgabentrennung aufweisen. Keine einzelne Person sollte in der Lage sein, Code zu schreiben und ihn bis in die Produktion zu befördern, ohne die Aufsicht eines anderen Menschen.
* Komponenten aus nicht vertrauenswürdigen Quellen, über jeden Teil des Tech-Stacks hinweg, in Produktionsumgebungen verwendet werden oder diese beeinflussen können.
* Sie die zugrunde liegende Plattform, Frameworks und Abhängigkeiten nicht risikobasiert und zeitnah aktualisieren oder upgraden. Dies tritt häufig in Umgebungen auf, in denen das Patchen eine monatliche oder vierteljährliche Aufgabe unter Änderungskontrolle ist, wodurch Organisationen tagelangen oder monatelangen unnötigen Risiken ausgesetzt sind, bevor Schwachstellen behoben werden.
* Softwareentwickler die Kompatibilität aktualisierter, upgegradeter oder gepatchter Bibliotheken nicht testen.
* Sie die Konfigurationen jedes Teils Ihres Systems nicht absichern (siehe [A02:2025-Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
* Ihre CI/CD-Pipeline eine schwächere Sicherheit aufweist als die Systeme, die sie erstellt und bereitstellt, insbesondere wenn sie komplex ist.


## Prävention und Gegenmaßnahmen.

Es sollte ein Patch-Management-Prozess vorhanden sein, der:



* Zentral das Software Bill of Materials (SBOM) Ihrer gesamten Software erstellt und verwaltet.
* Nicht nur Ihre direkten Abhängigkeiten, sondern auch deren (transitive) Abhängigkeiten usw. nachverfolgt.
* Die Angriffsfläche durch Entfernen ungenutzter Abhängigkeiten, unnötiger Funktionen, Komponenten, Dateien und Dokumentation reduziert.
* Die Versionen sowohl client- als auch serverseitiger Komponenten (z. B. Frameworks, Bibliotheken) und deren Abhängigkeiten kontinuierlich mit Tools wie OWASP Dependency Track, OWASP Dependency Check, retire.js usw. inventarisiert.
* Quellen wie Common Vulnerability and Exposures (CVE), National Vulnerability Database (NVD) und [Open Source Vulnerabilities (OSV)](https://osv.dev/) kontinuierlich auf Schwachstellen in den von Ihnen verwendeten Komponenten überwacht. Nutzen Sie Software-Kompositionsanalyse, Software-Supply-Chain- oder sicherheitsorientierte SBOM-Tools, um den Prozess zu automatisieren. Abonnieren Sie Warnungen zu Sicherheitsschwachstellen in den von Ihnen verwendeten Komponenten.
* Komponenten ausschließlich von offiziellen (vertrauenswürdigen) Quellen über sichere Verbindungen bezieht. Bevorzugen Sie signierte Pakete, um die Wahrscheinlichkeit zu verringern, eine modifizierte, bösartige Komponente einzubinden (siehe [A08:2025-Software and Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
* Bewusst wählt, welche Version einer Abhängigkeit verwendet wird, und nur bei Bedarf aktualisiert.
* Bibliotheken und Komponenten überwacht, die nicht mehr gewartet werden oder keine Sicherheits-Patches für ältere Versionen bereitstellen. Falls kein Patchen möglich ist, sollten Sie eine Migration zu einer Alternative in Betracht ziehen. Falls auch das nicht möglich ist, ziehen Sie den Einsatz eines virtuellen Patches in Betracht, um das entdeckte Problem zu überwachen, zu erkennen oder dagegen zu schützen.
* Ihre CI/CD-, IDE- und anderen Entwickler-Tools regelmäßig aktualisiert.
* Vermeidet, Updates gleichzeitig auf alle Systeme auszurollen. Nutzen Sie gestaffelte Rollouts oder Canary-Deployments, um das Risiko zu begrenzen, falls ein vertrauenswürdiger Anbieter kompromittiert wird.


Es sollte ein Änderungsmanagementprozess oder ein Tracking-System vorhanden sein, um Änderungen an folgenden Bereichen zu verfolgen:

* CI/CD-Einstellungen (alle Build-Tools und Pipelines)
* Code-Repositories
* Sandbox-Bereiche
* Entwickler-IDEs
* SBOM-Tooling und erstellte Artefakte
* Protokollierungssysteme und Protokolle
* Drittanbieter-Integrationen, z. B. SaaS
* Artefakt-Repositories
* Container-Registries


Folgende Systeme sollten abgesichert werden, einschließlich der Aktivierung von MFA und der Einschränkung von IAM:

* Ihr Code-Repository (dazu gehört das Nicht-Einchecken von Secrets, der Schutz von Branches und Backups)
* Entwickler-Workstations (regelmäßiges Patchen, MFA, Monitoring und mehr)
* Ihr Build-Server & CI/CD (Aufgabentrennung, Zugangskontrolle, signierte Builds, umgebungsspezifische Secrets, manipulationssichere Protokolle und mehr)
* Ihre Artefakte (Integrität durch Herkunftsnachweis, Signierung und Zeitstempel sicherstellen, Artefakte befördern statt für jede Umgebung neu zu bauen, sicherstellen, dass Builds unveränderlich sind)
* Infrastructure as Code (wie jeder Code verwaltet, einschließlich der Verwendung von PRs und Versionskontrolle)

Jede Organisation muss einen fortlaufenden Plan zur Überwachung, Priorisierung und Anwendung von Updates oder Konfigurationsänderungen für die gesamte Lebensdauer der Anwendung oder des Portfolios sicherstellen.


## Beispielhafte Angriffsszenarien.

**Szenario Nr. 1:** Ein vertrauenswürdiger Anbieter wird mit Malware kompromittiert, was dazu führt, dass Ihre Computersysteme beim Upgrade kompromittiert werden. Das bekannteste Beispiel hierfür ist wahrscheinlich:



* Die SolarWinds-Kompromittierung von 2019, die zur Kompromittierung von ~18.000 Organisationen führte. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Szenario Nr. 2:** Ein vertrauenswürdiger Anbieter wird so kompromittiert, dass er sich nur unter einer bestimmten Bedingung böswillig verhält.



* Der Bybit-Diebstahl von 1,5 Milliarden US-Dollar im Jahr 2025 wurde durch [einen Supply-Chain-Angriff auf Wallet-Software](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/) verursacht, der nur ausgeführt wurde, wenn die Ziel-Wallet verwendet wurde.

**Szenario Nr. 3:** Der [`Shai-Hulud`-Supply-Chain-Angriff](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) im Jahr 2025 war der erste erfolgreiche sich selbst verbreitende npm-Wurm. Angreifer platzierten bösartige Versionen populärer Pakete, die ein Post-Install-Skript verwendeten, um sensible Daten zu sammeln und in öffentliche GitHub-Repositories zu exfiltrieren. Die Malware erkannte auch npm-Token in der Opferumgebung und nutzte diese automatisch, um bösartige Versionen aller zugänglichen Pakete zu veröffentlichen. Der Wurm erreichte über 500 Paketversionen, bevor er von npm gestoppt wurde. Dieser Supply-Chain-Angriff war fortschrittlich, schnell ausbreitend und schädlich, und indem er auf Entwicklermaschinen abzielte, zeigte er, dass Entwickler selbst nun zu den Hauptzielen von Supply-Chain-Angriffen geworden sind.

**Szenario Nr. 4:** Komponenten laufen typischerweise mit denselben Berechtigungen wie die Anwendung selbst, sodass Fehler in einer beliebigen Komponente erhebliche Auswirkungen haben können. Solche Fehler können versehentlich (z. B. Codefehler) oder absichtlich (z. B. eine Hintertür in einer Komponente) sein. Einige Beispiele für entdeckte ausnutzbare Komponentenschwachstellen sind:

* CVE-2017-5638, eine Struts-2-Schwachstelle zur Remote-Code-Ausführung, die die Ausführung beliebigen Codes auf dem Server ermöglicht, wurde für erhebliche Datenschutzverletzungen verantwortlich gemacht.
* CVE-2021-44228 („Log4Shell"), eine Apache-Log4j-Zero-Day-Schwachstelle zur Remote-Code-Ausführung, wurde für Ransomware-, Kryptomining- und andere Angriffskampagnen verantwortlich gemacht.


## Referenzen.

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## Liste der zugeordneten CWEs

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
