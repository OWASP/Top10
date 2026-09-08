# A02:2025 Sicherheitsrelevante Fehlkonfiguration ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## Hintergrund.

Die Kategorie rückt auf von Platz 5 in der vorherigen Ausgabe: 100 % der Anwendungen wurden auf irgendeine Form von Fehlkonfiguration getestet, mit einer durchschnittlichen Inzidenzrate von 3 % und über 719.000 Vorkommen einer Common Weakness Enumeration (CWE) in dieser Risikokategorie. Angesichts der zunehmenden Verlagerung hin zu hoch konfigurierbarer Software ist es nicht verwunderlich, dass diese Kategorie aufsteigt. Bemerkenswerte enthaltene CWEs sind *CWE-16 Configuration* und *CWE-611 Unproper Restriction of XML External Entity Reference (XXE)*.

Eine sicherheitsrelevante Fehlkonfiguration liegt vor, wenn ein System, eine Anwendung oder ein Cloud-Dienst aus sicherheitstechnischer Sicht falsch eingerichtet ist, wodurch Schwachstellen entstehen.


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
   <td>16
   </td>
   <td>27.70%
   </td>
   <td>3.00%
   </td>
   <td>100.00%
   </td>
   <td>52.35%
   </td>
   <td>7.96
   </td>
   <td>3.97
   </td>
   <td>719,084
   </td>
   <td>1,375
   </td>
  </tr>
</table>



## Beschreibung.

Die Anwendung besitzt möglicherweise Schwachstellen, wenn Folgendes zutrifft:
* Mangelhafte Sicherheitshärtung des Anwendungsstacks oder ungeeignet konfigurierte Berechtigungen auf Cloud-Diensten.
* Nicht benötigte Features sind aktiviert oder installiert (z. B. unnötige Ports, Dienste, Seiten, Accounts oder Rechte).
* Standardkonten und -passwörter sind aktiviert bzw. unverändert.
* Die Fehlerbehandlung gibt Stack-Traces oder andere interne technische Fehlermeldungen an Anwender:innen preis.
* Für aktualisierte Systeme sind die neuesten Sicherheitsfeatures deaktiviert oder nicht sicher konfiguriert.
* Die Sicherheitseinstellungen in den Anwendungsservern und -frameworks (z. B. Struts, Spring, ASP.NET), Bibliotheken, Datenbanken etc. sind nicht auf sichere Werte gesetzt.
* Der Server sendet keine Sicherheits-Header oder -Direktiven, bzw. diese sind nicht sicher konfiguriert.
* Die Software ist veraltet oder verwundbar (siehe [A06:2025-Unsichere oder veraltete Komponenten](A06_2025-Vulnerable_and_Outdated_Components.md)).

Ohne einen abgestimmten und reproduzierbaren Prozess zur sicheren Konfiguration sind Systeme einem höheren Risiko ausgesetzt!


## Prävention und Gegenmaßnahmen.

Es sollten sichere Installationsprozesse implementiert werden, darunter:

* Ein wiederholbarer Härtungsprozess, welcher die schnelle und einfache Bereitstellung zusätzlicher Umgebungen, die entsprechend abgesichert sind, ermöglicht. Entwicklungs-, Qualitätssicherungs- und Produktionsumgebungen sollten alle identisch konfiguriert sein, wobei in jeder Umgebung unterschiedliche Zugangsdaten verwendet werden sollten. Dieser Prozess sollte automatisiert werden, um den Aufwand für die Einrichtung einer neuen sicheren Umgebung zu minimieren.
* Eine minimale Plattform ohne unnötige Funktionen, Komponenten, Dokumentation oder Beispiele: Entfernen Sie Funktionen und Frameworks die Sie nicht verwenden oder installieren Sie diese erst gar nicht.
* Überprüfen und Aktualisieren der Konfigurationen, die für alle Sicherheitshinweise, Updates und Patches im Rahmen des Patch-Verwaltungsprozesses geeignet sind (siehe [A03:2025 – Schwachstellen in der Software-Lieferkette](A03_2025-Software_Supply_Chain_Failures.md)). Überprüfen Sie die Cloud-Speicherberechtigungen (z. B. S3-Bucket-Berechtigungen).


## Beispielhafte Angriffsszenarien.

**Szenario Nr. 1:** Der Anwendungsserver wird mit Beispielanwendungen geliefert, die nicht vom Produktionsserver entfernt wurden. Diese Beispielanwendungen weisen bekannte Schwachstellen auf, die Angreifer:innen nutzen, um den Server zu gefährden. Angenommen, eine dieser Anwendungen ist die Admin-Konsole und die Standardkonten wurden nicht geändert. In diesem Fall meldet sich die/der Angreifer:in mit einem Standardkennwort an und übernimmt die Kontrolle.

**Szenario Nr. 2:** Die Directory Listings wurden nicht auf dem Server deaktiviert. Angreifer:innen entdecken, dass Verzeichnisse einfach aufgelistet werden können. Die/Der Angreifer:in findet die kompilierten Java-Klassen und lädt sie herunter, dekompiliert sie und betreibt Reverse Engineering, um den Code anzuzeigen. Dies ermöglicht das Findet eines schwerwiegenden Fehlers in der Zugriffskontrolle in der Anwendung.

**Szenario Nr. 3:** Die Konfiguration des Anwendungsservers ermöglicht die Rückgabe detaillierter Fehlermeldungen an Anwender:innen, wie z. B. Stack-Traces. Dadurch werden möglicherweise vertrauliche Informationen oder zugrunde liegende Fehler wie Komponentenversionen offengelegt, die als angreifbar bekannt sind.

**Szenario Nr. 4:** Ein Cloud-Dienstanbieter (CSP) gewährt standardmäßig Freigabeberechtigungen zum Internet und ermöglicht dadurch Zugriff auf sensible Daten in der Cloud.


## Referenzen.

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration


## Liste der zugeordneten CWEs

* [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)

* [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

* [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

* [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

* [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

* [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

* [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

* [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

* [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

* [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

* [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

* [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

* [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
