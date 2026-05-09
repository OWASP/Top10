# A08:2025 Software or Data Integrity Failures ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Hintergrund. 

Software or Data Integrity Failures verbleibt auf Platz #8, mit einer leichten, klarstellenden Namensänderung von „Software *und* Data Integrity Failures". Diese Kategorie konzentriert sich auf das Versäumnis, Vertrauensgrenzen einzuhalten und die Integrität von Software, Code und Datenartefakten auf einer niedrigeren Ebene als Software Supply Chain Failures zu überprüfen. Der Schwerpunkt liegt auf Annahmen in Bezug auf Software-Updates und kritische Daten, ohne die Integrität zu überprüfen. Zu den erwähnenswerten Common Weakness Enumerations (CWEs) gehören *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, *CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes* und *CWE-502: Deserialization of Untrusted Data*.


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
   <td>14
   </td>
   <td>8.98%
   </td>
   <td>2.75%
   </td>
   <td>78.52%
   </td>
   <td>45.49%
   </td>
   <td>7.11
   </td>
   <td>4.79
   </td>
   <td>501,327
   </td>
   <td>3,331
   </td>
  </tr>
</table>



## Beschreibung. 

Software- und Datenintegritätsfehler beziehen sich auf Code und Infrastruktur, die keinen Schutz dagegen bieten, dass ungültiger oder nicht vertrauenswürdiger Code oder Daten als vertrauenswürdig und gültig behandelt werden. Ein Beispiel hierfür ist, wenn eine Anwendung auf Plugins, Bibliotheken oder Module aus nicht vertrauenswürdigen Quellen, Repositories und Content Delivery Networks (CDNs) angewiesen ist. Eine unsichere CI/CD-Pipeline kann das Potenzial für unbefugten Zugriff, bösartigen Code oder Systemkompromittierung bieten. Ein weiteres Beispiel ist eine CI/CD-Pipeline, die Code oder Artefakte aus nicht vertrauenswürdigen Quellen bezieht und/oder diese vor der Verwendung nicht überprüft (z. B. durch Prüfung der Signatur oder eines ähnlichen Mechanismus).
Schließlich enthalten viele Anwendungen heute eine automatische Update-Funktion, bei der Updates ohne ausreichende Integritätsprüfung heruntergeladen und auf die zuvor vertrauenswürdige Anwendung angewendet werden. Angreifende könnten ihre eigenen Updates hochladen, die dann auf alle Installationen verbreitet und ausgeführt werden. Ein weiteres Beispiel besteht darin, dass Objekte oder Daten in eine Struktur kodiert oder serialisiert werden, die Angreifende sehen und ändern können, und die durch eine unsichere Deserialisierung verwundbar sind.


## Prävention und Gegenmaßnahmen. 



* Verwenden Sie digitale Signaturen oder ähnliche Mechanismen, um sicherzustellen, dass die Software oder Daten aus der erwarteten Quelle stammen und nicht verändert wurden.
* Stellen Sie sicher, dass Bibliotheken und Abhängigkeiten, wie z. B. npm oder Maven, ausschließlich vertrauenswürdige Repositories nutzen. Wenn Sie ein höheres Risikoprofil haben, sollten Sie in Erwägung ziehen, ein internes Repository zu hosten, das als vertrauenswürdig gilt und überprüft wurde.
* Stellen Sie sicher, dass es einen Überprüfungsprozess für Code- und Konfigurationsänderungen gibt, um das Risiko zu minimieren, dass bösartiger Code oder bösartige Konfigurationen in Ihre Software-Pipeline eingeschleust werden
* Stelle Sie sicher, dass Ihre CI/CD-Pipeline über eine angemessene Trennung, Konfiguration und Zugriffskontrolle verfügt, um die Integrität des Codes zu gewährleisten, der den Build- und Bereitstellungsprozess durchläuft.
* Stellen Sie sicher, dass unsignierte oder unverschlüsselte serialisierte Daten nicht von nicht vertrauenswürdigen Clients empfangen und anschließend ohne eine Form der Integritätsprüfung oder digitalen Signatur verwendet werden, um Manipulation oder ein erneutes Einspielen der serialisierten Daten zu erkennen.


## Beispielhafte Angriffsszenarien. 

**Szenario Nr. 1 – Einbindung von Web-Funktionalität aus einer nicht vertrauenswürdigen Quelle:** Ein Unternehmen nutzt einen externen Dienstleister für Support-Funktionalität. Der Bequemlichkeit halber wurde ein DNS-Mapping von `myCompany.SupportProvider.com` auf `support.myCompany.com` eingerichtet. Das bedeutet, dass alle Cookies – einschließlich Authentifizierungs-Cookies –, die für die Domain `myCompany.com` gesetzt wurden, nun an den Support-Anbieter gesendet werden. Jede Person mit Zugang zur Infrastruktur des Support-Anbieters kann die Cookies aller Nutzenden stehlen, die `support.myCompany.com` besucht haben, und einen Session-Hijacking-Angriff durchführen.

**Szenario Nr. 2 – Update ohne Signierung:** Viele Heimrouter, Set-Top-Boxen, Geräte-Firmware und andere Systeme überprüfen Updates nicht anhand signierter Firmware. Unsignierte Firmware wird zunehmend zum Angriffsziel und es ist davon auszugehen, dass sich dies weiter verschlechtern wird. Dies ist besonders problematisch, da es häufig keinen Mechanismus zur Behebung gibt, außer einen Fix in einer zukünftigen Version bereitzustellen und zu warten, bis ältere Versionen nicht mehr verwendet werden.

**Szenario Nr. 3 – Verwendung eines Pakets aus einer nicht vertrauenswürdigen Quelle:** Eine Entwicklerin bzw. ein Entwickler hat Schwierigkeiten, die aktualisierte Version eines benötigten Pakets zu finden, und lädt es daher nicht vom regulären, vertrauenswürdigen Paketmanager herunter, sondern von einer Website im Internet. Das Paket ist nicht signiert, sodass keine Möglichkeit besteht, die Integrität sicherzustellen. Das Paket enthält bösartigen Code.

**Szenario Nr. 4 – Unsichere Deserialisierung:** Eine React-Anwendung ruft eine Reihe von Spring-Boot-Microservices auf. Als funktionale Programmierende haben sie versucht, ihren Code unveränderlich zu gestalten. Die gewählte Lösung besteht darin, den Nutzerzustand zu serialisieren und mit jeder Anfrage hin- und herzuschicken. Eine angreifende Person erkennt die Java-Objektsignatur „rO0" (in Base64) und nutzt den [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner), um Remote Code Execution auf dem Anwendungsserver zu erlangen.

## Referenzen.

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)


## Liste der zugeordneten CWEs

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

* [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

* [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

* [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)

* [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)

* [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

* [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

* [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

* [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
