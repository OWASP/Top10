# A09:2025 Unzureichendes Sicherheitslogging und Alarmierung ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## Hintergrund. 

„Unzureichendes Sicherheitslogging und Alarmierung“ behält seinen Platz auf Rang 9. Der Name dieser Kategorie wurde leicht geändert, um die Alarmierungsfunktion hervorzuheben, die erforderlich ist, um bei relevanten Protokollereignissen Maßnahmen auszulösen. Diese Kategorie wird in den Daten stets unterrepräsentiert sein und wurde von den Teilnehmern der Community-Umfrage bereits zum dritten Mal auf einen Platz in der Liste gewählt. Diese Kategorie ist unglaublich schwer zu testen und in den CVE/CVSS-Daten nur minimal vertreten (nur 723 CVEs); sie kann jedoch erhebliche Auswirkungen auf die Transparenz, die Benachrichtigung bei Vorfällen und die Forensik haben. Diese Kategorie umfasst Probleme mit *properly handling output encoding to log files (CWE-117), inserting sensitive data into log files (CWE-532), und insufficient logging (CWE-778).*


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
   <td>5
   </td>
   <td>11.33%
   </td>
   <td>3.91%
   </td>
   <td>85.96%
   </td>
   <td>46.48%
   </td>
   <td>7.19
   </td>
   <td>2.65
   </td>
   <td>260,288
   </td>
   <td>723
   </td>
  </tr>
</table>



## Description. 

Ohne Protokollierung und Überwachung lassen sich Angriffe und Sicherheitsverletzungen nicht erkennen, und ohne Warnmeldungen ist es sehr schwierig, bei einem Sicherheitsvorfall schnell und effektiv zu reagieren. Eine unzureichende Protokollierung, kontinuierliche Überwachung, Erkennung und Warnmeldung zur Einleitung aktiver Maßnahmen kommt immer dann vor, wenn:


* Nachvollziehbare Ereignisse, wie Anmeldungen, fehlgeschlagene Anmeldungen und wertvolle Transaktionen, werden nicht protokolliert (zum Beispiel nur erfolgreiche Anmeldungen protokollieren, nicht aber fehlgeschlagene Versuche).
* Warnungen und Fehler erzeugen keine, unangemessene oder unklare Log-Einträge.
* Die Integrität der Protokolle ist nicht ausreichend vor Manipulationen geschützt.
* Die Logs von Anwendungen und APIs werden nicht auf verdächtige Aktivitäten überwacht.
* Protokolle werden nur lokal gespeichert und nicht angemessen gesichert.
* Geeignete Schwellenwerte für Warnmeldungen und Eskalationsprozesse für Gegenmaßnahmen sind nicht vorhanden oder nicht wirksam. Benachrichtigungen werden nicht innerhalb einer angemessenen Frist empfangen oder geprüft.
* Penetrationstests und Scans durch DAST-Tools (Dynamic Application Security Testing) (wie Burp oder ZAP) lösen keine Alarme aus.
* Die Anwendung kann Angriffe weder in Echtzeit noch nahezu in Echtzeit erkennen, eskalieren oder Alarm schlagen.
* Sie sind anfällig für den Verlust sensibler Informationen, wenn Sie Protokollierungs- und Warnereignisse für einen Benutzer oder einen Angreifer sichtbar machen (siehe [A01:2025-Broken Access Control](A01_2025-Broken_Access_Control.md)) oder wenn Sie sensible Informationen protokollieren, die nicht protokolliert werden sollten (wie z. B. personenbezogene Daten oder geschützte Gesundheitsdaten).
* Sie sind anfällig für Injection oder Angriffe auf die Protokollierungs- oder Überwachungssysteme, wenn Protokolldaten nicht encoded sind.
* Der Anwendung fehlen Fehler und andere Ausnahmebedingungen oder sie behandelt diese falsch, sodass das System nicht erkennt, dass ein Fehler aufgetreten ist, und daher nicht protokollieren kann, dass ein Problem vorlag.
* Es fehlen angemessene „Anwendungsfälle“ für die Ausgabe von Warnmeldungen oder diese sind veraltet, um eine besondere Situation zu erkennen.
* Zu viele Fehlalarme machen es unmöglich, wichtige Warnmeldungen von unwichtigen zu unterscheiden, was dazu führt, dass sie zu spät oder gar nicht erkannt werden (physische Überlastung des SOC-Teams).
* Erkannte Warnmeldungen können nicht korrekt verarbeitet werden, da das Handbuch für den Anwendungsfall unvollständig, veraltet oder nicht vorhanden ist.

## Prävention und Gegenmaßnahmen.

Je nach dem Risiko der Anwendung sollten Entwickler einige oder alle der folgenden Maßnahmen ergreifen:

* Sicherstellen, dass alle Anmeldevorgänge, Zugriffskontrollen und Fehler bei der serverseitigen Eingabeüberprüfung mit ausreichendem Sitzungskontext der Nutzenden erfasst werden, um verdächtige oder böswillige Anwendende zu identifizieren und ausreichend lange gespeichert werden, um eine spätere forensische Analyse zu ermöglichen.
* Stellen Sie sicher, dass jeder Teil Ihrer App, der eine Sicherheitsprüfung enthält, protokolliert wird, unabhängig davon, ob diese erfolgreich ist oder fehlschlägt.
* Stellen Sie sicher, dass die Protokolle in einem Format gespeichert werden, das von Protokollmanagement Lösungen leicht verarbeitet werden kann.
* Es sollte sichergestellt werden, dass die Protokolldaten korrekt encoded werden, sodass Injection-Angriffe oder Angriffe auf Logging- oder Überwachungssysteme verhindert werden.
* Es soll sichergestellt sein, dass alle Transaktionen einen Prüfpfad mit Integritätskontrollen aufweisen um Manipulationen oder Löschungen zu verhindern, z. B. durch Datenbanktabellen, die nur erweitert werden können, oder ähnliches.
* Stelle sicher, dass alle Transaktionen, bei denen ein Fehler auftritt, zurückgesetzt und neu gestartet werden. Wähle stets die „Fail-Closed“-Strategie.
* Wenn sich Ihre Anwendung oder deren Nutzer verdächtig verhalten, geben Sie eine Warnmeldung aus. Erstellen Sie zu diesem Thema Leitlinien für Ihre Entwickler, damit diese entsprechende Maßnahmen in den Code integrieren können, oder erwerben Sie ein System, das diese Aufgabe übernimmt.
* DevSecOps-Teams sollten eine effektive Überwachung und Alarmierung einrichten, sodass verdächtige Aktivitäten vom Security Operations Center (SOC)-Team schnell erkannt und darauf reagiert werden kann.
* Fügen Sie „Honeytokens“ als Fallen für Angreifer in Ihre Anwendung ein, z. B. in die Datenbank, in Daten oder als echte und/oder technische Benutzeridentität. Da diese im normalen Geschäftsbetrieb nicht verwendet werden, erzeugt jeder Zugriff Protokolldaten, die nahezu ohne Fehlalarme gemeldet werden können.
* Verhaltensanalysen und KI-Unterstützung könnten optional als zusätzliche Technik eingesetzt werden, um die Fehlalarmquote bei Warnmeldungen zu senken.
* Erstellen oder übernehmen Sie einen Notfallplan für die Reaktion auf Vorfälle und für die Wiederherstellung, wie z. B. dem Leitfaden des National Institute of Standards and Technology (NIST) 800-61r2 oder neuer. Bringen Sie Ihren Softwareentwicklern bei, wie Angriffe auf Anwendungen und Vorfälle aussehen, damit sie diese melden können.

Es gibt kommerzielle und Open-Source-Frameworks zum Schutz von Anwendungen wie das OWASP ModSecurity Core Rule Set, und Open-Source-Log correlation software, wie Elasticsearch, Logstash, Kibana (ELK) Stack, die individuelle Dashboards und Warnmeldungen bereitstellen. Es gibt auch kommerzielle Observability-Tools, mit denen Sie nahezu in Echtzeit auf Angriffe reagieren oder diese abwehren können.



## Beispielhafte Angriffsszenarien. 

**Szenario 1:**  Der Betreiber der Website eines Anbieters von Kinderkrankenversicherungen konnte das Eindringen in das System aufgrund mangelnder Überwachung und Protokollierung nicht erkennen. Eine externe Partei informierte den Krankenversicherungsanbieter, dass Angreifende auf Tausende der mehr als 3,5 Millionen sensiblen Gesundheitsdaten der Kinder zugegriffen und diese verändert haben. Eine Überprüfung nach dem Vorfall ergab, dass die Entwickler der Website wesentliche Schwachstellen nicht behoben hatten. Da es weder eine Protokollierung noch eine Überwachung des Systems gab, bestand die Datenlücke möglicherweise bereits seit 2013, also über einen Zeitraum von mehr als sieben Jahren.

**Szenario #2:** Bei einer größeren indischen Fluggesellschaft kam es zu einer Datenpanne, die mehr als zehn Jahre lang personenbezogene Daten von Millionen von Fluggästen betraf, einschließlich Reisepass- und Kreditkartendaten. Die Datenpanne trat bei einem externen Cloud-Hosting-Anbieter auf, der die Fluggesellschaft nach einiger Zeit über die Lücke informierte.

**Szenario #3:** Bei einer großen europäischen Fluggesellschaft kam es zu einem meldepflichtigen Verstoß gegen die DSGVO. Der Verstoß wurde Berichten zufolge durch Sicherheitsschwachstellen in Zahlungsanwendungen verschuldet, die von Angreifenden ausgenutzt wurden, die mehr als 400.000 Zahlungsdatensätze von Kunden abfingen. Die Fluggesellschaft wurde daraufhin von der Datenschutzbehörde mit einer Geldstrafe von 20 Millionen Pfund belegt.


## Referenzen.

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## Liste der zugeordneten CWEs

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
