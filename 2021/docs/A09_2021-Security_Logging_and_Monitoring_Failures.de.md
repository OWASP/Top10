# A09:2021 – Sicherheitsprotokollierungs- und Überwachungsfehler ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Beurteilungskriterien

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Bezug / Kontext / Auswertung

Sicherheitsprotokollierung und -überwachung stammen aus der Top-10-Community-Umfrage (Nr. 3) und stiegen leicht auf vom zehnten Platz in den OWASP Top 10 2017. Protokollierung und Überwachung können schwierig zu testen sein und erfordern oft Interviews oder die Prüfung, ob während eines Penetration Tests Angriffe erkannt wurden. Für diese Kategorie gibt es nicht viele CVE/CVSS-Daten, aber die Erkennung und Reaktion auf Vorfälle ist von entscheidender Bedeutung. Außerdem kann es große Auswirkungen auf die Verantwortlichkeit, Sichtbarkeit, Alarmierung und die Forensik haben. Diese Kategorie geht über *CWE-778 Insufficient Logging* hinaus und umfasst außerdem *CWE-117 Improper Output Neutralization for Logs*, *CWE-223 Omission of Security-relevant Information* und *CWE-532* *Insertion of Sensitive Information into Log File*.

## Beschreibung

Erneut in den OWASP Top 10 2021 soll diese Kategorie dabei helfen, aktive Verstöße zu erkennen, zu eskalieren und darauf zu reagieren. Ohne Protokollierung und Überwachung können Sichereheitsverstöße nicht erkannt werden. Es kommt in vielfältiger Weise zu unzureichender Protokollierung, Erkennung, Überwachung und fehlender Reaktion:

– Auditierbare Ereignisse, wie Anmeldungen, fehlgeschlagene Anmeldungen und Finanztransaktionen von hohem Wert, werden nicht protokolliert.

- Warnungen und Fehler erzeugen keine, unzureichende oder uneindeutige Protokoll-Einträge.

- Protokolle von Anwendungen und Schnittstellen werden nicht ausreichend hinsichtlich verdächtiger Aktivitäten überwacht.

- Protokolle werden nur lokal gespeichert.

- Geeignete Alarmierungs-Schwellen und Eskalations-Prozesse als Reaktion auf (potentielle) Vorfälle liegen nicht vor oder sind nicht wirksam.

- Penetrationstests und Scans durch DAST-Tools (Dynamic Application Security Testing) (wie OWASP ZAP) lösen keine Alarme aus.

- Die eingesetzten Überwachungsverfahren sind nicht in der Lage aktive Angriffe zu erkennen und in Echtzeit oder nahezu Echtzeit Alarm auszulösen.

Wenn Ihre Systeme Protokollierungs- und Alarmierungs-Nachrichten Benutzern oder Angreifern preisgeben, kann dies zum Abfluss von Daten führen (siehe [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## Prävention und Gegenmaßnahmen

Abhängig vom Risiko der Anwendung sollten Entwickler einige oder alle der folgenden Kontrollen implementieren:

- Stellen Sie sicher, dass alle erfolglosen Login- und Zugriffs-Versuche und Fehler bei der serverseitigen Eingabevalidierung mit aussagekräftigem Benutzerkontext protokolliert werden, um verdächtige oder schädliche Accounts zu identifizieren. Halten Sie diese Informationen ausreichend lange vor, um auch später forensische Analysen vorzunehmen zu können.

– Stellen Sie sicher, dass Protokollierungen in einem Format erstellt werden, die eine einfache Verarbeitung durch zentrale Protokollanalyse- und -managementwerkzeuge ermöglicht.

- Stellen Sie sicher, dass die Protokolldaten korrekt encodiert sind, um Injections oder Angriffe auf die Protokollierungs- oder Überwachungssysteme zu verhindern.

- Speichern Sie für wichtige Transaktionen Audit-Trails mit Integritätsschutz, um Verfälschung oder ein Löschen zu verhindern, z.B. durch Einsatz von Datenbanktabellen, die nur das Anhängen von Datensätzen zulassen.

- DevSecOps-Teams sollten wirksame Monitoring- und Alarmierungs-Verfahren einrichten, damit verdächtige Aktivitäten zeitnah entdeckt und bearbeitet werden.

- Etablieren Sie Notfall- und Wiederherstellungspläne für Sicherheitsvorfälle, z.B. auf Basis von NIST 800-61 rev 2.

Es gibt kommerzielle und Open-Source-Frameworks für den Schutz Ihrer Anwendungen, wie das OWASP ModSecurity Core Rule Set und Open-Source-Logging-Software, wie den Elasticsearch-, Logstash- und Kibana-Stack (ELK), die über benutzerdefinierte Dashboards und Warnungen verfügen.

## Beispielhafte Angriffsszenarien

**Szenario Nr. 1:** Der Website-Betreiber einer Kinderkrankenversicherung konnte aufgrund mangelnder Überwachung und Protokollierung einen Angriff nicht feststellen. Ein Dritter informierte den Krankenversicherungsanbieter darüber, dass ein Angreifer auf tausende sensible Gesundheitsakten zugegriffen und diese verändert hatte. Eine Überprüfung nach dem Vorfall ergab, dass die Website-Entwickler wesentlichen Schwachstellen nicht behoben hatten. Da es keine Protokollierung oder Überwachung des Systems gab, könnte die Datenschutzverletzung seit 2013 angedauert haben, über einen Zeitraum von mehr als sieben Jahren.

**Szenario Nr. 2:** Bei einer großen indischen Fluggesellschaft kam es zu einem Datenverlust, der personenbezogene Daten von Millionen von Passagieren aus mehr als zehn Jahren betraf, darunter Pass- und Kreditkartendaten. Der Datenverstoß ereignete sich bei einem externen Cloud-Hosting-Anbieter, der die Fluggesellschaft nach einiger Zeit über den Verstoß informierte.

**Szenario Nr. 3:** Eine große europäische Fluggesellschaft erlitt einen meldepflichtigen Verstoß gegen die DSGVO. Der Verstoß wurde Berichten zufolge durch Sicherheitslücken in Zahlungsanwendungen verursacht, die von Angreifern ausgenutzt wurden und mehr als 400.000 Zahlungsdatensätze von Kunden abgegriffen haben. Die Datenschutzbehörde verhängte daraufhin eine Geldstrafe von 20 Millionen Pfund gegen die Fluggesellschaft.

## Referenzen

- [OWASP Proactive Controls: Protokollierung und Überwachung implementieren](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

- [OWASP Application Security Verification Standard: V7 Logging and Monitoring](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP-Testleitfaden: Testen auf detaillierten Fehlercode](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

- [OWASP-Spickzettel: Anwendungsprotokollierungsvokabular](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

- [OWASP-Spickzettel: Protokollierung](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [Datenintegrität: Wiederherstellung nach Ransomware und anderen zerstörerischen Ereignissen](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

- [Datenintegrität: Identifizieren und Schützen von Vermögenswerten vor Ransomware und anderen zerstörerischen Ereignissen](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

- [Datenintegrität: Ransomware und andere zerstörerische Ereignisse erkennen und darauf reagieren](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Liste der zugeordneten CWEs

[CWE-117 Unsachgemäße Ausgabeneutralisierung für Protokolle](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Weglassung sicherheitsrelevanter Informationen](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Einfügen vertraulicher Informationen in die Protokolldatei](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Unzureichende Protokollierung](https://cwe.mitre.org/data/definitions/778.html)
