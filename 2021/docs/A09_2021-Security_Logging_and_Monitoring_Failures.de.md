---
source: "https://owasp.org/Top10/09_2021-Security_Logging_and_Monitoring_Failures/"
title:  "A09:2021 – Unzureichendes Logging und Sicherheitsmonitoring"
id:     "A09:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".9" -%}
#A09:2021 – Unzureichendes Logging und Sicherheitsmonitoring ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id= id, name="Fehler beim Logging und Monitoring", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.10") }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Sicherheitsprotokollierung und -überwachung belegten in der Top-10-Community-Umfrage Platz 3 und stiegen somit etwas von der zehnten Position in der OWASP Top 10 2017. Die Protokollierung und Überwachung können schwierig zu testen sein, da sie oft Interviews oder die Frage nach der Erkennung von Angriffen während eines Penetrationstests erfordern. Es gibt nicht viele CVE/CVSS-Daten für diese Kategorie, aber das Erkennen von und Reagieren auf Eindringlinge spielt eine wichtige Rolle. Allerdings kann dies sehr hilfreich für die Verantwortlichkeit, die Transparenz, die Alarmierung bei Vorfällen und die Forensik sein. 
Diese Kategorie geht über *CWE-778 Insufficient Logging* hinaus und umfasst 
*CWE-117 Improper Output Neutralization for Logs*,
*CWE-223 Omission of Security-relevant Information* und 
*CWE-532* *Insertion of Sensitive Information into Log File*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Wieder in den OWASP Top 10 2021 soll diese Kategorie bei der Erkennung, Eskalation und Reaktion auf laufende Angriffe helfen. Ohne Protokollierung und
Überwachung können Angriffe nicht erkannt werden. Unzureichende Protokollierung,
Erkennung, Überwachung und aktive Reaktion treten permanent auf:
- Prüfbare Ereignisse wie Anmeldungen, fehlgeschlagene Anmeldungen und Transaktionen mit hohem Wert werden nicht protokolliert.

- Warnungen und Fehler erzeugen keine, unzureichende oder ungenaue Einträge im Logging

- Logs von Anwendungen und APIs werden nicht auf verdächtige Aktivitäten überwacht.

 - Logs werden nur lokal gespeichert.

- Angemessene Schwellwerte für Alarme und Maßnahmen zur Eskalation sind nicht vorhanden oder nicht wirksam.

- Penetrationstests und Scans durch DAST-Tools (Dynamic Application Security Testing) (wie OWASP ZAP) lösen keine Warnmeldungen aus.

- Die Anwendung kann Angriffe nicht erkennen, eskalieren oder Alarm schlagen, wenn sie tatsächlich oder beinahe unmittelbar erfolgen.

Sie sind anfällig für Informationslecks, wenn Sie Protokollierungs- und Alarm-Ereignisse für einen Benutzer oder einen Angreifer sichtbar machen (siehe [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Je nach dem Risiko der Anwendung sollten Entwickler einige oder alle der folgenden Maßnahmen ergreifen:

- Stellen Sie sicher, dass alle Anmelde-, Zugriffskontroll- und serverseitigen Eingabevalidierungen Fehler mit ausreichendem Benutzerkontext protokolliert werden können, um verdächtige oder böswillige Konten zu identifizieren und ausreichend lange eine spätere forensische Analyse zu ermöglichen.

- Stellen Sie sicher, dass die Logs in einem Format erstellt werden, das von Log-Management Lösungen leicht verarbeitet werden können.

- Stellen Sie sicher, dass die Protokolldaten korrekt kodiert sind, um Injections oder Angriffe auf die Protokollierungs- oder Überwachungssysteme zu verhindern.

- Stellen Sie sicher, dass hochwertige Transaktionen über einen Prüfpfad mit Integritätskontrollen verfügen , um Manipulationen oder Löschungen zu verhindern, wie z. B. "append-only Datenbanktabellen oder ähnliches.

- DevSecOps-Teams sollten eine effektive Überwachung und Alarmierung einrichten so dass verdächtige Aktivitäten schnell erkannt werden und darauf reagiert wird.

- Erstellen oder übernehmen Sie einen Reaktions- und Wiederherstellungsplan für Zwischenfälle, z. B. National Institute of Standards and Technology (NIST) 800-61r2 oder neuer.

Es gibt sowohl kommerzielle als auch Open-Source-Frameworks zum Schutz von Anwendungen wie das OWASP ModSecurity Core Rule Set, und Open-Source-Log Korrelations-Software, wie Elasticsearch, Logstash, Kibana (ELK)
Stack, die benutzerdefinierte Dashboards und Warnmeldungen bereitstellen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Der Betreiber der Website eines Anbieters von Kinderkrankenversicherungen konnte das Eindringen in das System aufgrund mangelnder Überwachung und Protokollierung nicht erkennen. Eine externe Partei informierte den Krankenversicherungsanbieter, dass ein Angreifer auf Tausende sensibler Gesundheitsdaten von mehr als 3,5 Millionen Kindern zugegriffen und diese verändert hatte. Eine Überprüfung nach dem Vorfall ergab, dass die Entwickler der Website wesentliche Schwachstellen nicht behoben hatten. Da das System weder protokolliert noch überwacht wurde, könnte die Datenschutzverletzung bereits seit 2013, also seit mehr als sieben Jahren, im Gange sein.

**Szenario #2:** Bei einer großen indischen Fluggesellschaft kam es zu einer unbefugten Zugriffsnahme auf personenbezogene Daten von Millionen von Fluggästen, die mehr als zehn Jahre lang gespeichert waren, darunter Pass- und Kreditkartendaten. Die Datenpanne trat bei einem externen Cloud-Hosting-Anbieter auf, der die Fluggesellschaft nach einiger Zeit über die Verletzung informierte.

**Szenario #3:** Bei einer großen europäischen Fluggesellschaft kam es zu einem meldepflichtigen Verstoß gegen die DSGVO. Der Verstoß wurde Berichten zufolge durch Sicherheitsschwachstellen in Zahlungsanwendungen verursacht, die von Angreifern ausgenutzt wurden, die mehr als 400.000 Zahlungsdatensätze von Kunden abfingen. Die Fluggesellschaft wurde daraufhin von der Datenschutzbehörde mit einer Geldstrafe von 20 Millionen Pfund belegt.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3." ~ "9", osib=osib) }} <!-- [OWASP Proaktive Kontrollen: Protokollierung und Überwachung implementieren](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html) -->
- {{ osib_link(link="osib.owasp.asvs.4-0." ~ "7", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V7 Logging and Monitoring](https://owasp.org/www-project-application-security-verification-standard) -->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.8.1", osib=osib) }} <!--- war: [OWASP-Testleitfaden: Testen auf detaillierte Fehlercodes](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Logging Vocabulary", osib=osib) }} <!-- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Logging", osib=osib) }} <!-- [OWASP Spickzettel: Protokollierung](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.nist.csrc.sp.1800-11", osib=osib) }} <!--- [Datenintegrität: Wiederherstellung nach Ransomware und anderen zerstörerischen Ereignissen](https://csrc.nist.gov/publications/detail/sp/1800-11/final) -->
- {{ osib_link(link="osib.nist.csrc.sp.1800-25", osib=osib) }} <!--- [Datenintegrität: identifizierung und Schutz von Vermögenswerten vor Ransomware und anderen zerstörerischen Ereignissen](https://csrc.nist.gov/publications/detail/sp/1800-25/final) -->
- {{ osib_link(link="osib.nist.csrc.sp.1800-26", osib=osib) }} <!--- [Datenintegrität: Erkennen und Reagieren auf Ransomware und andere zerstörerische Ereignisse](https://csrc.nist.gov/publications/detail/sp/1800-26/final) -->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.117", doc="", osib=osib) }} <!-- [CWE-117: Unsachgemäße Ausgabeneutralisierung für Protokolle](https://cwe.mitre.org/data/definitions/117.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.223", doc="", osib=osib) }} <!-- [CWE-223: Auslassung sicherheitsrelevanter Informationen](https://cwe.mitre.org/data/definitions/223.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.532", doc="", osib=osib) }} <!-- [CWE-532: Einfügen vertraulicher Informationen in die Protokolldatei](https://cwe.mitre.org/data/definitions/532.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.778", doc="", osib=osib) }} <!-- [CWE-778: Unzureichende Protokollierung](https://cwe.mitre.org/data/definitions/778.html) -->
