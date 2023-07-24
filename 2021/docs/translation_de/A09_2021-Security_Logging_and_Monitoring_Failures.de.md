---
source: "https://owasp.org/Top10/09_2021-Security_Logging_and_Monitoring_Failures/“
title: "A09:2021 – Fehler beim Logging und Monitoring“
id: "A09:2021“
lang:	"de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".9" -%}
#A09:2021 – Fehler beim Logging und Monitoring ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id= id, name="Fehler beim Logging und Monitoring", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.10") }}


## Faktoren {{ osib_anchor(osib=osib~".factors", id=id~"-factors", name=title~":Factors", aussehen=appearance, source=source~"#"~id, parent= osib) }}

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Sicherheitsprotokollierung und -überwachung stammen aus der Top-10-Community-Umfrage (Nr. 3) und liegen damit leicht über dem zehnten Platz in den OWASP Top 10 2017. Protokollierung und Überwachung können schwierig zu testen sein und erfordern oft Interviews oder die Frage, ob während eines Eindringens Angriffe erkannt wurden prüfen. Für diese Kategorie gibt es nicht viele CVE/CVSS-Daten, aber die Erkennung und Reaktion auf Verstöße ist von entscheidender Bedeutung. Dennoch kann es große Auswirkungen auf die Verantwortlichkeit, Sichtbarkeit, Alarmierung von Vorfällen und die Forensik haben. Diese Kategorie geht über *CWE-778 Unzureichende Protokollierung* hinaus und umfasst *CWE-117 Unsachgemäße Ausgabeneutralisierung für Protokolle*, *CWE-223 Weglassen sicherheitsrelevanter Informationen* und *CWE-532* *Einfügung vertraulicher Informationen in die Protokolldatei*.

## Ist die Anwendung verwundbar {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Wieder bei den OWASP Top 10 2021 dabei soll diese Kategorie dabei helfen, aktive Verstöße zu erkennen, zu eskalieren und darauf zu reagieren. Ohne Protokollierung und Überwachung können Verstöße nicht erkannt werden. Es kommt jederzeit zu unzureichender Protokollierung, Erkennung, Überwachung und aktiver Reaktion:
– Überprüfbare Ereignisse wie Anmeldungen, fehlgeschlagene Anmeldungen und Transaktionen mit hohem Wert werden nicht protokolliert.

- Warnungen und Fehler erzeugen keine, unzureichende oder unklare Protokollmeldungen.

- Protokolle von Anwendungen und APIs werden nicht auf verdächtige Aktivitäten überwacht.

- Protokolle werden nur lokal gespeichert.

- Angemessene Warnschwellen und Reaktionseskalationsprozesse sind nicht vorhanden oder wirksam.

- Penetrationstests und Scans durch DAST-Tools (Dynamic Application Security Testing) (wie OWASP ZAP) lösen keine Warnungen aus.

- Die Anwendung kann aktive Angriffe nicht in Echtzeit oder nahezu in Echtzeit erkennen, eskalieren oder darauf hinweisen.

Sie sind anfällig für Informationslecks, wenn Sie Protokollierungs- und Warnereignisse für einen Benutzer oder einen Angreifer sichtbar machen (siehe [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## Wie kann ich das verhindern {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Abhängig vom Risiko der Anwendung sollten Entwickler einige oder alle der folgenden Kontrollen implementieren:

– Stellen Sie sicher, dass alle Anmelde-, Zugriffskontroll- und serverseitigen Eingabevalidierungsfehler mit ausreichendem Benutzerkontext protokolliert werden können, um verdächtige oder böswillige Konten zu identifizieren, und ausreichend lange aufbewahrt werden können, um eine verzögerte forensische Analyse zu ermöglichen.

– Stellen Sie sicher, dass Protokolle in einem Format generiert werden, das von Protokollverwaltungslösungen problemlos verarbeitet werden kann.

- Stellen Sie sicher, dass die Protokolldaten korrekt codiert sind, um Einschleusungen oder Angriffe auf die Protokollierungs- oder Überwachungssysteme zu verhindern.

- Stellen Sie sicher, dass hochwertige Transaktionen über einen Prüfpfad mit Integritätskontrollen verfügen, um Manipulationen oder Löschungen zu verhindern, z. B. Datenbanktabellen, die nur angehängt werden können, oder ähnliches.

- DevSecOps-Teams sollten eine wirksame Überwachung und Alarmierung einrichten, damit verdächtige Aktivitäten schnell erkannt und darauf reagiert werden.

- Erstellen oder übernehmen Sie einen Plan zur Reaktion auf Vorfälle und zur Wiederherstellung, z. B. National Institute of Standards and Technology (NIST) 800-61r2 oder höher.

Es gibt kommerzielle und Open-Source-Anwendungsschutz-Frameworks wie das OWASP ModSecurity Core Rule Set und Open-Source-Protokollkorrelationssoftware wie den Elasticsearch-, Logstash- und Kibana-Stack (ELK), die über benutzerdefinierte Dashboards und Warnungen verfügen.

## Beispiel-Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Der Website-Betreiber eines Kinderkrankenversicherungsanbieters konnte aufgrund mangelnder Überwachung und Protokollierung keinen Verstoß feststellen. Eine externe Partei informierte den Krankenversicherungsanbieter darüber, dass ein Angreifer auf Tausende sensible Gesundheitsakten von mehr als 3,5 Millionen Kindern zugegriffen und diese verändert hatte. Eine Überprüfung nach dem Vorfall ergab, dass die Website-Entwickler keine wesentlichen Schwachstellen behoben hatten. Da es keine Protokollierung oder Überwachung des Systems gab, könnte die Datenschutzverletzung seit 2013 andauern, also über einen Zeitraum von mehr als sieben Jahren.

**Szenario Nr. 2:** Bei einer großen indischen Fluggesellschaft kam es zu einem Datenverstoß, der personenbezogene Daten von Millionen von Passagieren im Wert von mehr als zehn Jahren betraf, darunter Pass- und Kreditkartendaten. Der Datenverstoß ereignete sich bei einem externen Cloud-Hosting-Anbieter, der die Fluggesellschaft nach einiger Zeit über den Verstoß informierte.

**Szenario Nr. 3:** Eine große europäische Fluggesellschaft erlitt einen meldepflichtigen Verstoß gegen die DSGVO. Der Verstoß wurde Berichten zufolge durch Sicherheitslücken in Zahlungsanwendungen verursacht, die von Angreifern ausgenutzt wurden und mehr als 400.000 Zahlungsdatensätze von Kunden abgegriffen haben. Die Datenschutzbehörde verhängte daraufhin eine Geldstrafe von 20 Millionen Pfund gegen die Fluggesellschaft.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3." ~ "9", osib=osib) }} <!-- [OWASP Proaktive Kontrollen: Protokollierung und Überwachung implementieren](https://owasp.org /www-project-proactive-controls/v3/en/c9-security-logging.html) ->
- {{ osib_link(link="osib.owasp.asvs.4-0." ~ "7", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V7 Logging and Monitoring](https:/ /owasp.org/www-project-application-security-verification-standard) ->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.8.1", osib=osib) }} <!--- war: [OWASP-Testleitfaden: Testen auf detaillierte Fehlercodes](https:// owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code) --->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Logging Vocabulary", osib=osib) }} <!-- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp .org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Logging", osib=osib) }} <!-- [OWASP Spickzettel: Protokollierung](https://cheatsheetseries.owasp.org/ cheatsheets/Logging_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.nist.csrc.sp.1800-11", osib=osib) }} <!--- [Datenintegrität: Wiederherstellung nach Ransomware und anderen zerstörerischen Ereignissen](https://csrc .nist.gov/publications/detail/sp/1800-11/final) --->
- {{ osib_link(link="osib.nist.csrc.sp.1800-25", osib=osib) }} <!--- [Datenintegrität: identifizierung und Schutz von Vermögenswerten vor Ransomware und anderen zerstörerischen Ereignissen](https: //csrc.nist.gov/publications/detail/sp/1800-25/final) --->
- {{ osib_link(link="osib.nist.csrc.sp.1800-26", osib=osib) }} <!--- [Datenintegrität: Erkennen und Reagieren auf Ransomware und andere zerstörerische Ereignisse](https:/ /csrc.nist.gov/publications/detail/sp/1800-26/final) --->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.117", doc="", osib=osib) }} <!-- [CWE-117: Unsachgemäße Ausgabeneutralisierung für Protokolle](https://cwe. mitre.org/data/definitions/117.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.223", doc="", osib=osib) }} <!-- [CWE-223: Auslassung sicherheitsrelevanter Informationen](https://cwe .mitre.org/data/definitions/223.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.532", doc="", osib=osib) }} <!-- [CWE-532: Einfügen vertraulicher Informationen in die Protokolldatei](https:// cwe.mitre.org/data/definitions/532.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.778", doc="", osib=osib) }} <!-- [CWE-778: Unzureichende Protokollierung](https://cwe.mitre.org /data/definitions/778.html) ->
