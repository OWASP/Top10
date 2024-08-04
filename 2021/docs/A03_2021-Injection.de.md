h---
source: "https://owasp.org/Top10/A03_2021-Injection/"
title:  "A03:2021 – Injection"
id:     "A03:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".3" -%}
#A03:2021 – Injection     ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}  {{ osib_anchor(osib=osib, id=id, name="Injection", lang=lang, source=source, parent=parent, merged_from=[extra.osib.document ~ ".2017.1", extra.osib.document ~ ".2017.7"] ) }}

## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09 %             | 3.37 %              | 7.25                 | 7.15                | 94.04 %       | 47.90 %       | 274,228           | 32,078     |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Die Injection rutscht von der ersten auf die dritte Position ab. 94 % der Anwendungen wurden auf irgendeine Form der Injection getestet, mit einer maximalen Häufigkeit von 19,09 %, einer durchschnittlichen Häufigkeit von 3,37 % und über 274.000 Vorkommnissen. Zu den wichtigsten Common Weakness Enumerations (CWEs) zählen *CWE-79: Cross-Site Scripting*, *CWE-89: SQL Injection* und *CWE-73: External Control of File Name or Path*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Eine Anwendung ist für diesen Angriff anfällig, wenn:

- Daten, die von Mitgliedern stammen, von der Anwendung nicht ausreichend validiert, gefiltert oder bereinigt werden.

- Dynamische Anfragen oder nicht-parametrisierte Aufrufe ohne ein dem Kontext entsprechendes Escaping direkt einem Interpreter übergeben werden.

- Bösartige Daten innerhalb von ORM („Object-Relational Mapping“)-Suchparametern genutzt werden können, um vertrauliche Datensätze von Dritten zu extrahieren.

- Bösartige Daten direkt oder als Teil zusammengesetzter dynamischer Querys verwendet werden. Die SQL-Abfragen oder Befehle beinhalten die Struktur und die schädlichen Daten in den dynamischen Querys, Befehlen oder Stored Procedures

Zu den häufigeren Injection Arten gehören SQL, NoSQL, OS-Befehle, Object Relational Mapping (ORM), LDAP und Expression Language (EL) oder Object Graph Navigation Library (OGNL). Das Grundkonzept eines Injection-Angriffs ist für alle Interpreter gleich. Ein Quellcode Review ist die beste Methode, um Injection-Schwachstellen in Anwendungen zu finden. Ausführliches (ggf. automatisiertes) Testen aller Parameter und Variablen, Header-, URL-, Cookies-, JSON-, SOAP- und XML-Eingaben wird dringend empfohlen. Statische (SAST, Quellcode-Ebene), dynamische (DAST, laufende Anwendung) und interaktive (IAST, Mischform aus statisch und dynamisch) Test-Werkzeuge können von Organisationen für ihre CI/CD-Pipeline genutzt werden, um neue Schwachstellen noch vor einer möglichen Auslieferung in Produktivsysteme zu identifizieren.

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": Prävention und Gegenmaßnahmen", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Eine konsequente Trennung von Daten, Suchanfragen und Befehlen ist für die Vermeidung von Injection-Angriffen unerlässlich:

- Die bevorzugte Methode ist die Verwendung einer sicheren API, die die Verwendung des Interpreters vollständig vermeidet, eine parametrisierte Schnittstelle bereitstellt oder in objektrelationale Mapping-Tools (ORMs) umwandelt. 
<br/> **Anmerkung:** Stored Procedures können - auch parametrisiert - immer noch SQL-Injections ermöglichen, wenn PL/SQL oder T-SQL Anfragen und Eingabedaten konkateniert oder mit EXECUTE IMMEDIATE oder exec() ausgeführt werden.

- Für die serverseitige Eingabe-Validierung empfiehlt sich die Nutzung eines Positivlisten(“Whitelist”)-Ansatzes. Dies ist i. A. kein vollständiger Schutz, da viele Anwendungen Sonderzeichen z. B. in Textfelder oder APIs für mobile Anwendungen benötigen.

- Für jede noch verbliebene dynamische Query müssen Sonderzeichen für den jeweiligen Interpreter mit der richtigen Escape-Syntax entschärft werden. <br/> **Anmerkung:** Ein Escaping von SQL-Bezeichnern, wie z. B. die Namen von Tabellen oder Spalten usw. ist nicht möglich.
Falls Mitglieder solche Bezeichner selbst eingeben können, so ist dies durchaus gefährlich. Dies ist eine übliche Schwachstelle bei Software, die Reports aus einer Datenbank erstellt.

- SQL-Querys sollten LIMIT oder andere SQL-Controls verwenden, um den möglichen Massen-Abfluss von Daten zu verhindern.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Eine Anwendung nutzt ungeprüfte Eingabedaten für den Zusammenbau der folgenden verwundbaren SQL-Abfrage:
```
String query = "SELECT \* FROM Accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Szenario Nr. 2:** Auch das blinde Vertrauen in Frameworks kann zu Querys führen, die ganz analog zu obigem Beispiel verwundbar sind (z. B. Hibernate Query Language (HQL)):
```
Abfrage HQLQuery = session.createQuery("FROM Accounts WHERE custID='" + request.getParameter("id") + "'");
```

In beiden Fällen können Angreifende den ‘id’-Parameter im Browser ändern und sendet: „UNION SLEEP(10);--“. Zum Beispiel:
```
http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Hierdurch wird die Logik der Anfrage verändert, so dass alle Datensätze der Tabelle „accounts“ ohne Einschränkung auf einen Kunden zurückgegeben werden.
Gefährlichere Attacken wären z. B. das Ändern oder Löschen von Daten oder das Aufrufen von Stored Procedures.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3." ~ "3", osib=osib) }} <!-- [OWASP Proactive Controls: Sicherer Datenbankzugriff](https://owasp.org/ www-project-proactive-controls/v3/en/c3-secure-database) -->
- {{ osib_link(link="osib.owasp.asvs.4-0.5", osib=osib) }} <!--- [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www -project-application-security-verification-standard) --->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.7.5", osib=osib) }}, <!-- [OWASP-Testhandbuch: SQL-Injection](https://owasp.org/www -project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) --> {{ osib_link(link="osib.owasp.wstg.4-2.4.7.12", doc= "", osib=osib) }}, <!-- [Command Injection ](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12 -Testing_for_Command_Injection) -->
{{ osib_link(link="osib.owasp.wstg.4-2.4.7.5.7", doc="", osib=osib) }} <!-- [ORM-Injektion ](https://owasp.org/ www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Injection Prevention", osib=osib) }} <!-- [OWASP Spickzettel: Injektionsprävention](https://cheatsheetseries.owasp. org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "SQL Injection Prevention", osib=osib) }} <!-- [OWASP-Spickzettel: SQL-Injection-Prävention](https://cheatsheetseries. owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Injection Prevention in Java", osib=osib) }} <!-- [OWASP Cheat Sheet: Injection Prevention in Java](https:// (cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Query Parameterization", osib=osib) }} <!-- [OWASP Spickzettel: Abfrageparametrisierung](https://cheatsheetseries.owasp. org/cheatsheets/Query_Parameterization_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.owasp.oat.0.14", osib=osib) }} <!--- [OWASP Automatisierte Bedrohungen für Webanwendungen – OAT-014](https://owasp.org/www -project-automated-threats-to-web-applications/) --->
- {{ osib_link(link="osib.portswigger.kb.issues.serversidetemplateinjection", doc="osib.portswigger.kb.issues", osib=osib) }} <!--- [PortSwigger: Serverseitige Vorlageninjektion ](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection) --->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.20", doc="", osib=osib) }} <!-- [CWE-20: Unsachgemäße Eingabevalidierung](https://cwe.mitre.org/data/definitions/20.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.74", doc="", osib=osib) }} <!-- [CWE-74: Unsachgemäße Neutralisierung spezieller Elemente in der Ausgabe, die von einer nachgeschalteten Komponente verwendet wird ('Injektion')](https://cwe.mitre.org/data/definitions/74.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.75", doc="", osib=osib) }} <!-- [CWE-75: Fehler beim Bereinigen spezieller Elemente in einer anderen Ebene (Spezielle Elementinjektion )](https://cwe.mitre.org/data/definitions/75.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.77", doc="", osib=osib) }} <!-- [CWE-77: Unsachgemäße Neutralisierung spezieller Elemente, die in einem Befehl verwendet werden ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.78", doc="", osib=osib) }} <!-- [CWE-78: Unsachgemäße Neutralisierung spezieller Elemente, die in einem OS-Befehl verwendet werden ('OS Befehlsinjektion')](https://cwe.mitre.org/data/definitions/78.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.79", doc="", osib=osib) }} <!-- [CWE-79: Unsachgemäße Neutralisierung von Eingaben während der Webseitengenerierung („Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.80", doc="", osib=osib) }} <!-- [CWE-80: Unsachgemäße Neutralisierung skriptbezogener HTML-Tags in einer Webseite (Grundlegendes XSS)](https://cwe.mitre.org/data/definitions/80.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.83", doc="", osib=osib) }} <!-- [CWE-83: Unsachgemäße Neutralisierung von Skripten in Attributen auf einer Webseite](https://cwe.mitre.org/data/definitions/83.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.87", doc="", osib=osib) }} <!-- [CWE-87: Unsachgemäße Neutralisierung der alternativen XSS-Syntax](https://cwe.mitre.org/data/definitions/87.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.88", doc="", osib=osib) }} <!-- [CWE-88: Unsachgemäße Neutralisierung von Argumenttrennzeichen in einem Befehl („Argument Injection“ )](https://cwe.mitre.org/data/definitions/88.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.89", doc="", osib=osib) }} <!-- [CWE-89: Unsachgemäße Neutralisierung spezieller Elemente, die in einem SQL-Befehl verwendet werden ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.90", doc="", osib=osib) }} <!-- [CWE-90: Unsachgemäße Neutralisierung spezieller Elemente, die in einer LDAP-Abfrage verwendet werden ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.91", doc="", osib=osib) }} <!-- [CWE-91: XML-Injection (auch bekannt als Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.93", doc="", osib=osib) }} <!-- [CWE-93: Unsachgemäße Neutralisierung von CRLF-Sequenzen ('CRLF-Injection')](https://cwe.mitre.org/data/definitions/93.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.94", doc="", osib=osib) }} <!-- [CWE-94: Unsachgemäße Kontrolle der Codegenerierung („Code-Injection“)] (https://cwe.mitre.org/data/definitions/94.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.95", doc="", osib=osib) }} <!-- [CWE-95: Unsachgemäße Neutralisierung von Anweisungen in dynamisch ausgewertetem Code ('Eval Injection“ )](https://cwe.mitre.org/data/definitions/95.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.96", doc="", osib=osib) }} <!-- [CWE-96: Unsachgemäße Neutralisierung von Anweisungen in statisch gespeichertem Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.97", doc="", osib=osib) }} <!-- [CWE-97: Unsachgemäße Neutralisierung von Server-Side Includes (SSI) innerhalb eines Webs Seite](https://cwe.mitre.org/data/definitions/97.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.98", doc="", osib=osib) }} <!-- [CWE-98: Unsachgemäße Kontrolle des Dateinamens für die Include/Require-Anweisung im PHP-Programm ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.99", doc="", osib=osib) }} <!-- [CWE-99: Unsachgemäße Kontrolle von Ressourcenkennungen („Ressourceninjektion“)](https://cwe.mitre.org/data/definitions/99.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.100", doc="", osib=osib) }} <!-- [CWE-100: Veraltet: War ein Allheilmittel für Eingabevalidierungsprobleme](https://cwe.mitre.org/data/definitions/100.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.113", doc="", osib=osib) }} <!-- [CWE-113: Unsachgemäße Neutralisierung von CRLF-Sequenzen in HTTP-Headern (HTTP Response Splitting)](https://cwe.mitre.org/data/definitions/113.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.116", doc="", osib=osib) }} <!-- [CWE-116: Unsachgemäße Kodierung oder Escapezeichen der Ausgabe](https://cwe mitre.org/data/definitions/116.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.138", doc="", osib=osib) }} <!-- [CWE-138: Unsachgemäße Neutralisierung spezieller Elemente](https://cwe.mitre.org/data/definitions/138.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.184", doc="", osib=osib) }} <!-- [CWE-184: Unvollständige Liste unzulässiger Eingaben](https://cwe.mitre.org/data/definitions/184.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.470", doc="", osib=osib) }} <!-- [CWE-470: Verwendung extern gesteuerter Eingaben zur Auswahl von Klassen oder Code (' Unsichere Reflexion')](https://cwe.mitre.org/data/definitions/470.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.471", doc="", osib=osib) }} <!-- [CWE-471: Änderung angenommener unveränderlicher Daten (MAID)](https://cwe.mitre.org/data/definitions/471.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.564", doc="", osib=osib) }} <!-- [CWE-564: SQL-Injection: Ruhezustand](https://cwe.mitre.org/data/definitions/564.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.610", doc="", osib=osib) }} <!-- [CWE-610: Extern gesteuerter Verweis auf eine Ressource in einer anderen Sphäre](https://cwe.mitre.org/data/definitions/610.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.643", doc="", osib=osib) }} <!-- [CWE-643: Unsachgemäße Neutralisierung von Daten in XPath-Ausdrücken („XPath-Injection“) ](https://cwe.mitre.org/data/definitions/643.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.644", doc="", osib=osib) }} <!-- [CWE-644: Unsachgemäße Neutralisierung von HTTP-Headern für die Skriptsyntax](https://cwe.mitre.org/data/definitions/644.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.652", doc="", osib=osib) }} <!-- [CWE-652: Unsachgemäße Neutralisierung von Daten in XQuery-Ausdrücken („XQuery-Injection“) ](https://cwe.mitre.org/data/definitions/652.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.917", doc="", osib=osib) }} <!-- [CWE-917: Unsachgemäße Neutralisierung spezieller Elemente, die in einer Ausdruckssprachenanweisung verwendet werden (' Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html) -->
