# A03:2021 – Injektion ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 7.25                 | 7.15                | 94.04%       | 47.90%       | 274,228           | 32,078     |

## Überblick

Die Injektion gleitet in die dritte Position ab. 94 % der Anträge wurden auf irgendeine Form der Injektion getestet, mit einer maximalen Inzidenzrate von 19 %, einer durchschnittlichen Inzidenzrate von 3 % und 274.000 Vorkommnissen. Zu den bemerkenswerten Common Weakness Enumerations (CWEs) gehören *CWE-79: Cross-Site Scripting*, *CWE-89: SQL Injection* und *CWE-73: External Control of File Name or Path*.

## Beschreibung

Eine Anwendung ist anfällig für Angriffe, wenn:

- Vom Benutzer bereitgestellte Daten von der Anwendung nicht validiert, gefiltert oder bereinigt werden.

- Dynamische Abfragen oder nicht parametrisierte Aufrufe ohne kontextbewusstes Escapen direkt im Interpreter verwendet werden.

- Gefährliche Daten in ORM-Suchparametern (Object-Relational Mapping) verwendet werden, um zusätzliche, sensible Datensätze zu extrahieren.

- Feindselig Daten direkt verwendet oder miteinander verkettet werden. Der SQL Oder-Befehl enthält die Struktur und schädliche Daten in dynamischen Abfragen, Befehlen oder gespeicherten Prozeduren.

Zu den häufigeren Injektionen gehören SQL, NoSQL, OS-Befehle, Object Relational Mapping (ORM), LDAP und Expression Language (EL) oder Object Graph Navigation Library (OGNL). Das Konzept ist bei allen Interpretern identisch. Die Überprüfung des Quellcodes ist die beste Methode, um festzustellen, ob Anwendungen anfällig für Injektionen sind. Das automatisierte Testen aller Parameter, Header, URLs, Cookies, JSON-, SOAP- und XML-Dateneingaben wird dringend empfohlen. Unternehmen können statische (SAST), dynamische (DAST) und interaktive (IAST) Tools zum Testen der Anwendungssicherheit in die CI/CD-Pipeline integrieren, um eingeführte Injektionsfehler vor der Produktionsbereitstellung zu identifizieren.

## Gegenmaßnahmen

Um die Injektion zu verhindern, müssen Daten von Befehlen und Abfragen getrennt gehalten werden:

– Die bevorzugte Option ist die Verwendung einer sicheren API, die die Verwendung des Interpreters vollständig vermeidet, eine parametrisierte Schnittstelle bereitstellt oder auf Object Relational Mapping Tools (ORMs) migriert.<br/> **Hinweis:** Auch wenn sie schon parametrisierten wurden können gespeicherten Prozeduren immer noch SQL-Injection auslösen, wenn PL/SQL oder T-SQL Abfragen und Daten verkettet oder feindselige Daten mit EXECUTE IMMEDIATE oder exec() ausführt.

– Verwenden Sie eine positive serverseitige Eingabevalidierung. Dies ist kein vollständiger Schutz, da viele Anwendungen Sonderzeichen erfordern, beispielsweise Textbereiche oder APIs für mobile Anwendungen.

- Für alle verbleibenden dynamischen Abfragen maskieren Sie Sonderzeichen mit der spezifischen Escape-Syntax für diesen Interpreter.<br/> **Hinweis:** SQL-Strukturen wie Tabellennamen, Spaltennamen usw. können nicht maskiert werden. Daher sind die von Benutzern gewählten Strukturnamen als gefährlich zu betrachten. Dies ist ein häufiges Problem bei Software welche Berichte verfasst.

- Verwenden Sie LIMIT und andere SQL-Steuerelemente in Abfragen, um die Ausgabe bzw. Abfreage eine großen Anzahl von Datensätzen im Falle einer SQL-Injection zu verhindern.

## Beispielangriffsszenarien

**Szenario Nr. 1:** Eine Anwendung verwendet nicht vertrauenswürdige Daten bei der Erstellung des folgenden anfälligen SQL-Aufrufs:
```
String query = "SELECT \* FROM Accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Szenario Nr. 2:** Ebenso kann das blinde Vertrauen einer Anwendung in Frameworks zu Abfragen führen, die immer noch anfällig sind (z. B. Hibernate Query Language (HQL)):
```
Abfrage HQLQuery = session.createQuery("FROM Accounts WHERE custID='" + request.getParameter("id") + "'");
```

In beiden Fällen ändert der Angreifer den Parameterwert „id“ in seinem Browser, um Folgendes zu senden: „UNION SLEEP(10);--“. Zum Beispiel:
```
http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Dadurch ändert sich die Bedeutung beider Abfragen, sodass alle Datensätze aus der Kontentabelle zurückgegeben werden. Gefährlichere Angriffe könnten Daten verändern oder löschen oder sogar gespeicherte Prozeduren aufrufen.

## Referenzen

- [OWASP Proactive Controls: Sicherer Datenbankzugriff](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

- [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP-Testleitfaden: SQL-Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Befehlsinjektion]( https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection) und [ORM-Injection](https://owasp.org/www -project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

- [OWASP-Spickzettel: Injektionsprävention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

- [OWASP-Spickzettel: SQL-Injection-Prävention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

- [OWASP Spickzettel: Injektionsprävention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

- [OWASP-Spickzettel: Abfrageparametrisierung](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

- [OWASP Automatisierte Bedrohungen für Webanwendungen – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

- [PortSwigger: Serverseitige Vorlageninjektion](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Liste der zugeordneten CWEs

[CWE-20 Unsachgemäße Eingabevalidierung](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Unsachgemäße Neutralisierung spezieller Elemente in der Ausgabe, die von einer nachgeschalteten Komponente verwendet wird („Injektion“)](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75-Fehler bei der Sanierung spezieller Elemente in eine andere Ebene (Spezialelement-Injektion)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Unsachgemäße Neutralisierung spezieller Elemente, die in einem Befehl verwendet werden („Command Injection“)](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Unsachgemäße Neutralisierung spezieller Elemente, die in einem Betriebssystembefehl verwendet werden („OS Command Injection“)](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Unsachgemäße Neutralisierung von Eingaben während der Webseitengenerierung („Cross-Site Scripting“)](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Unsachgemäße Neutralisierung skriptbezogener HTML-Tags in einer Webseite (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Unsachgemäße Neutralisierung von Skripten in Attributen auf einer Webseite](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Unsachgemäße Neutralisierung der alternativen XSS-Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Unsachgemäße Neutralisierung von Argumenttrennzeichen in einem Befehl („Argument Injection“)](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Unsachgemäße Neutralisierung spezieller Elemente, die in einem SQL-Befehl verwendet werden („SQL-Injection“)](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Unsachgemäße Neutralisierung spezieller Elemente, die in einer LDAP-Abfrage verwendet werden („LDAP-Injection“)](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML-Injection (auch bekannt als Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Unsachgemäße Neutralisierung von CRLF-Sequenzen („CRLF-Injektion“)](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Unsachgemäße Kontrolle der Codegenerierung („Code-Injection“)](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Unsachgemäße Neutralisierung von Anweisungen in dynamisch ausgewertetem Code („Eval Injection“)](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Unsachgemäße Neutralisierung von Anweisungen in statisch gespeichertem Code („Static Code Injection“)](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Unsachgemäße Neutralisierung von Server-Side Includes (SSI) innerhalb einer Webseite](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Unsachgemäße Kontrolle des Dateinamens für die Include/Require-Anweisung im PHP-Programm („PHP Remote File Inclusion“)](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Unsachgemäße Kontrolle von Ressourcenkennungen („Ressourceninjektion“)](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 veraltet: War ein Sammelbegriff für Eingabevalidierungsprobleme](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Unsachgemäße Neutralisierung von CRLF-Sequenzen in HTTP-Headern („HTTP Response Splitting“)](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Unsachgemäße Kodierung oder Escapezeichen der Ausgabe](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Unsachgemäße Neutralisierung spezieller Elemente](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Unvollständige Liste unzulässiger Eingaben](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Verwendung extern gesteuerter Eingaben zur Auswahl von Klassen oder Code („Unsichere Reflexion“)](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471-Änderung angenommener unveränderlicher Daten (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL-Injection: Ruhezustand](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Extern gesteuerter Verweis auf eine Ressource in einem anderen Bereich](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Unsachgemäße Neutralisierung von Daten in XPath-Ausdrücken („XPath-Injection“)](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Unsachgemäße Neutralisierung von HTTP-Headern für die Skriptsyntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Unsachgemäße Neutralisierung von Daten in XQuery-Ausdrücken („XQuery-Injection“)](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Unsachgemäße Neutralisierung spezieller Elemente, die in einer Expression Language-Anweisung verwendet werden („Expression Language Injection“)](https://cwe.mitre.org/data/definitions/917.html)
