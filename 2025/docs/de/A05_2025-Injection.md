# A05:2025 Injection ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Hintergrund. 

„Injection“ fällt im Ranking um zwei Plätze von Platz 3 auf Platz 5 zurück, behält jedoch seine Position im Vergleich zu „A04:2025 – Fehlerhafter Einsatz von Kryptographie“ und „A06:2025 – Unsicheres Anwendungsdesign“ bei. „Injection“ ist eine der am häufigsten getesteten Kategorien, wobei 100 % der Anwendungen auf irgendeine Form von Injection geprüft wurden. Mit 37 CVEs wies diese Kategorie die höchste Anzahl an CVEs aller Kategorien auf. Injection umfasst Cross-Site-Scripting (hohe Häufigkeit/geringe Auswirkung) mit mehr als 30.000 CVEs und SQL-Injection (geringe Häufigkeit/hohe Auswirkung) mit mehr als 14.000 CVEs. Die enorme Anzahl gemeldeter CVEs für CWE-79 „Improper Neutralization of Input During Web Page Generation“ („Cross-Site-Scripting“) senkt die gewichtete durchschnittliche Auswirkung dieser Kategorie. 


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
   <td>37
   </td>
   <td>13.77%
   </td>
   <td>3.08%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.15
   </td>
   <td>4.32
   </td>
   <td>1,404,249
   </td>
   <td>62,445
   </td>
  </tr>
</table>



## Beschreibung. 

Eine Injection-Sicherheitslücke ist ein Anwendungsfehler, der es ermöglicht, dass nicht vertrauenswürdige Benutzereingaben an einen Interpreter (z. B. einen Browser, eine Datenbank oder die Befehlszeile) gesendet werden und dazu führt, dass der Interpreter Teile dieser Eingaben als Befehle ausführt.  

Eine Anwendung ist für diesen Angriff anfällig, wenn:

* Daten, die von Nutzenden stammen, von der Anwendung nicht ausreichend validiert, gefiltert oder bereinigt werden.
* Dynamische Anfragen oder nicht-parametrisierte Aufrufe ohne ein, dem Kontext entsprechendes Escaping direkt einem Interpreter übergeben werden.
* Unbereinigte Daten innerhalb von ORM („Object-Relational Mapping“)-Suchparametern genutzt werden können, um zusätzliche, sensible Datensätze zu extrahieren.
* Potenziell bösartige Daten direkt oder als Teil zusammengesetzter, dynamischer Querys verwendet werden. Die SQL-Abfragen oder Befehle beinhalten die schädlichen Daten in dynamischen Querys, Befehlen oder Stored Procedures.

Zu den häufigeren Injection Arten gehören SQL, NoSQL, OS-Befehle, Object Relational Mapping (ORM), LDAP und Expression Language (EL) oder Object Graph Navigation Library (OGNL). Das Grundkonzept eines Injection-Angriffs ist für alle Interpreter gleich. Die Erkennung lässt sich am besten durch eine Kombination aus Code-Review und automatisierten Tests (einschließlich Fuzzing) aller Parameter, Header, URLs, Cookies sowie JSON-, SOAP- und XML-Eingabedaten erreichen. Statische (SAST, Quellcode-Ebene), dynamische (DAST, laufende Anwendung) und interaktive (IAST, Mischform aus statisch und dynamisch) Test-Werkzeuge können von Organisationen für ihre CI/CD-Pipeline genutzt werden, um neue Schwachstellen noch vor einer möglichen Auslieferung in Produktivsysteme zu identifizieren.

Eine verwandte Klasse von Injektionsschwachstellen ist bei LLMs mittlerweile weit verbreitet. Diese werden separat in den [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) behandelt, insbesondere unter [LLM01:2025 Prompt-Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).


## Prävention und Gegenmaßnahmen.

Eine konsequente Trennung von Daten, Suchanfragen und Befehlen ist für die Vermeidung von Injection-Angriffen unerlässlich:

* Die bevorzugte Methode ist die Verwendung einer sicheren API, die die Verwendung des Interpreters vollständig vermeidet, eine parametrisierte Schnittstelle bereitstellt oder in objektrelationale Mapping-Tools (ORMs) umwandelt. 
**Anmerkung:** Stored Procedures können - auch parametrisiert - immer noch SQL-Injections ermöglichen, wenn PL/SQL oder T-SQL Anfragen und Eingabedaten konkateniert oder mit EXECUTE IMMEDIATE oder exec() ausgeführt werden.

Wenn es nicht möglich ist, die Daten von den Befehlen zu trennen, können Sie die Risiken mithilfe der folgenden Techniken verringern:

* Nutzen Sie eine serverseitige Eingabe-Validierung mit Allow-List. Dies ist kein vollständiger Schutz, da viele Anwendungen Sonderzeichen z. B. in Textfelder oder APIs für mobile Anwendungen benötigen.

* Für jede noch verbliebene dynamische Query müssen Sonderzeichen für den jeweiligen Interpreter mit der richtigen Escape-Syntax entschärft werden.
**Anmerkung:** Ein Escaping von SQL-Bezeichnern, wie z. B. die Namen von Tabellen oder Spalten usw. ist nicht möglich. Falls Nutzende solche Bezeichner selbst eingeben können, so ist dies durchaus gefährlich. Dies ist eine übliche Schwachstelle bei Software, die Reports aus einer Datenbank erstellt.

**Warnung**: Diese Techniken beinhalten das Parsen und Escapen komplexer Zeichenfolgen, wodurch sie fehleranfällig sind und nicht robust bei geringfügigen Änderungen am System. 

## Beispielhafte Angriffsszenarien. 

**Szenario Nr. 1:** Eine Anwendung nutzt ungeprüfte Eingabedaten für den Zusammenbau der folgenden verwundbaren SQL-Abfrage:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

Ein Angreifer manipuliert den Wert des id-Parameters im Browser und sendet `' OR '1'='1`. z.B.:

```
http://example.com/app/accountView?id=' OR '1'='1
```

Dadurch wird die Abfrage so geändert, dass alle Datensätze aus der Tabelle „accounts“ zurückgegeben werden. Gefährlichere Angriffe könnten Daten verändern oder löschen oder sogar Stored Procedures aufrufen.

**Szenario Nr. 2:** Auch das blinde Vertrauen in Frameworks kann zu Querys führen, die ganz analog zu obigem Beispiel verwundbar sind (z. B. Hibernate Query Language (HQL)):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Ein Angreifer gibt Folgendes ein: `' OR custID IS NOT NULL OR custID='`. Dadurch wird der Filter umgangen und es werden alle Accounts zurückgegeben. Obwohl HQL weniger gefährliche Funktionen enthält als reines SQL, ermöglicht es dennoch unbefugten Datenzugriff, wenn Benutzereingaben in Abfragen eingebunden werden.

**Szenario Nr. 3:** Eine Anwendung gibt Benutzereingaben direkt an ein OS-Kommando weiter:

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

Ein Angreifer übergibt `example.com; cat /etc/passwd` um beliebige Befehle auf dem Server auszuführen.

## Referenzen.

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 



## Liste der zugeordneten CWEs

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

* [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)

* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

* [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

* [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)

* [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

* [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

* [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

* [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

* [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

* [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

* [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

* [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

* [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)

* [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)

* [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)

* [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

* [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)

* [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)

* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

* [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)

* [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)

* [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

* [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)

* [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)

* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

* [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

* [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
