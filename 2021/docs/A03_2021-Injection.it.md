# A03:2021 – Injection    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"} 

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 7.25                 | 7.15                | 94.04%       | 47.90%       | 274,228           | 32,078     |

## Panoramica

Injection scende alla terza posizione. Il 94% delle applicazioni
sono state testate per qualche forma di injection con un tasso massimo di incidenza del 19%, un tasso medio di incidenza del 3% e 274k occorrenze. Le Common Weakness Enumerations (CWEs) incluse sono
*CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, and *CWE-73:
External Control of File Name or Path*.

## Descrizione 

Un'applicazione è vulnerabile alle injection quando:

- I dati forniti dall'utente non sono validati, filtrati o sanificati dall'applicazione.

- Le query dinamiche o le chiamate non parametrizzate senza escaping contestuale vengono passate direttamente    all'interprete.

- Input malevolo viene usato all'interno di parametri di ricerca di un ORM (object-relational mapping)
    per estrarre ulteriori record sensibili.

- Input malevolo viene usato in modo diretto o concatenato. Le query SQL o i comandi
    includono i dati ostili nelle query dinamiche, nei comandi o nelle stored procedure.


Alcune delle forme di injection più comuni sono SQL, NoSQL, OS command, Object
Relational Mapping (ORM), LDAP, e Expression Language (EL) o Object
Graph Navigation Library (OGNL). Il concetto è identico
tra tutti gli interpreti. La revisione del codice sorgente è il metodo migliore per
rilevare se le applicazioni sono vulnerabili alle injection. È fortemente consigliato il testing
automatico di tutti i parametri, headers, URL, cookie, e sui formati di dato come JSON, SOAP e XML. 
Le organizzazioni possono includere strumenti statici (SAST), dinamici (DAST) e interattivi (IAST) per i test di sicurezza delle applicazioni nella pipeline CI/CD
per identificare prima della messa in produzione le problematiche di injection eventualmente presenti.


## Come prevenire

Prevenire le forme di injection richiede di mantenere i dati separati dai comandi e dalle query:

- L'opzione preferita è quella di usare un'API sicura, che eviti di usare l'interprete
    interamente, che fornisce un'interfaccia parametrizzata o
    migra verso strumenti di Object Relational Mapping (ORM).<br/>
    **Nota:** Anche quando sono parametrizzate, le stored procedure possono ancora introdurre
    SQL injection se PL/SQL o T-SQL concatena query e dati o
    esegue input ostili con EXECUTE IMMEDIATE o exec().

- Usare una validazione degli input lato server positiva. Questa
    non è una difesa completa, poiché molte applicazioni richiedono caratteri speciali, 
    come aree di testo o API per applicazioni mobili.

- Per qualsiasi query dinamica residua, svolgera l'escaping dei caratteri speciali usando
    la sintassi di escape specifica per quell'interprete.<br/>
    **Nota:** Le strutture SQL come i nomi delle tabelle, i nomi delle colonne e così via
    non possono essere oggetto di escape, e quindi i nomi di queste strutture fornite dall'utente sono
    e rimangono pericolose. Questo è un problema comune nel software di reportistica.

- Usare LIMIT e altri controlli SQL all'interno delle query per prevenire la
    divulgazione di massa dei record in caso di SQL injection.


## Esempi di scenari d'attacco

**Scenario #1:** Un'applicazione usa dati non fidati nella costruzione
della seguente chiamata SQL vulnerabile:
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Scenario #2:** Allo stesso modo, la fiducia cieca di un'applicazione nei framework
può risultare in query che sono ancora vulnerabili, (ad esempio, Hibernate Query
Language (HQL)):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

In entrambi i casi, l'attaccante modifica il valore del parametro 'id' nel suo
browser per inviare: ' UNION SELECT SLEEP(10);--. Per esempio:
```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Questo cambia il significato di entrambe le query per restituire tutti i record dalla
della tabella degli account. Attacchi più pericolosi potrebbero modificare o cancellare i dati
o anche invocare stored procedures.

## Riferimenti

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Lista dei CWE correlati

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')] (https://cwe.mitre.org/data/definitions/917.html)
