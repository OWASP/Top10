# A05:2025 Injection ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Contesto.

L'Injection scende di due posizioni dal #3 al #5 nella classifica, mantenendo la sua posizione relativa rispetto ad A04:2025-Cryptographic Failures e A06:2025-Insecure Design. L'Injection è una delle categorie più testate, con il 100% delle applicazioni testate per qualche forma di injection. Ha avuto il maggior numero di CVE per qualsiasi categoria, con 37 CWE in questa categoria. L'Injection include Cross-site Scripting (alta frequenza/basso impatto) con oltre 30k CVE e SQL Injection (bassa frequenza/alto impatto) con oltre 14k CVE. Il numero massivo di CVE segnalati per CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') abbassa l'impatto medio ponderato di questa categoria.


## Tabella dei punteggi.


<table>
  <tr>
   <td>CWE Mappate 
   </td>
   <td>Tasso Massimo di Incidenza
   </td>
   <td>Tasso Medio di Incidenza
   </td>
   <td>Copertura Massima
   </td>
   <td>Copertura Media
   </td>
   <td>Exploit Medio Ponderato
   </td>
   <td>Impatto Medio Ponderato
   </td>
   <td>Totale Occorrenze
   </td>
   <td>Totale CVE
   </td>
  </tr>
  <tr>
   <td>37
   </td>
   <td>13,77%
   </td>
   <td>3,08%
   </td>
   <td>100,00%
   </td>
   <td>42,93%
   </td>
   <td>7,15
   </td>
   <td>4,32
   </td>
   <td>1.404.249
   </td>
   <td>62.445
   </td>
  </tr>
</table>



## Descrizione.

Una vulnerabilità di injection è una falla applicativa che consente all'input non attendibile dell'utente di essere inviato a un interprete (es. un browser, un database, la riga di comando) e fa sì che l'interprete esegua parti di quell'input come comandi.

Un'applicazione è vulnerabile agli attacchi quando:

* I dati forniti dall'utente non vengono validati, filtrati o sanificati dall'applicazione.
* Query dinamiche o chiamate non parametrizzate senza escape consapevole del contesto vengono utilizzate direttamente nell'interprete.
* Dati non sanificati vengono utilizzati nei parametri di ricerca dell'object-relational mapping (ORM) per estrarre record aggiuntivi e sensibili.
* Dati potenzialmente ostili vengono direttamente utilizzati o concatenati. L'SQL o il comando contiene la struttura e i dati malevoli in query dinamiche, comandi o stored procedure.

Alcune delle injection più comuni sono SQL, NoSQL, OS command, Object Relational Mapping (ORM), LDAP e Expression Language (EL) o Object Graph Navigation Library (OGNL) injection. Il concetto è identico tra tutti gli interpreti. Il rilevamento è meglio ottenuto tramite una combinazione di revisione del codice sorgente e testing automatizzato (incluso il fuzzing) di tutti i parametri, header, URL, cookie, dati JSON, SOAP e XML. L'aggiunta di strumenti di testing della sicurezza applicativa statici (SAST), dinamici (DAST) e interattivi (IAST) nella pipeline CI/CD può essere utile per identificare le falle di injection prima della distribuzione in produzione.

Una classe correlata di vulnerabilità di injection è diventata comune negli LLM. Queste sono discusse separatamente nell'[OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/), specificamente [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).


## Come prevenire.

Il modo migliore per prevenire l'injection richiede di mantenere i dati separati dai comandi e dalle query:

* L'opzione preferita è utilizzare un'API sicura, che eviti l'uso dell'interprete interamente, fornisca un'interfaccia parametrizzata, o migri verso Object Relational Mapping Tools (ORM).
**Nota:** Anche quando parametrizzate, le stored procedure possono ancora introdurre SQL injection se PL/SQL o T-SQL concatena query e dati o esegue dati ostili con EXECUTE IMMEDIATE o exec().

Quando non è possibile separare i dati dai comandi, è possibile ridurre le minacce utilizzando le seguenti tecniche.

* Utilizzare la validazione degli input positiva lato server. Non si tratta di una difesa completa poiché molte applicazioni richiedono caratteri speciali, come aree di testo o API per applicazioni mobile.
* Per qualsiasi query dinamica residua, eseguire l'escape dei caratteri speciali utilizzando la sintassi di escape specifica per quell'interprete.
**Nota:** Le strutture SQL come i nomi delle tabelle, i nomi delle colonne, ecc. non possono essere sottoposte a escape, quindi i nomi di struttura forniti dall'utente sono pericolosi. Questo è un problema comune nel software di generazione di report.

**Attenzione:** queste tecniche implicano l'analisi e l'escape di stringhe complesse, rendendole soggette a errori e non robuste a fronte di piccole modifiche al sistema sottostante.

## Scenari di attacco di esempio.

**Scenario #1:** Un'applicazione utilizza dati non attendibili nella costruzione della seguente chiamata SQL vulnerabile:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

Un attaccante modifica il valore del parametro 'id' nel browser inviando: `' OR '1'='1`. Ad esempio:

```
http://example.com/app/accountView?id=' OR '1'='1
```

Questo modifica il significato della query per restituire tutti i record dalla tabella degli account. Attacchi più pericolosi potrebbero modificare o eliminare dati o persino invocare stored procedure.

**Scenario #2:** L'eccessiva fiducia di un'applicazione nei framework può risultare in query ancora vulnerabili. Ad esempio, Hibernate Query Language (HQL):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Un attaccante fornisce: `' OR custID IS NOT NULL OR custID='`. Questo bypassa il filtro e restituisce tutti gli account. Sebbene HQL abbia meno funzioni pericolose del SQL grezzo, consente ancora l'accesso non autorizzato ai dati quando l'input dell'utente viene concatenato nelle query.

**Scenario #3:** Un'applicazione passa direttamente l'input dell'utente a un comando OS:

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

Un attaccante fornisce `example.com; cat /etc/passwd` per eseguire comandi arbitrari sul server.

## Riferimenti.

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP LLM Top 10: LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)


## Lista delle CWE Mappate

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)
* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
