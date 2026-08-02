#  A01:2025 Broken Access Control ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}



## Contesto.

Mantenendo la sua posizione al #1 nel Top Ten, il 100% delle applicazioni testate è risultato avere qualche forma di broken access control. Tra le CWE degne di nota vi sono *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201: Exposure of Sensitive Information Through Sent Data*, *CWE-918 Server-Side Request Forgery (SSRF)* e *CWE-352: Cross-Site Request Forgery (CSRF)*. Questa categoria ha il maggior numero di occorrenze nei dati contribuiti e il secondo più alto numero di CVE correlati.


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
   <td>40
   </td>
   <td>20,15%
   </td>
   <td>3,74%
   </td>
   <td>100,00%
   </td>
   <td>42,93%
   </td>
   <td>7,04
   </td>
   <td>3,84
   </td>
   <td>1.839.701
   </td>
   <td>32.654
   </td>
  </tr>
</table>



## Descrizione.

Il controllo degli accessi applica policy tali per cui gli utenti non possono agire al di fuori dei propri permessi previsti. I fallimenti portano tipicamente a divulgazione non autorizzata di informazioni, modifica o distruzione di tutti i dati, o all'esecuzione di una funzione di business al di fuori dei limiti dell'utente. Le vulnerabilità comuni di controllo degli accessi includono:



* Violazione del principio del minimo privilegio, comunemente noto come deny by default, dove l'accesso dovrebbe essere concesso solo per determinate capacità, ruoli o utenti, ma è disponibile a chiunque.
* Aggiramento dei controlli di accesso modificando l'URL (parameter tampering o force browsing), lo stato interno dell'applicazione o la pagina HTML, oppure utilizzando uno strumento di attacco che modifica le richieste API.
* Permettere la visualizzazione o la modifica dell'account di qualcun altro fornendo il suo identificatore univoco (insecure direct object references).
* Un'API accessibile con controlli di accesso mancanti per POST, PUT e DELETE.
* Escalation di privilegi. Agire come utente senza essere autenticati o acquisire privilegi superiori a quelli previsti per l'utente autenticato (es. accesso admin).
* Manipolazione dei metadati, come il replay o la manomissione di un token di controllo degli accessi JSON Web Token (JWT), un cookie o un campo nascosto manipolato per elevare i privilegi, o l'abuso dell'invalidazione JWT.
* La configurazione errata di CORS consente l'accesso alle API da origini non autorizzate o non attendibili.
* Force browsing (indovinare URL) verso pagine autenticate come utente non autenticato o verso pagine privilegiate come utente standard.


## Come prevenire.

Il controllo degli accessi è efficace solo se implementato in codice lato server attendibile o in API serverless, dove l'attaccante non può modificare il controllo degli accessi o i metadati.



* Tranne per le risorse pubbliche, negare l'accesso per default.
* Implementare i meccanismi di controllo degli accessi una sola volta e riutilizzarli in tutta l'applicazione, inclusa la minimizzazione dell'utilizzo del Cross-Origin Resource Sharing (CORS).
* I modelli di controllo degli accessi devono applicare la proprietà dei record piuttosto che consentire agli utenti di creare, leggere, aggiornare o eliminare qualsiasi record.
* I requisiti di limite di business univoci dell'applicazione devono essere applicati dai modelli di dominio.
* Disabilitare il directory listing del web server e garantire che i metadati dei file (es. .git) e i file di backup non siano presenti nelle web root.
* Registrare i fallimenti del controllo degli accessi, inviare alert agli amministratori quando appropriato (es. fallimenti ripetuti).
* Implementare limiti di frequenza sull'accesso ad API e controller per minimizzare i danni degli strumenti di attacco automatizzati.
* Gli identificatori di sessione con stato devono essere invalidati sul server dopo il logout. I token JWT senza stato devono avere una durata breve per minimizzare la finestra di opportunità per un attaccante. Per JWT con durata più lunga, considerare l'uso di refresh token e seguire gli standard OAuth per revocare l'accesso.
* Utilizzare toolkit o pattern ben consolidati che forniscono controlli degli accessi semplici e dichiarativi.

Gli sviluppatori e il personale QA devono includere test funzionali del controllo degli accessi nei test unitari e di integrazione.


## Scenari di attacco di esempio.

**Scenario #1:** L'applicazione utilizza dati non verificati in una chiamata SQL che accede alle informazioni dell'account:


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```


Un attaccante può semplicemente modificare il parametro 'acct' del browser per inviare qualsiasi numero di account desiderato. Se non verificato correttamente, l'attaccante può accedere all'account di qualsiasi utente.


```
https://example.com/app/accountInfo?acct=notmyacct
```


**Scenario #2:** Un attaccante costringe semplicemente il browser a puntare a URL specifici. Sono necessari i diritti di amministratore per accedere alla pagina di amministrazione.


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


Se un utente non autenticato può accedere a una delle due pagine, si tratta di una falla. Se un non-amministratore può accedere alla pagina di amministrazione, si tratta di una falla.

**Scenario #3:** Un'applicazione gestisce tutto il controllo degli accessi nel front-end. Sebbene l'attaccante non riesca ad accedere a `https://example.com/app/admin_getappInfo` a causa del codice JavaScript in esecuzione nel browser, può semplicemente eseguire:


```
$ curl https://example.com/app/admin_getappInfo
```


dalla riga di comando.


## Riferimenti.

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## Lista delle CWE Mappate

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)
* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)
* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)
* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)
* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)
* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)
* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)
* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)
* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)
* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)
* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)
* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)
* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)
* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)
* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)
* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)
* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
