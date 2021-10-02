# A01:2021 – Broken Access Control    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs Mappati | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## Panoramica

Salendo dalla quinta posizione, il 94% delle applicazioni è stato testato per
una qualche forma di broken access control con un tasso medio di incidenza del 3,81%, e ha il maggior numero di occorrenze nel dataset con oltre 318k. Le Common Weakness Enumerations (CWE) incluse sono *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201: Exposure of Sensitive Information Through Sent Data*, e *CWE-352: Cross-Site Request Forgery*.

## Descrizione

Il controllo degli accessi fa rispettare la policy in modo che gli utenti non possano agire al di fuori dei
permessi previsti. Problematiche su questo tipo di controllo tipicamente portano alla divulgazione non autorizzata di
informazioni, alla modifica o alla distruzione di tutti i dati o l'esecuzione di una funzione di business al di fuori dei limiti dell'utente. Le vulnerabilità più comuni che affliggono i meccanismi di controllo degli accessi includono:

- Violazione del principio del minimo privilegio o deny by default,
  dove l'accesso dovrebbe essere concesso solo per particolari capabilities,
  ruoli o utenti, ma è disponibile a chiunque.

- Bypassare i controlli di accesso modificando l'URL (modifica dei parametri o
  navigazione forzata), lo stato interno dell'applicazione o la
  pagina HTML, o utilizzando uno strumento di attacco che modifica le richieste API.

- Permettere la visualizzazione o la modifica dell'account di qualcun altro, fornendo
  il suo identificatore unico (insecure direct object references)

- Accesso all'API con controlli di accesso mancanti per POST, PUT e DELETE.

- Elevazione dei privilegi. Agire come un utente senza essere loggato o
  agire come amministratore quando si è svolto il login come utente base.

- Manipolazione dei metadati, come la riproduzione o la modifica di un JSON
  Web Token (JWT), o un cookie o un campo nascosto
  manipolati per elevare i privilegi o abusare dell'invalidazione del JWT.

- La configurazione errata di CORS permette l'accesso all'API da origini non autorizzate/non fidate.

- Forzare la navigazione verso pagine autenticate come utente non autenticato o
  a pagine privilegiate come utente base.

## Come prevenirla

Il controllo degli accessi è efficace solo nel codice lato server o
API server-less, dove l'attaccante non può modificare i meccanismi di controllo dell'accesso
o i metadati.

- Tranne che per le risorse pubbliche, applicare il principio di deny by default.

- Implementare i meccanismi di controllo dell'accesso una volta sola e riutilizzarli in tutta
  l'applicazione, incluso limitare l'utilizzo di Cross-Origin Resource Sharing (CORS).

- I controlli di accesso del Model dovrebbero imporre la proprietà dei record piuttosto che
  accettare che l'utente possa creare, leggere, aggiornare o cancellare qualsiasi
  record.

- I requisiti unici dei vincoli di business di un'applicazione dovrebbero essere applicati nei
  modelli di dominio.

- Disabilitare il directory listing del server web e garantire che i metadati dei file (ad es,
  .git) e i file di backup non siano presenti all'interno delle web roots.

- Registrare i fallimenti dei meccanismi di controllo dell'accesso, avvisare gli amministratori quando appropriato (ad es,
  fallimenti ripetuti).

- Implementare meccanismi di rate limiting per accesso all'API e al controller per minimizzare il danno da
  strumenti di attacco automatizzati.

- Gli identificatori di sessione stateful dovrebbero essere invalidati sul server dopo il logout.
  I token JWT stateless dovrebbero piuttosto essere di breve durata in modo che la finestra di 
  opportunità per un attaccante sia ridotta al minimo. Per i JWT di lunga durata è altamente raccomandato di
  seguire gli standard OAuth per revocare l'accesso.

Gli sviluppatori e lo staff di QA dovrebbero includere test funzionali di controllo dell'accesso
e test di integrazione.

## Esempi di scenari d'attacco

**Scenario #1:** L'applicazione usa dati non verificati in una chiamata SQL che
sta accedendo alle informazioni dell'account:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

Un attaccante modifica semplicemente il parametro 'acct' del browser per inviare
numero di conto a piacere. Se il parametro non è verificato correttamente, l'attaccante può accedere all'account di qualsiasi utente.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Scenario #2:** Un attaccante forza semplicemente la navigazione verso gli URL di destinazione. Sono richiesti i diritti di amministratore per accedere alla pagina di amministrazione.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```
Se un utente non autenticato può accedere a una delle due pagine, è una falla. Se un non amministratore può accedere alla pagina dell'amministratore, questa è una falla.

## Riferimenti

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## Lista dei CWEs rilevanti

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
