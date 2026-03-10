# A10:2025 Mishandling of Exceptional Conditions ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## Contesto.

La gestione impropria delle condizioni eccezionali è una nuova categoria per il 2025. Questa categoria contiene 24 CWE e si concentra sulla gestione impropria degli errori, errori logici, failing open e altri scenari correlati derivanti da condizioni anomale che i sistemi possono incontrare. Questa categoria include alcuni CWE precedentemente associati a scarsa qualità del codice. Per noi era troppo generico; a nostro avviso, questa categoria più specifica fornisce indicazioni migliori.

CWE notevoli inclusi in questa categoria: *CWE-209 Generation of Error Message Containing Sensitive Information, CWE-234 Failure to Handle Missing Parameter, CWE-274 Improper Handling of Insufficient Privileges, CWE-476 NULL Pointer Dereference,* e *CWE-636 Not Failing Securely ('Failing Open')*.


## Tabella dei punteggi.


<table>
  <tr>
   <td>CWE Mappati
   </td>
   <td>Tasso di Incidenza Massimo
   </td>
   <td>Tasso di Incidenza Medio
   </td>
   <td>Copertura Massima
   </td>
   <td>Copertura Media
   </td>
   <td>Exploit Ponderato Medio
   </td>
   <td>Impatto Ponderato Medio
   </td>
   <td>Occorrenze Totali
   </td>
   <td>CVE Totali
   </td>
  </tr>
  <tr>
   <td>24
   </td>
   <td>20,67%
   </td>
   <td>2,95%
   </td>
   <td>100,00%
   </td>
   <td>37,95%
   </td>
   <td>7,11
   </td>
   <td>3,81
   </td>
   <td>769.581
   </td>
   <td>3.416
   </td>
  </tr>
</table>



## Descrizione.

La gestione impropria delle condizioni eccezionali nel software si verifica quando i programmi non riescono a prevenire, rilevare e rispondere a situazioni insolite e imprevedibili, il che porta a crash, comportamenti imprevisti e talvolta vulnerabilità. Questo può coinvolgere uno o più dei seguenti 3 fallimenti: l'applicazione non previene una situazione insolita, non la identifica mentre si sta verificando e/o risponde in modo inadeguato o non risponde affatto alla situazione in seguito.

Le condizioni eccezionali possono essere causate da validazione dell'input mancante, scarsa o incompleta, o gestione degli errori tardiva ad alto livello invece che nelle funzioni dove si verificano, o stati ambientali imprevisti come problemi di memoria, privilegi o rete, gestione incoerente delle eccezioni, o eccezioni non gestite del tutto, che permettono al sistema di cadere in uno stato sconosciuto e imprevedibile. Ogni volta che un'applicazione non è sicura della sua prossima istruzione, una condizione eccezionale è stata gestita in modo improprio. Errori ed eccezioni difficili da trovare possono minacciare la sicurezza dell'intera applicazione per molto tempo.

Molte diverse vulnerabilità di sicurezza possono verificarsi quando gestiamo male le condizioni eccezionali, come bug logici, overflow, race condition, transazioni fraudolente, o problemi con memoria, stato, risorse, timing, autenticazione e autorizzazione. Questi tipi di vulnerabilità possono influenzare negativamente la riservatezza, la disponibilità e/o l'integrità di un sistema o dei suoi dati. Gli attaccanti manipolano la gestione degli errori difettosa di un'applicazione per colpire questa vulnerabilità.


## Come prevenire.

Per gestire correttamente una condizione eccezionale dobbiamo pianificare tali situazioni (aspettarsi il peggio). Dobbiamo "catturare" ogni possibile errore di sistema direttamente nel punto in cui si verifica e poi gestirlo (il che significa fare qualcosa di significativo per risolvere il problema e assicurarci di riprenderci dalla questione). Come parte della gestione, dovremmo includere la generazione di un errore (per informare l'utente in modo comprensibile), la registrazione dell'evento, nonché l'emissione di un alert se riteniamo che sia giustificato. Dovremmo anche avere un gestore globale delle eccezioni nel caso in cui ci sia qualcosa che abbiamo mancato. Idealmente, avremmo anche strumenti o funzionalità di monitoraggio e/o osservabilità che vigilano su errori ripetuti o pattern che indicano un attacco in corso, in grado di emettere una risposta, una difesa o un blocco di qualche tipo. Questo può aiutarci a bloccare e rispondere a script e bot che si concentrano sulle nostre debolezze nella gestione degli errori.

Catturare e gestire le condizioni eccezionali garantisce che l'infrastruttura sottostante dei nostri programmi non sia lasciata a gestire situazioni imprevedibili. Se siamo nel mezzo di una transazione di qualsiasi tipo, è estremamente importante eseguire il rollback di ogni parte della transazione e ricominciare (noto anche come failing closed). Tentare di recuperare una transazione a metà è spesso il punto in cui creiamo errori irrecuperabili.

Quando possibile, aggiungere rate limiting, quote di risorse, throttling e altri limiti ovunque sia possibile, per prevenire le condizioni eccezionali in primo luogo. Nulla nell'informatica dovrebbe essere illimitato, poiché questo porta a mancanza di resilienza applicativa, denial of service, attacchi a forza bruta riusciti e bollette cloud straordinarie. Considerare se errori ripetuti identici, al di sopra di un certo tasso, debbano essere emessi solo come statistiche che mostrano con quale frequenza si sono verificati e in quale arco temporale. Queste informazioni dovrebbero essere aggiunte al messaggio originale in modo da non interferire con il logging e il monitoraggio automatizzati, vedere [A09:2025 Security Logging & Alerting Failures](A09_2025-Security_Logging_and_Alerting_Failures.md).

Oltre a questo, vorremmo includere una validazione rigorosa dell'input (con sanificazione o escaping per caratteri potenzialmente pericolosi che dobbiamo accettare), e gestione degli errori *centralizzata*, logging, monitoraggio e alerting, e un gestore globale delle eccezioni. Un'applicazione non dovrebbe avere più funzioni per la gestione delle condizioni eccezionali, dovrebbe essere eseguita in un unico posto, allo stesso modo ogni volta. Dovremmo anche creare requisiti di sicurezza del progetto per tutti i consigli in questa sezione, eseguire attività di threat modeling e/o revisione del design sicuro nella fase di progettazione dei nostri progetti, eseguire code review o analisi statica, nonché eseguire test di stress, prestazioni e penetration testing del sistema finale.

Se possibile, l'intera organizzazione dovrebbe gestire le condizioni eccezionali allo stesso modo, poiché rende più facile rivedere e verificare il codice per errori in questo importante controllo di sicurezza.


## Scenari di attacco di esempio.

**Scenario #1:** L'esaurimento delle risorse dovuto alla gestione impropria delle condizioni eccezionali (Denial of Service) potrebbe essere causato se l'applicazione cattura le eccezioni quando i file vengono caricati, ma non rilascia correttamente le risorse dopo. Ogni nuova eccezione lascia risorse bloccate o altrimenti non disponibili, finché tutte le risorse non sono esaurite.

**Scenario #2:** L'esposizione di dati sensibili tramite la gestione impropria degli errori del database che rivela l'errore di sistema completo all'utente. L'attaccante continua a forzare errori al fine di utilizzare le informazioni di sistema sensibili per creare un attacco SQL injection migliore. I dati sensibili nei messaggi di errore all'utente sono ricognizione.

**Scenario #3:** La corruzione dello stato nelle transazioni finanziarie potrebbe essere causata da un attaccante che interrompe una transazione multi-step tramite interruzioni di rete. Immaginate che l'ordine della transazione fosse: addebitare l'account utente, accreditare l'account di destinazione, registrare la transazione. Se il sistema non esegue correttamente il rollback dell'intera transazione (failing closed) quando si verifica un errore a metà, l'attaccante potrebbe potenzialmente prosciugare l'account dell'utente, o possibilmente una race condition che consente all'attaccante di inviare denaro alla destinazione più volte.


## Riferimenti.

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/)

## Lista dei CWE Mappati
* [CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215 Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234 Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248 Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252 Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274 Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369 Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390 Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391 Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394 Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396 Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397 Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460 Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476 NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478 Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484 Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550 Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636 Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703 Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754 Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755 Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)
