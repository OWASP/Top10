# A09:2025 Security Logging & Alerting Failures ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## Contesto.

Security Logging & Alerting Failures mantiene la sua posizione al #9. Questa categoria ha una leggera modifica del nome per enfatizzare la funzione di alerting necessaria per indurre azioni sugli eventi di logging rilevanti. Questa categoria sarà sempre sottorappresentata nei dati e per la terza volta è stata votata in una posizione nella lista dai partecipanti al sondaggio della community. Questa categoria è incredibilmente difficile da testare e ha una rappresentazione minima nei dati CVE/CVSS (solo 723 CVE); ma può essere molto impattante per la visibilità, l'alerting degli incidenti e la forensica. Questa categoria include problemi con la *corretta gestione dell'encoding dell'output nei file di log (CWE-117), l'inserimento di dati sensibili nei file di log (CWE-532) e il logging insufficiente (CWE-778).*


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
   <td>5
   </td>
   <td>11,33%
   </td>
   <td>3,91%
   </td>
   <td>85,96%
   </td>
   <td>46,48%
   </td>
   <td>7,19
   </td>
   <td>2,65
   </td>
   <td>260.288
   </td>
   <td>723
   </td>
  </tr>
</table>



## Descrizione.

Senza logging e monitoraggio, gli attacchi e le violazioni non possono essere rilevati, e senza alerting è molto difficile rispondere in modo rapido ed efficace durante un incidente di sicurezza. Un logging insufficiente, un monitoraggio continuo, il rilevamento e l'alerting per avviare risposte attive si verificano ogni volta che:


* Gli eventi verificabili, come i login, i login falliti e le transazioni di alto valore, non vengono registrati o vengono registrati in modo incoerente (ad esempio, vengono registrati solo i login riusciti, ma non i tentativi falliti).
* Gli avvisi e gli errori generano messaggi di log assenti, inadeguati o poco chiari.
* L'integrità dei log non è adeguatamente protetta dalla manomissione.
* I log delle applicazioni e delle API non vengono monitorati per attività sospette.
* I log vengono archiviati solo localmente e non vengono adeguatamente sottoposti a backup.
* Soglie di alerting appropriate e processi di escalation delle risposte non sono in atto o efficaci. Gli alert non vengono ricevuti o esaminati entro un tempo ragionevole.
* I penetration test e le scansioni degli strumenti di dynamic application security testing (DAST) (come Burp o ZAP) non attivano alert.
* L'applicazione non è in grado di rilevare, escalare o avvisare per attacchi attivi in tempo reale o quasi in tempo reale.
* Sei vulnerabile alla fuga di informazioni sensibili rendendo visibili gli eventi di logging e alerting a un utente o a un attaccante (vedi [A01:2025-Broken Access Control](A01_2025-Broken_Access_Control.md)), o registrando informazioni sensibili che non dovrebbero essere registrate (come PII o PHI).
* Sei vulnerabile a injection o attacchi ai sistemi di logging o monitoraggio se i dati dei log non sono correttamente codificati.
* L'applicazione manca o gestisce male gli errori e altre condizioni eccezionali, in modo tale che il sistema non sia consapevole che si è verificato un errore e quindi non sia in grado di registrare che c'è stato un problema.
* Mancano o sono obsoleti adeguati 'use case' per l'emissione di alert per riconoscere una situazione speciale.
* Troppi alert falsi positivi rendono impossibile distinguere gli alert importanti da quelli non importanti, con il risultato che vengono riconosciuti troppo tardi o per niente (sovraccarico fisico del team SOC).
* Gli alert rilevati non possono essere elaborati correttamente perché il playbook per il caso d'uso è incompleto, obsoleto o mancante.


## Come prevenire.

Gli sviluppatori dovrebbero implementare alcuni o tutti i seguenti controlli, a seconda del rischio dell'applicazione:


* Garantire che tutti i fallimenti di login, controllo degli accessi e validazione degli input lato server possano essere registrati con un contesto utente sufficiente per identificare account sospetti o malevoli e conservati per un tempo sufficiente a consentire un'analisi forense differita.
* Garantire che ogni parte dell'app che contiene un controllo di sicurezza venga registrata, indipendentemente dal fatto che abbia successo o fallisca.
* Garantire che i log vengano generati in un formato che le soluzioni di gestione dei log possano consumare facilmente.
* Garantire che i dati dei log siano codificati correttamente per prevenire injection o attacchi ai sistemi di logging o monitoraggio.
* Garantire che tutte le transazioni abbiano una traccia di audit con controlli di integrità per prevenire manomissioni o cancellazioni, come tabelle di database append-only o simili.
* Garantire che tutte le transazioni che generano un errore vengano annullate e ricominciare. Fallire sempre in modo chiuso.
* Se la tua applicazione o i suoi utenti si comportano in modo sospetto, emettere un alert. Creare linee guida per gli sviluppatori su questo argomento in modo che possano programmare in base a questo o acquistare un sistema per questo.
* I team DevSecOps e di sicurezza dovrebbero stabilire use case efficaci di monitoraggio e alerting inclusi playbook in modo che le attività sospette vengano rilevate e gestite rapidamente dal team del Security Operations Center (SOC).
* Aggiungere 'honeytoken' come trappole per gli attaccanti nella tua applicazione, ad esempio nel database, nei dati, come identità utente reale e/o tecnica. Poiché non vengono utilizzati nel normale business, qualsiasi accesso genera dati di logging che possono essere segnalati con quasi nessun falso positivo.
* L'analisi comportamentale e il supporto AI potrebbero essere opzionalmente una tecnica aggiuntiva per supportare bassi tassi di falsi positivi per gli alert.
* Stabilire o adottare un piano di risposta agli incidenti e di recupero, come NIST 800-61r2 o successivo. Insegnare agli sviluppatori software come appaiono gli attacchi e gli incidenti alle applicazioni, in modo che possano segnalarli.

Esistono prodotti commerciali e open-source per la protezione delle applicazioni come l'OWASP ModSecurity Core Rule Set, e software open-source di correlazione dei log, come lo stack Elasticsearch, Logstash, Kibana (ELK), che includono dashboard personalizzate e alerting che potrebbero aiutarti a combattere questi problemi. Esistono anche strumenti di osservabilità commerciali che possono aiutarti a rispondere o bloccare gli attacchi in tempo quasi reale.


## Scenari di attacco di esempio.

**Scenario #1:** L'operatore del sito web di un fornitore di piani sanitari per bambini non ha potuto rilevare una violazione a causa della mancanza di monitoraggio e logging. Una parte esterna ha informato il fornitore del piano sanitario che un attaccante aveva acceduto e modificato migliaia di cartelle sanitarie sensibili di oltre 3,5 milioni di bambini. Una revisione post-incidente ha rilevato che gli sviluppatori del sito web non avevano affrontato vulnerabilità significative. Poiché non esisteva alcun logging o monitoraggio del sistema, la violazione dei dati potrebbe essere stata in corso dal 2013, un periodo di oltre sette anni.

**Scenario #2:** Una importante compagnia aerea indiana ha subito una violazione dei dati che coinvolgeva oltre dieci anni di dati personali di milioni di passeggeri, inclusi dati di passaporto e carte di credito. La violazione dei dati si è verificata presso un provider di cloud hosting di terze parti, che ha notificato la compagnia aerea della violazione dopo qualche tempo.

**Scenario #3:** Una importante compagnia aerea europea ha subito una violazione segnalabile al GDPR. La violazione è stata causata da vulnerabilità di sicurezza dell'applicazione di pagamento sfruttate dagli attaccanti, che hanno raccolto oltre 400.000 record di pagamento dei clienti. La compagnia aerea è stata multata di 20 milioni di sterline dall'autorità di regolamentazione della privacy.


## Riferimenti.

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)
-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)
-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)
-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)
-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## Lista delle CWE Mappate

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)
* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
