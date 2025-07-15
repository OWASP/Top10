# A09:2021 – Security Logging and Monitoring Failures    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Panoramica

La problematica relativa alla mancanza di logging e monitoraggio degli eventi di sicurezza proviene dal sondaggio della community della Top 10 (#3), salita leggermente dalla decima posizione della OWASP Top 10 2017. Questa problematica
è complicata da testare, spesso si utilizzano interviste o si chiede se durante i penetration test sono stati individuati degli attacchi. In questa categoria non ci sono molti dati di
CVE/CVSS, ma identificare e rispondere alle violazioni di sicurezza è essenziale. Ha un impatto elevato per quanto riguarda la responsabilità, la visibilità, l'allerta sugli incidenti e la forensics. Questa categoria estende la *CWE-778
Insufficient Logging* per includere *CWE-117 Improper Output Neutralization
for Logs*, *CWE-223 Omission of Security-relevant Information*, e
*CWE-532* *Insertion of Sensitive Information into Log File*.

## Descrizione 

Tornando alla Top 10 2021 di OWASP, questa categoria è per aiutare a rilevare,
svolgere escalation e rispondere alle violazioni attive. Senza logging e
monitoraggio, le violazioni non possono essere rilevate. Il logging,
il rilevamento, il monitoraggio e la risposta attiva insufficienti si verificano ogni volta che:

-   Gli eventi verificabili, come i login, i login falliti e le transazioni ad alto valore, non vengono registrati.

-   Warning ed errori non generano messaggi di log, oppure sono inadeguati o poco chiari.

-   I log di applicazioni e API non sono monitorati per attività sospette.

-   I file di log vengono memorizzati solo localmente.

-   Non sono presenti o sono inefficaci le soglie di allarme e processi di escalation della risposta

-   I penetration test e le scansioni da parte di strumenti DAST (Dynamic Application Security Testing) (come OWASP ZAP) 
    non attivano nessun allarme.

-   L'applicazione non è in grado di rilevare, svolgere escalation o avvisare per gli attacchi attivi
    in real-time o quasi in real-time. 

Si è vulnerabili alla fuga di informazioni se gli eventi di logging e gli alert sono
visibili ad un utente o ad un attaccante (vedi [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## Come prevenire

Gli sviluppatori dovrebbero implementare alcuni o tutti i seguenti controlli, 
a seconda del rischio dell'applicazione:

-   Assicurarsi che tutti i login, il controllo degli accessi e gli errori a seguito della verifica degli input lato server
    possono essere registrati con un contesto utente sufficiente per identificare
    account sospetti o malevoli e conservati per un tempo sufficiente a consentire
    un'analisi forense a posteriori.

-   Assicurarsi che i log siano generati in un formato che le soluzioni di gestione dei log
    possano facilmente consumare.

-   Assicurarsi che i dati di log siano codificati correttamente per prevenire injection o
    attacchi ai sistemi di registrazione o monitoraggio.

-   Assicurarsi che le transazioni di alto valore abbiano un audit trail con controlli di integrità
    per prevenire manomissioni o cancellazioni, come le tabelle append-only di un database, o simili.

-   I team DevSecOps dovrebbero stabilire sistemi di monitoraggio di allerta efficaci
    in modo che le attività sospette siano rilevate e affrontate rapidamente.

-   Stabilire o adottare un piano incident response e recovery, come ad esempio il
    National Institute of Standards and Technology (NIST) 800-61r2 o successivo.

Ci sono framework di protezione delle applicazioni commerciali e open-source
come l'OWASP ModSecurity Core Rule Set, e software di correlazione dei log open-source, 
come Elasticsearch, Logstash, Kibana (ELK) che dispongono di dashboard e sistemi di alerting personalizzati.

## Esempi di scenari d'attacco

**Scenario #1:** L'operatore del sito web di un fornitore di piani sanitari per bambini
non ha potuto rilevare una violazione a causa di una mancanza di logging e monitoraggio. Una
terza parte ha informato il fornitore del piano sanitario che un attaccante aveva
acceduto e modificato migliaia di cartelle cliniche di più di
3,5 milioni di bambini. Una indagine post-incidente ha rilevato che gli sviluppatori del sito web
non avevano corretto delle vulnerabilità significative presenti. Poiché non c'era
nessuna forma di logging o monitoraggio del sistema, la violazione dei dati potrebbe essere stata
in corso dal 2013, un periodo di più di sette anni.

**Scenario #2:** Una grande compagnia aerea indiana ha subito una violazione dei dati che ha coinvolto 
più di dieci anni di dati personali di milioni di passeggeri, compresi i dati dei passaporti e delle carte di credito. 
La violazione dei dati si è verificata presso un fornitore di hosting cloud di terze parti, 
che ha notificato la compagnia aerea della violazione dopo qualche tempo.

**Scenario #3:** Una grande compagnia aerea europea ha subito una violazione riferibile al GDPR. 
La violazione è stata causata da delle vulnerabilità dell'applicazione di pagamento 
sfruttate dagli aggressori, che hanno raccolto più di 400.000
record di pagamento dei clienti. A seguito di ciò, la compagnia aerea è stata multata 20 milioni di sterline 
dal garante della privacy.

## Riferimenti

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V8 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html))   

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Lista dei CWE correlati

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
