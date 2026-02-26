# A08:2025 Software or Data Integrity Failures ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Contesto.

Software or Data Integrity Failures continua all'#8, con una leggera modifica chiarificatrice del nome da "Software *and* Data Integrity Failures". Questa categoria si concentra sul fallimento nel mantenimento dei confini di fiducia e nella verifica dell'integrità di software, codice e artefatti dati a un livello inferiore rispetto ai Software Supply Chain Failures. Questa categoria si concentra sulle assunzioni relative agli aggiornamenti software e ai dati critici, senza verificarne l'integrità. Le CWE notevoli includono *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*, *CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes*, e *CWE-502: Deserialization of Untrusted Data*.


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
   <td>14
   </td>
   <td>8,98%
   </td>
   <td>2,75%
   </td>
   <td>78,52%
   </td>
   <td>45,49%
   </td>
   <td>7,11
   </td>
   <td>4,79
   </td>
   <td>501.327
   </td>
   <td>3.331
   </td>
  </tr>
</table>



## Descrizione.

I fallimenti di integrità del software e dei dati riguardano codice e infrastruttura che non proteggono da codice o dati non validi o non attendibili trattati come attendibili e validi. Un esempio è dove un'applicazione si basa su plugin, librerie o moduli da fonti non attendibili, repository e content delivery network (CDN). Una pipeline CI/CD non sicura priva di controlli di integrità del software in consumo e fornitura può introdurre la possibilità di accesso non autorizzato, codice non sicuro o malevolo, o compromissione del sistema. Un altro esempio è una CI/CD che estrae codice o artefatti da luoghi non attendibili e/o non li verifica prima dell'uso (controllando la firma o un meccanismo simile). Infine, molte applicazioni ora includono funzionalità di aggiornamento automatico, dove gli aggiornamenti vengono scaricati senza una verifica dell'integrità sufficiente e applicati all'applicazione precedentemente attendibile. Gli attaccanti potrebbero potenzialmente caricare i propri aggiornamenti da distribuire ed eseguire su tutte le installazioni. Un altro esempio è dove oggetti o dati sono codificati o serializzati in una struttura che un attaccante può vedere e modificare, rendendoli vulnerabili alla deserializzazione non sicura.


## Come prevenire.



* Utilizzare firme digitali o meccanismi simili per verificare che il software o i dati provengano dalla fonte prevista e non siano stati alterati.
* Garantire che librerie e dipendenze, come npm o Maven, consumino solo repository attendibili. Se si ha un profilo di rischio più elevato, considerare l'hosting di un repository interno noto-buono e verificato.
* Garantire che ci sia un processo di revisione per le modifiche al codice e alla configurazione per minimizzare la possibilità che codice o configurazione malevoli vengano introdotti nella pipeline software.
* Garantire che la pipeline CI/CD abbia un'adeguata segregazione, configurazione e controllo degli accessi per garantire l'integrità del codice che scorre attraverso i processi di build e deploy.
* Garantire che dati serializzati non firmati o non cifrati non vengano ricevuti da client non attendibili e successivamente utilizzati senza qualche forma di controllo dell'integrità o firma digitale per rilevare manomissioni o replay dei dati serializzati.


## Scenari di attacco di esempio.

**Scenario #1 Inclusione di funzionalità web da una fonte non attendibile:** Un'azienda utilizza un provider di servizi esterno per fornire funzionalità di supporto. Per comodità, ha un mapping DNS per `myCompany.SupportProvider.com` verso `support.myCompany.com`. Ciò significa che tutti i cookie, inclusi i cookie di autenticazione, impostati sul dominio `myCompany.com` verranno ora inviati al provider di supporto. Chiunque abbia accesso all'infrastruttura del provider di supporto può rubare i cookie di tutti gli utenti che hanno visitato `support.myCompany.com` ed eseguire un attacco di session hijacking.

**Scenario #2 Aggiornamento senza firma:** Molti router domestici, set-top box, firmware di dispositivi e altri non verificano gli aggiornamenti tramite firmware firmato. Il firmware non firmato è un obiettivo crescente per gli attaccanti e si prevede che peggiorerà ulteriormente. Questa è una preoccupazione importante poiché molte volte non esiste alcun meccanismo per rimediare se non correggere in una versione futura e attendere che le versioni precedenti vengano dismesse.

**Scenario #3 Utilizzo di pacchetti da una fonte non attendibile:** Uno sviluppatore ha difficoltà a trovare la versione aggiornata di un pacchetto che sta cercando, quindi lo scarica non dal gestore di pacchetti regolare e attendibile, ma da un sito web online. Il pacchetto non è firmato, quindi non c'è opportunità di garantire l'integrità. Il pacchetto include codice malevolo.

**Scenario #4 Deserializzazione non sicura:** Un'applicazione React chiama una serie di microservizi Spring Boot. Essendo programmatori funzionali, hanno cercato di garantire che il loro codice sia immutabile. La soluzione a cui sono arrivati è serializzare lo stato dell'utente e passarlo avanti e indietro con ogni richiesta. Un attaccante nota la firma dell'oggetto Java "rO0" (in base64) e utilizza il [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) per ottenere l'esecuzione di codice remoto sul server applicativo.

## Riferimenti.

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)


## Lista delle CWE Mappate

* [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
* [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
* [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
* [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)
* [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
* [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)
* [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)
* [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)
* [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
* [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)
* [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
* [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
