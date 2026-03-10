# A03:2025 Software Supply Chain Failures ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Contesto.

Questa categoria è risultata al primo posto nel sondaggio della community del Top 10, con esattamente il 50% dei rispondenti che la classificava al #1. Dalla sua prima comparsa nel Top 10 del 2013 come "A9 – Using Components with Known Vulnerabilities", il rischio è cresciuto fino a includere tutti i fallimenti della supply chain, non solo quelli che coinvolgono vulnerabilità note. Nonostante questo ambito ampliato, i fallimenti della supply chain continuano a essere difficili da identificare con solo 11 Common Vulnerability and Exposures (CVE) con le CWE correlate. Tuttavia, quando testata e riportata nei dati contribuiti, questa categoria ha il tasso medio di incidenza più alto al 5,19%. Le CWE rilevanti sono *CWE-477: Use of Obsolete Function, CWE-1104: Use of Unmaintained Third Party Components*, CWE-1329: *Reliance on Component That is Not Updateable*, e *CWE-1395: Dependency on Vulnerable Third-Party Component*.


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
   <td>6
   </td>
   <td>9,56%
   </td>
   <td>5,72%
   </td>
   <td>65,42%
   </td>
   <td>27,47%
   </td>
   <td>8,17
   </td>
   <td>5,23
   </td>
   <td>215.248
   </td>
   <td>11
   </td>
  </tr>
</table>



## Descrizione.

I fallimenti della supply chain del software sono interruzioni o altre compromissioni nel processo di costruzione, distribuzione o aggiornamento del software. Sono spesso causati da vulnerabilità o modifiche malevole nel codice di terze parti, negli strumenti o in altre dipendenze su cui il sistema si basa.

È probabile che tu sia vulnerabile se:

* non monitori attentamente le versioni di tutti i componenti che utilizzi (sia lato client che lato server). Ciò include i componenti che utilizzi direttamente e le dipendenze annidate (transitive).
* il software è vulnerabile, non supportato o non aggiornato. Ciò include OS, server web/applicativi, DBMS, applicazioni, API e tutti i componenti, ambienti di runtime e librerie.
* non effettui scansioni regolari per le vulnerabilità e non ti abboni ai bollettini di sicurezza relativi ai componenti che utilizzi.
* non disponi di un processo di gestione delle modifiche o di monitoraggio delle modifiche all'interno della tua supply chain, incluso il monitoraggio di IDE, estensioni e aggiornamenti IDE, modifiche al repository di codice della tua organizzazione, sandbox, repository di immagini e librerie, il modo in cui gli artifact vengono creati e archiviati, ecc. Ogni parte della tua supply chain deve essere documentata, soprattutto le modifiche.
* non hai rafforzato ogni parte della tua supply chain, con particolare attenzione al controllo degli accessi e all'applicazione del minimo privilegio.
* i sistemi della tua supply chain non hanno alcuna separazione dei compiti. Nessuna singola persona dovrebbe poter scrivere codice e promuoverlo fino in produzione senza la supervisione di un'altra persona.
* vengono utilizzati componenti da fonti non attendibili, in qualsiasi parte dello stack tecnologico, o possono impattare gli ambienti di produzione.
* non correggi o aggiorni la piattaforma sottostante, i framework e le dipendenze in modo tempestivo e basato sul rischio. Ciò accade comunemente in ambienti dove le patch sono un'attività mensile o trimestrale sotto controllo delle modifiche, lasciando le organizzazioni esposte per giorni o mesi prima di correggere le vulnerabilità.
* gli sviluppatori software non testano la compatibilità delle librerie aggiornate, aggiornate o patchate.
* non metti in sicurezza le configurazioni di ogni parte del tuo sistema (vedi [A02:2025-Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
* la tua pipeline CI/CD ha una sicurezza più debole rispetto ai sistemi che costruisce e distribuisce, specialmente se è complessa.


## Come prevenire.

Deve essere in atto un processo di gestione delle patch per:



* Generare e gestire centralmente il Software Bill of Materials (SBOM) dell'intero software.
* Monitorare non solo le dipendenze dirette, ma anche le loro dipendenze (transitive), e così via.
* Ridurre la superficie di attacco rimuovendo dipendenze non utilizzate, funzionalità, componenti, file e documentazione non necessari.
* Fare un inventario continuo delle versioni dei componenti sia lato client che lato server (es. framework, librerie) e delle loro dipendenze utilizzando strumenti come OWASP Dependency Track, OWASP Dependency Check, retire.js, ecc.
* Monitorare continuamente fonti come Common Vulnerability and Exposures (CVE), National Vulnerability Database (NVD) e [Open Source Vulnerabilities (OSV)](https://osv.dev/) per le vulnerabilità nei componenti utilizzati. Utilizzare software composition analysis, supply chain del software o strumenti SBOM orientati alla sicurezza per automatizzare il processo. Abbonarsi agli alert per le vulnerabilità di sicurezza relative ai componenti utilizzati.
* Ottenere componenti solo da fonti ufficiali (attendibili) tramite link sicuri. Preferire pacchetti firmati per ridurre la possibilità di includere un componente modificato e malevolo (vedi [A08:2025-Software and Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
* Scegliere deliberatamente quale versione di una dipendenza utilizzare e aggiornare solo quando necessario.
* Monitorare le librerie e i componenti non mantenuti o che non creano patch di sicurezza per le versioni più vecchie. Se le patch non sono possibili, considerare la migrazione a un'alternativa. Se non è possibile, considerare l'implementazione di una virtual patch per monitorare, rilevare o proteggere dal problema scoperto.
* Aggiornare regolarmente CI/CD, IDE e qualsiasi altro strumento di sviluppo.
* Evitare di distribuire aggiornamenti a tutti i sistemi contemporaneamente. Utilizzare rollout graduali o canary deployment per limitare l'esposizione in caso di compromissione di un vendor attendibile.


Deve essere in atto un processo di gestione delle modifiche o un sistema di monitoraggio per tracciare le modifiche a:

* Impostazioni CI/CD (tutti gli strumenti di build e pipeline)
* Repository di codice
* Aree sandbox
* IDE degli sviluppatori
* Strumenti SBOM e artifact creati
* Sistemi di logging e log
* Integrazioni di terze parti, come SaaS
* Repository di artifact
* Container registry


Rafforzare i seguenti sistemi, inclusa l'abilitazione di MFA e il blocco degli IAM:

* Il repository di codice (che include il non inserimento di segreti, la protezione dei branch, i backup)
* Le workstation degli sviluppatori (patch regolari, MFA, monitoraggio e altro)
* Il server di build e CI/CD (separazione dei compiti, controllo degli accessi, build firmate, segreti con scope per ambiente, log a prova di manomissione e altro)
* Gli artifact (garantire l'integrità tramite provenienza, firma e timestamp, promuovere gli artifact piuttosto che ricostruirli per ogni ambiente, garantire che le build siano immutabili)
* L'infrastruttura come codice (gestita come tutto il codice, incluso l'uso di PR e controllo delle versioni)

Ogni organizzazione deve garantire un piano continuo per il monitoraggio, il triage e l'applicazione di aggiornamenti o modifiche di configurazione per tutta la durata dell'applicazione o del portfolio.


## Scenari di attacco di esempio.

**Scenario #1:** Un vendor attendibile viene compromesso con malware, portando alla compromissione dei tuoi sistemi informatici quando esegui l'aggiornamento. L'esempio più famoso di questo è probabilmente:



* La compromissione di SolarWinds nel 2019 che ha portato alla compromissione di circa 18.000 organizzazioni. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Scenario #2:** Un vendor attendibile viene compromesso in modo tale da comportarsi in modo malevolo solo sotto una condizione specifica.



* Il furto di 1,5 miliardi di dollari da Bybit nel 2025 è stato causato da [un attacco alla supply chain nel software del wallet](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/) che veniva eseguito solo quando il wallet target era in uso.

**Scenario #3:** Il [supply chain attack `Shai-Hulud`](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) nel 2025 è stato il primo worm npm auto-propagante di successo. Gli attacchi hanno seminato versioni malevole di pacchetti popolari, che utilizzavano uno script post-install per raccogliere ed esfiltrare dati sensibili in repository GitHub pubblici. Il malware rilevava anche i token npm nell'ambiente vittima e li utilizzava automaticamente per pubblicare versioni malevole di qualsiasi pacchetto accessibile. Il worm ha raggiunto oltre 500 versioni di pacchetti prima di essere interrotto da npm. Questo attacco alla supply chain era avanzato, a diffusione rapida e dannoso, e prendendo di mira le macchine degli sviluppatori ha dimostrato che gli sviluppatori stessi sono ora obiettivi primari degli attacchi alla supply chain.

**Scenario #4:** I componenti tipicamente vengono eseguiti con gli stessi privilegi dell'applicazione stessa, quindi le falle in qualsiasi componente possono avere un impatto grave. Tali falle possono essere accidentali (es. errore di codice) o intenzionali (es. una backdoor in un componente). Alcuni esempi di vulnerabilità di componenti sfruttabili scoperte sono:

* CVE-2017-5638, una vulnerabilità di remote code execution in Struts 2 che consente l'esecuzione di codice arbitrario sul server, è stata imputata a violazioni significative.
* CVE-2021-44228 ("Log4Shell"), una vulnerabilità zero-day di remote code execution in Apache Log4j, è stata imputata a campagne di ransomware, cryptomining e altri attacchi.


## Riferimenti

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)


## Lista delle CWE Mappate

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)
* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)
* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)
* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
