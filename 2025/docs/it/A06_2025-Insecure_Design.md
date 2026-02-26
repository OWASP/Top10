# A06:2025 Insecure Design ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}


## Contesto.

L'Insecure Design scende di due posizioni dal #4 al #6 nella classifica mentre **[A02:2025-Security Misconfiguration](A02_2025-Security_Misconfiguration.md)** e **[A03:2025-Software Supply Chain Failures](A03_2025-Software_Supply_Chain_Failures.md)** la superano. Questa categoria è stata introdotta nel 2021 e abbiamo visto miglioramenti evidenti nel settore relativi al threat modeling e una maggiore enfasi sulla progettazione sicura. Questa categoria si concentra sui rischi legati a falle di design e architetturali, con un appello a un maggiore utilizzo del threat modeling, di pattern di design sicuro e di architetture di riferimento. Ciò include falle nella logica di business di un'applicazione, es. la mancanza di definizione di cambiamenti di stato indesiderati o imprevisti all'interno di un'applicazione. Come community, dobbiamo andare oltre lo "shift-left" nello spazio del codice, verso attività pre-codice come la stesura dei requisiti e la progettazione dell'applicazione, che sono critiche per i principi di Secure by Design (es. vedi **[Establish a Modern AppSec Program: Planning and Design Phase](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**). Le CWE notevoli includono *CWE-256: Unprotected Storage of Credentials, CWE-269 Improper Privilege Management, CWE-434 Unrestricted Upload of File with Dangerous Type, CWE-501: Trust Boundary Violation, e CWE-522: Insufficiently Protected Credentials.*


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
   <td>39
   </td>
   <td>22,18%
   </td>
   <td>1,86%
   </td>
   <td>88,76%
   </td>
   <td>35,18%
   </td>
   <td>6,96
   </td>
   <td>4,05
   </td>
   <td>729.882
   </td>
   <td>7.647
   </td>
  </tr>
</table>



## Descrizione.

L'Insecure Design è una categoria ampia che rappresenta diverse debolezze, espresse come "progettazione dei controlli mancante o inefficace". L'Insecure Design non è la fonte di tutte le altre categorie di rischio del Top Ten. Si noti che c'è una differenza tra Insecure Design e implementazione non sicura. Distinguiamo tra falle di design e difetti di implementazione per una ragione: hanno cause principali diverse, si verificano in momenti diversi nel processo di sviluppo e hanno rimedi diversi. Un design sicuro può ancora avere difetti di implementazione che portano a vulnerabilità sfruttabili. Un design non sicuro non può essere corretto da un'implementazione perfetta poiché i controlli di sicurezza necessari non sono mai stati creati per difendersi da attacchi specifici. Uno dei fattori che contribuisce all'Insecure Design è la mancanza di profilazione del rischio di business inerente al software o al sistema in fase di sviluppo, e quindi il fallimento nel determinare quale livello di progettazione della sicurezza è richiesto.

Tre parti fondamentali per avere un design sicuro sono:

* Raccolta dei Requisiti e Gestione delle Risorse
* Creazione di un Design Sicuro
* Un Secure Development Lifecycle


### Requisiti e Gestione delle Risorse

Raccogliere e negoziare i requisiti di business per un'applicazione con il business, inclusi i requisiti di protezione riguardanti la riservatezza, l'integrità, la disponibilità e l'autenticità di tutti i data asset e la logica di business prevista. Tenere conto di quanto sarà esposta la tua applicazione e se hai bisogno di segregazione dei tenant (oltre a quelle necessarie per il controllo degli accessi). Compilare i requisiti tecnici, inclusi i requisiti di sicurezza funzionali e non funzionali. Pianificare e negoziare il budget coprendo tutto il design, la costruzione, il testing e l'operatività, incluse le attività di sicurezza.


### Design Sicuro

Il design sicuro è una cultura e una metodologia che valuta costantemente le minacce e garantisce che il codice sia progettato e testato in modo robusto per prevenire metodi di attacco noti. Il threat modeling dovrebbe essere integrato nelle sessioni di refinement (o attività simili); cercare i cambiamenti nei flussi di dati e nel controllo degli accessi o in altri controlli di sicurezza. Nello sviluppo delle user story, determinare il flusso corretto e gli stati di fallimento, assicurarsi che siano ben compresi e concordati dalle parti responsabili e interessate. Analizzare le assunzioni e le condizioni per i flussi previsti e di fallimento per garantire che rimangano accurate e desiderabili. Determinare come validare le assunzioni e applicare le condizioni necessarie per i comportamenti corretti. Assicurarsi che i risultati siano documentati nella user story. Imparare dagli errori e offrire incentivi positivi per promuovere i miglioramenti. Il design sicuro non è né un componente aggiuntivo né uno strumento che puoi aggiungere al software.


### Secure Development Lifecycle

Il software sicuro richiede un secure development lifecycle, un pattern di design sicuro, una metodologia "paved road", una libreria di componenti sicuri, strumenti appropriati, threat modeling e post-mortem degli incidenti che vengono utilizzati per migliorare il processo. Contatta i tuoi specialisti della sicurezza all'inizio di un progetto software, durante il progetto e per la manutenzione continuativa del software. Considera di sfruttare l'[OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/) per aiutare a strutturare i tuoi sforzi di sviluppo software sicuro.

Spesso l'auto-responsabilità degli sviluppatori è sottovalutata. Favorire una cultura di consapevolezza, responsabilità e mitigazione proattiva dei rischi. Scambi regolari sulla sicurezza (es. durante le sessioni di threat modeling) possono generare una mentalità che include la sicurezza in tutte le decisioni di design importanti.


## Come prevenire.



* Stabilire e utilizzare un secure development lifecycle con professionisti AppSec per aiutare a valutare e progettare controlli di sicurezza e privacy
* Stabilire e utilizzare una libreria di pattern di design sicuro o componenti "paved-road"
* Utilizzare il threat modeling per le parti critiche dell'applicazione come autenticazione, controllo degli accessi, logica di business e flussi chiave
* Utilizzare il threat modeling come strumento educativo per generare una mentalità di sicurezza
* Integrare il linguaggio e i controlli di sicurezza nelle user story
* Integrare controlli di plausibilità a ogni livello dell'applicazione (dal frontend al backend)
* Scrivere test unitari e di integrazione per validare che tutti i flussi critici siano resistenti al modello di minaccia. Compilare use-case *e* misuse-case per ogni livello dell'applicazione.
* Segregare i livelli del sistema e della rete a seconda dell'esposizione e delle esigenze di protezione
* Segregare i tenant in modo robusto by design attraverso tutti i livelli


## Scenari di attacco di esempio.

**Scenario #1:** Un flusso di recupero delle credenziali potrebbe includere "domande e risposte", che è vietato da NIST 800-63b, dall'OWASP ASVS e dall'OWASP Top 10. Le domande e risposte non possono essere considerate attendibili come prova di identità, poiché più di una persona può conoscere le risposte. Tale funzionalità dovrebbe essere rimossa e sostituita con un design più sicuro.

**Scenario #2:** Una catena cinematografica consente sconti per prenotazioni di gruppo e ha un massimo di quindici partecipanti prima di richiedere un deposito. Gli attaccanti potrebbero fare threat modeling di questo flusso e testare se riescono a trovare un vettore di attacco nella logica di business dell'applicazione, es. prenotare seicento posti e tutti i cinema contemporaneamente in poche richieste, causando una massiccia perdita di reddito.

**Scenario #3:** Il sito di e-commerce di una catena retail non ha protezione contro bot usati da scalper per acquistare schede video di fascia alta da rivendere su siti di aste. Questo crea pubblicità terribile per i produttori di schede video e i proprietari delle catene retail, e risentimenti duraturi con gli appassionati che non riescono a ottenere queste schede a nessun prezzo. Un attento design anti-bot e regole di logica di dominio, come acquisti effettuati entro pochi secondi dalla disponibilità, potrebbero identificare acquisti non autentici e rifiutare tali transazioni.


## Riferimenti.



* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## Lista delle CWE Mappate

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)
