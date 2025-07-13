# A04:2021 – Insecure Design   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} 

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## Panoramica

Una nuova categoria per il 2021 si concentra sui rischi legati ai difetti di progettazione e di architettura, con un appello per un maggiore uso del threat modeling, dei design pattern sicuri e delle architetture di riferimento. Come comunità dobbiamo andare oltre lo "spostamento a sinistra" nel processo di sviluppo per svolgere attività preliminari che sono fondamentali per i principi di Secure by Design. Le Common Weakness Enumerations (CWEs) incluse sono *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation*, and *CWE-522: Insufficiently Protected Credentials*.

## Descrizione

Insecure design è un'ampia categoria che rappresenta diverse debolezze, espressa come "progettazione inefficace o mancante dei controlli di sicurezza". Il design insicuro non è la fonte di tutte le altre categorie di rischio nella Top 10. Design insicuro e implementazione insicura sono differenti. Distinguiamo tra difetti di progettazione e difetti di implementazione per un motivo: hanno cause e rimedi diversi. Un design sicuro può ancora avere difetti di implementazione che portano a vulnerabilità che possono essere sfruttate. Un design insicuro non può essere corretto da un'implementazione perfetta, poiché per definizione, i controlli di sicurezza necessari non sono mai stati creati per difendersi da attacchi specifici. Uno dei fattori che contribuiscono al design insicuro è la mancanza di un profilo di rischio aziendale inerente al software o al sistema che viene sviluppato, e quindi il fallimento nel determinare quale livello di security design è richiesto.

### Requisiti e gestione delle risorse

Raccogliere e negoziare i requisiti di business per un'applicazione con l'azienda, compresi i requisiti di protezione relativi a riservatezza, integrità, disponibilità e autenticità di tutte le risorse di dati e la logica di business prevista. Prendete in considerazione quanto sarà esposta la vostra applicazione e se avete bisogno della segregazione dei tenants (oltre al controllo degli accessi). Compilare i requisiti tecnici, compresi i requisiti di sicurezza funzionali e non funzionali. Pianificare e negoziare il budget che copre tutte le attività di progettazione, costruzione, test e funzionamento, comprese quelle di sicurezza.

### Secure Design

Il secure design è una cultura e una metodologia che valuta costantemente le minacce e assicura che il codice sia progettato e testato in modo robusto per prevenire attacchi conosciuti. La fase di threat modeling dovrebbe essere integrata nelle sessioni di perfezionamento (o attività simili); prestare particolare attenzione ai cambiamenti nei flussi di dati e nel controllo degli accessi o altri controlli di sicurezza. Nello sviluppo della user story determinare il flusso corretto e gli stati considerati invalidi, assicurarsi che siano ben compresi e concordati dalle parti responsabili e interessate. Analizzare i presupposti e le condizioni per i flussi attesi e non attesi, assicurarsi che siano ancora accurati e auspicabili. Determinare come convalidare i presupposti e applicare le condizioni necessarie per i comportamenti corretti. Assicurarsi che i risultati siano documentati nella user story. Imparare dagli errori e offrire incentivi positivi per promuovere i miglioramenti. La progettazione sicura non è né un add-on né uno strumento che si può aggiungere al software.

### Secure Development Lifecycle

Il software sicuro richiede un ciclo di vita di sviluppo sicuro, una qualche forma di modello di progettazione sicuro, una metodologia paved road, una libreria di componenti sicura, strumenti e threat modeling. Rivolgetevi agli specialisti della sicurezza all'inizio di un progetto software per tutto il progetto e la manutenzione del vostro software. Considerate di sfruttare il [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) per aiutare a strutturare i vostri sforzi di sviluppo del software sicuro.

## Come prevenire

-   Stabilire e utilizzare un ciclo di vita di sviluppo sicuro con i professionisti di AppSec
    per aiutare a valutare e progettare la sicurezza e i controlli relativi alla privacy

-   Stabilire e utilizzare una libreria di design pattern sicuri o
    componenti pronti all'uso

-   Usare il threat modeling per i componenti di autenticazione più critici, il controllo     dell'accesso, logica di business e flussi chiave

-   Integrare il linguaggio e i controlli di sicurezza nelle user stories

-   Integrare i controlli di plausibilità ad ogni livello della vostra applicazione
    (dal frontend al backend)

-   Scrivere test unitari e di integrazione per convalidare che tutti i flussi critici 
    siano resistenti al modello di minaccia rappresentato. Compilare i casi d'uso *e* i casi di uso improprio per ogni livello della vostra applicazione.

-   Segregare i tier su livelli di sistema e di rete a seconda delle
    esigenze di esposizione e protezione.

-   Segregare i tenant in modo robusto by design in tutti i tier.

-   Limitare il consumo di risorse per utente o servizio

## Esempi di scenari d'attacco

**Scenario #1:**  Un flusso per il recupero delle credenziali potrebbe includere "domande
e risposte", che è proibito da NIST 800-63b, OWASP ASVS e
OWASP Top 10. Domande e risposte non possono essere attendibili come prova di
identità in quanto più di una persona può conoscere le risposte, ed è per questo che sono
state proibite. Tale codice dovrebbe essere rimosso e sostituito con un design più
più sicuro.

**Scenario #2:** Una catena di cinema permette sconti per prenotazioni di gruppo e ha un
massimo di quindici partecipanti prima di richiedere un pagamento. Gli attaccanti potrebbero
svolgere il threat modeling di questo flusso e testare se possono prenotare seicento posti in
tutti i cinema in una volta sola con poche richieste, causando una massiccia perdita di incassi.

**Scenario #3:** Il sito di e-commerce di una catena di negozi non ha
protezione contro i bot gestiti da scalper che comprano schede video di fascia alta per
rivenderle su siti di aste online. Questo crea una terribile pubblicità per i produttori di schede video e i proprietari di catene di vendita al dettaglio e il perdurare del cattivo sangue con
appassionati che non possono acquistare queste schede in nessun modo. Un'attenta progettazione anti-bot e regole di logica di dominio, come gli acquisti effettuati entro pochi
secondi dalla disponibilità, potrebbero identificare gli acquisti non autentici e
respingere tali transazioni.

## Riferimenti

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## Lista dei CWE correlati

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)
