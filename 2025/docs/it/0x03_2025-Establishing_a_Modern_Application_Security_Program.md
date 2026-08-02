# Stabilire un Programma Moderno di Sicurezza Applicativa

Le liste OWASP Top Ten sono documenti di sensibilizzazione, pensati per portare attenzione sui rischi più critici di qualsiasi argomento trattino. Non sono pensate come lista completa, ma solo come punto di partenza. Nelle versioni precedenti di questa lista abbiamo prescritto l'avvio di un programma di sicurezza applicativa come il modo migliore per evitare questi rischi e altro ancora. In questa sezione tratteremo come avviare e costruire un programma moderno di sicurezza applicativa.

Se hai già un programma di sicurezza applicativa, considera di eseguire una valutazione della maturità utilizzando [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) o DSOMM (DevSecOps Maturity Model). Questi modelli di maturità sono completi ed esaustivi e possono essere utilizzati per aiutarti a capire dove dovresti concentrare al meglio i tuoi sforzi per espandere e maturare il tuo programma. Nota: non devi fare tutto ciò che è in OWASP SAMM o DSOMM per svolgere un buon lavoro; sono pensati per guidarti e offrire molte opzioni. Non sono pensati per offrire standard irraggiungibili o descrivere programmi inaccessibili. Sono ampi per offrirti molte idee e opzioni.

Se stai iniziando un programma da zero, o se trovi OWASP SAMM o DSOMM "troppo" per il tuo team al momento, ti preghiamo di rivedere i seguenti consigli.


### 1. Stabilire un Approccio al Portfolio Basato sul Rischio:

* Identificare le esigenze di protezione del portfolio applicativo da una prospettiva aziendale. Questo dovrebbe essere guidato in parte dalle leggi sulla privacy e da altre normative pertinenti all'asset di dati da proteggere.

* Stabilire un [modello comune di valutazione del rischio](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) con un insieme coerente di fattori di probabilità e impatto che rifletta la tolleranza al rischio dell'organizzazione.

* Misurare e dare priorità di conseguenza a tutte le applicazioni e API. Aggiungere i risultati al proprio [Configuration Management Database (CMDB)](https://de.wikipedia.org/wiki/Configuration_Management_Database).

* Stabilire linee guida di assurance per definire correttamente la copertura e il livello di rigore richiesto.


### 2. Abilitare con una Base Solida:

* Stabilire un insieme di policy e standard mirati che forniscano una baseline di sicurezza applicativa a cui tutti i team di sviluppo devono aderire.

* Definire un insieme comune di controlli di sicurezza riutilizzabili che complementino queste policy e standard e forniscano indicazioni di progettazione e sviluppo sul loro utilizzo.

* Stabilire un curriculum di formazione sulla sicurezza applicativa che sia obbligatorio e mirato a diversi ruoli di sviluppo e argomenti.


### 3. Integrare la Sicurezza nei Processi Esistenti:

* Definire e integrare attività di implementazione e verifica sicura nei processi di sviluppo e operativi esistenti.

* Le attività includono threat modeling, progettazione sicura e revisione del design, codifica sicura e code review, penetration testing e remediation.

* Fornire esperti in materia e servizi di supporto ai team di sviluppo e di progetto per avere successo.

* Rivedere il ciclo di vita dello sviluppo del sistema attuale e tutte le attività di sicurezza del software, strumenti, policy e processi, quindi documentarli.

* Per il nuovo software, aggiungere una o più attività di sicurezza a ogni fase del ciclo di vita dello sviluppo del sistema (SDLC). Di seguito offriamo molti suggerimenti su cosa è possibile fare. Assicurarsi di eseguire queste nuove attività su ogni nuovo progetto o iniziativa software, in modo da sapere che ogni nuovo software sarà consegnato con una postura di sicurezza accettabile per la propria organizzazione.

* Selezionare le attività per garantire che il prodotto finale soddisfi un livello di rischio accettabile per l'organizzazione.

* Per il software esistente (a volte chiamato legacy) è necessario avere un piano di manutenzione formale; consultare di seguito le idee su come mantenere le applicazioni sicure nella sezione "Operazioni e Gestione dei Cambiamenti".


### 4. Formazione sulla Sicurezza Applicativa:

* Considerare di avviare un programma di security champion, o un programma generale di formazione sulla sicurezza per gli sviluppatori (a volte chiamato programma di advocacy o di sensibilizzazione alla sicurezza), per insegnare loro tutto ciò che si vorrebbe che sapessero. Questo li terrà aggiornati, li aiuterà a sapere come svolgere il loro lavoro in modo sicuro e renderà più positiva la cultura della sicurezza nel luogo di lavoro. Spesso migliora anche la fiducia tra i team e crea un rapporto di lavoro più sereno. OWASP ti supporta in questo con la [OWASP Security Champions Guide](https://securitychampions.owasp.org/), che viene ampliata passo dopo passo.

* Il Progetto OWASP Education fornisce materiali di formazione per aiutare a educare gli sviluppatori sulla sicurezza delle applicazioni web. Per l'apprendimento pratico sulle vulnerabilità, provare [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/), o [OWASP WebGoat](https://owasp.org/www-project-webgoat/). Per rimanere aggiornati, partecipare a una [Conferenza OWASP AppSec](https://owasp.org/events/), a [OWASP Conference Training](https://owasp.org/events/), o alle riunioni del [capitolo OWASP](https://owasp.org/chapters/) locale.


### 5. Fornire Visibilità al Management:

* Gestire con le metriche. Guidare le decisioni di miglioramento e finanziamento basandosi sulle metriche e sui dati di analisi raccolti. Le metriche includono l'aderenza alle pratiche e alle attività di sicurezza, le vulnerabilità introdotte, le vulnerabilità mitigate, la copertura delle applicazioni, la densità dei difetti per tipo e conteggi delle istanze, ecc.

* Analizzare i dati delle attività di implementazione e verifica per cercare la causa radice e i pattern di vulnerabilità per guidare miglioramenti strategici e sistemici nell'intera azienda. Imparare dagli errori e offrire incentivi positivi per promuovere i miglioramenti.



## Stabilire e Utilizzare Processi di Sicurezza Ripetibili e Controlli di Sicurezza Standard

### Fase di Gestione dei Requisiti e delle Risorse:

* Raccogliere e negoziare i requisiti aziendali per un'applicazione con il business, inclusi i requisiti di protezione per quanto riguarda la riservatezza, l'autenticità, l'integrità e la disponibilità di tutti gli asset di dati, e la logica di business prevista.

* Compilare i requisiti tecnici inclusi i requisiti di sicurezza funzionali e non funzionali. OWASP raccomanda di utilizzare l'[OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) come guida per definire i requisiti di sicurezza per le proprie applicazioni.

* Pianificare e negoziare il budget che copre tutti gli aspetti di progettazione, costruzione, test e operazioni, incluse le attività di sicurezza.

* Aggiungere le attività di sicurezza al proprio calendario di progetto.

* Presentarsi come rappresentante della sicurezza al kick-off del progetto, in modo che sappiano con chi parlare.


### Richieste di Offerta (RFP) e Contrattualizzazione:

* Negoziare i requisiti con sviluppatori interni o esterni, incluse linee guida e requisiti di sicurezza rispetto al proprio programma di sicurezza, ad esempio SDLC, best practice.

* Valutare il soddisfacimento di tutti i requisiti tecnici, inclusa una fase di pianificazione e progettazione.

* Negoziare tutti i requisiti tecnici, inclusi progettazione, sicurezza e service level agreement (SLA).

* Adottare template e checklist, come [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex).<br>**Nota:** *L'annex è per la legge contrattuale statunitense, quindi si prega di consultare un consulente legale qualificato prima di utilizzare l'annex di esempio.*


### Fase di Pianificazione e Progettazione:

* Negoziare la pianificazione e la progettazione con gli sviluppatori e gli stakeholder interni, ad esempio gli specialisti di sicurezza.

* Definire l'architettura di sicurezza, i controlli, le contromisure e le revisioni del design appropriate alle esigenze di protezione e al livello di minaccia previsto. Questo dovrebbe essere supportato dagli specialisti di sicurezza.

* Piuttosto che inserire la sicurezza retroattivamente nelle applicazioni e nelle API, è molto più conveniente progettare la sicurezza fin dall'inizio. OWASP raccomanda le [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) e i [OWASP Proactive Controls](https://top10proactive.owasp.org/) come buon punto di partenza per le indicazioni su come progettare la sicurezza inclusa fin dall'inizio.

* Eseguire il threat modeling, vedere [OWASP Cheat Sheet: Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

* Insegnare agli architetti software i concetti e i pattern di progettazione sicura e chiedere loro di aggiungerli ai loro design ove possibile.

* Esaminare i flussi di dati con gli sviluppatori.

* Aggiungere user story di sicurezza accanto a tutte le altre user story.


### Secure Development Lifecycle:

* Per migliorare il processo che la propria organizzazione segue nella costruzione di applicazioni e API, OWASP raccomanda l'[OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/). Questo modello aiuta le organizzazioni a formulare e implementare una strategia per la sicurezza del software su misura per i rischi specifici che affrontano.

* Fornire formazione sulla codifica sicura agli sviluppatori software, e qualsiasi altra formazione che si ritiene possa aiutarli a creare applicazioni più robuste e sicure.

* Code review, vedere [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).

* Fornire agli sviluppatori strumenti di sicurezza, poi insegnare loro come usarli, in particolare analisi statica, analisi della composizione del software, secret scanner e scanner [Infrastructure-as-Code (IaC)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html).

* Creare guardrail per gli sviluppatori, se possibile (salvaguardie tecniche per orientarli verso scelte più sicure).

* Costruire controlli di sicurezza forti e utilizzabili è difficile. Offrire default sicuri quando possibile, e creare "strade asfaltate" (rendendo il modo più semplice anche il modo più sicuro per fare qualcosa, il modo preferito ovvio) quando possibile. Le [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) sono un buon punto di partenza per gli sviluppatori, e molti framework moderni ora includono controlli di sicurezza standard ed efficaci per autorizzazione, validazione, prevenzione CSRF, ecc.

* Fornire agli sviluppatori plugin IDE relativi alla sicurezza e incoraggiarli a utilizzarli.

* Fornire loro uno strumento di gestione dei segreti, licenze e documentazione su come utilizzarlo.

* Fornire loro un'AI privata da utilizzare, idealmente configurata con un server RAG pieno di documentazione di sicurezza utile, prompt scritti dal team per risultati migliori e un server MCP che chiama gli strumenti di sicurezza preferiti dell'organizzazione. Insegnare loro come usare l'AI in modo sicuro, perché lo faranno comunque.


### Stabilire Test Continui di Sicurezza Applicativa:

* Testare le funzioni tecniche e l'integrazione con l'architettura IT e coordinare i test aziendali.

* Creare casi di test "use" e "abuse" da prospettive tecniche e aziendali.

* Gestire i test di sicurezza in base ai processi interni, alle esigenze di protezione e al livello di minaccia presunto dell'applicazione.

* Fornire strumenti di test della sicurezza (fuzzer, DAST, ecc.), un luogo sicuro per testare e formazione su come usarli, OPPURE eseguire i test per loro OPPURE assumere un tester.

* Se si richiede un alto livello di assurance, considerare un penetration test formale, nonché stress testing e performance testing.

* Lavorare con gli sviluppatori per aiutarli a decidere cosa devono correggere dai bug report e garantire che i loro manager concedano loro il tempo per farlo.


### Rollout:

* Mettere in funzione l'applicazione e migrare dalle applicazioni precedentemente utilizzate se necessario.

* Finalizzare tutta la documentazione, incluso il change management database (CMDB) e l'architettura di sicurezza.


### Operazioni e Gestione dei Cambiamenti:

* Le operazioni devono includere linee guida per la gestione della sicurezza dell'applicazione (ad esempio, patch management).

* Aumentare la consapevolezza della sicurezza degli utenti e gestire i conflitti tra usabilità e sicurezza.

* Pianificare e gestire i cambiamenti, ad esempio migrare a nuove versioni dell'applicazione o di altri componenti come OS, middleware e librerie.

* Assicurarsi che tutte le app siano nell'inventario, con tutti i dettagli importanti documentati. Aggiornare tutta la documentazione, incluso il CMDB e l'architettura di sicurezza, i controlli e le contromisure, inclusi eventuali runbook o documentazione di progetto.

* Eseguire logging, monitoraggio e alerting per tutte le app. Aggiungerlo se manca.

* Creare processi per aggiornamenti e patch efficaci ed efficienti.

* Creare calendari di scansione regolari (idealmente dinamica, statica, segreti, IaC e analisi della composizione del software).

* SLA per la correzione dei bug di sicurezza.

* Fornire un modo per i dipendenti (e idealmente anche per i clienti) di segnalare bug.

* Stabilire un team di risposta agli incidenti addestrato che comprenda come appaiono gli attacchi e gli incidenti software, strumenti di osservabilità.

* Eseguire strumenti di blocco o protezione per fermare gli attacchi automatizzati.

* Hardening annuale (o più frequente) delle configurazioni.

* Penetration testing almeno annuale (a seconda del livello di assurance richiesto per la propria app).

* Stabilire processi e strumenti per l'hardening e la protezione della supply chain software.

* Stabilire e aggiornare la pianificazione della continuità operativa e del disaster recovery che includa le applicazioni più importanti e gli strumenti utilizzati per mantenerle.


### Dismissione dei Sistemi:

* Tutti i dati richiesti devono essere archiviati. Tutti gli altri dati devono essere eliminati in modo sicuro.

* Dismettere in modo sicuro l'applicazione, inclusa l'eliminazione di account, ruoli e permessi non utilizzati.

* Impostare lo stato dell'applicazione su "dismesso" nel CMDB.


## Utilizzo dell'OWASP Top 10 come Standard

L'OWASP Top 10 è principalmente un documento di sensibilizzazione. Tuttavia, questo non ha impedito alle organizzazioni di utilizzarlo come standard AppSec del settore de facto dalla sua nascita nel 2003. Se si desidera utilizzare l'OWASP Top 10 come standard di codifica o test, è bene sapere che è il minimo assoluto e solo un punto di partenza.

Una delle difficoltà nell'utilizzare l'OWASP Top 10 come standard è che documentiamo i rischi AppSec e non necessariamente problemi facilmente testabili. Ad esempio, [A06:2025-Insecure Design](A06_2025-Insecure_Design.md) va oltre la portata della maggior parte delle forme di testing. Un altro esempio è testare se il logging e il monitoraggio in atto, in uso ed efficaci sono implementati, il che può essere fatto solo con interviste e richiedendo un campionamento di risposte agli incidenti efficaci. Uno strumento di analisi statica del codice può cercare l'assenza di logging, ma potrebbe essere impossibile determinare se la logica di business o il controllo degli accessi stia registrando violazioni critiche della sicurezza. I penetration tester potrebbero essere in grado solo di determinare che hanno invocato la risposta agli incidenti in un ambiente di test, che viene raramente monitorato allo stesso modo della produzione.

Ecco le nostre raccomandazioni su quando è appropriato utilizzare l'OWASP Top 10:


<table>
  <tr>
   <td><strong>Caso d'Uso</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>OWASP Application Security Verification Standard</strong>
   </td>
  </tr>
  <tr>
   <td>Sensibilizzazione
   </td>
   <td>Sì
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Formazione
   </td>
   <td>Livello base
   </td>
   <td>Completo
   </td>
  </tr>
  <tr>
   <td>Progettazione e architettura
   </td>
   <td>Occasionalmente
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Standard di codifica
   </td>
   <td>Minimo indispensabile
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Secure Code review
   </td>
   <td>Minimo indispensabile
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Checklist di peer review
   </td>
   <td>Minimo indispensabile
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Unit testing
   </td>
   <td>Occasionalmente
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Integration testing
   </td>
   <td>Occasionalmente
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Penetration testing
   </td>
   <td>Minimo indispensabile
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Supporto degli strumenti
   </td>
   <td>Minimo indispensabile
   </td>
   <td>Sì
   </td>
  </tr>
  <tr>
   <td>Secure Supply Chain
   </td>
   <td>Occasionalmente
   </td>
   <td>Sì
   </td>
  </tr>
</table>


Incoraggiamo chiunque voglia adottare uno standard di sicurezza applicativa a utilizzare l'[OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS), poiché è progettato per essere verificabile e testato, e può essere utilizzato in tutte le parti di un ciclo di sviluppo sicuro.

L'ASVS è l'unica scelta accettabile per i vendor di strumenti. Gli strumenti non possono rilevare, testare o proteggere in modo completo contro l'OWASP Top 10 a causa della natura di alcuni dei rischi dell'OWASP Top 10, con riferimento a [A06:2025-Insecure Design](A06_2025-Insecure_Design.md). OWASP scoraggia qualsiasi affermazione di copertura completa dell'OWASP Top 10, perché è semplicemente non vera.
