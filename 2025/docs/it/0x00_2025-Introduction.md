![OWASP Logo](../assets/TOP_10_logo_Final_Logo_Colour.png)

# I Dieci Rischi di Sicurezza delle Applicazioni Web Più Critici

# Introduzione

Benvenuto all'8ª edizione dell'OWASP Top Ten!

Un enorme ringraziamento a tutti coloro che hanno contribuito con dati e prospettive nel sondaggio. Senza di voi, questa edizione non sarebbe stata possibile. **GRAZIE!**


## Presentazione dell'OWASP Top 10:2025



* [A01:2025 - Broken Access Control](A01_2025-Broken_Access_Control.md)
* [A02:2025 - Security Misconfiguration](A02_2025-Security_Misconfiguration.md)
* [A03:2025 - Software Supply Chain Failures](A03_2025-Software_Supply_Chain_Failures.md)
* [A04:2025 - Cryptographic Failures](A04_2025-Cryptographic_Failures.md)
* [A05:2025 - Injection](A05_2025-Injection.md)
* [A06:2025 - Insecure Design](A06_2025-Insecure_Design.md)
* [A07:2025 - Authentication Failures](A07_2025-Authentication_Failures.md)
* [A08:2025 - Software or Data Integrity Failures](A08_2025-Software_or_Data_Integrity_Failures.md)
* [A09:2025 - Security Logging & Alerting Failures](A09_2025-Security_Logging_and_Alerting_Failures.md)
* [A10:2025 - Mishandling of Exceptional Conditions](A10_2025-Mishandling_of_Exceptional_Conditions.md)


## Cosa è cambiato nel Top 10 per il 2025

Ci sono due nuove categorie e una consolidazione nel Top Ten per il 2025. Abbiamo lavorato per mantenere il focus sulla causa principale piuttosto che sui sintomi, per quanto possibile. Con la complessità dell'ingegneria del software e della sicurezza applicativa, è praticamente impossibile creare dieci categorie senza un certo livello di sovrapposizione.

![Mapping](../assets/2025-mappings.png)

* **[A01:2025 - Broken Access Control](A01_2025-Broken_Access_Control.md)** mantiene la sua posizione al #1 come rischio di sicurezza applicativa più grave; i dati contribuiti indicano che in media il 3,73% delle applicazioni testate presentava una o più delle 40 Common Weakness Enumeration (CWE) in questa categoria. Come indicato dalla linea tratteggiata nella figura sopra, la Server-Side Request Forgery (SSRF) è stata incorporata in questa categoria.
* **[A02:2025 - Security Misconfiguration](A02_2025-Security_Misconfiguration.md)** è salita dal #5 del 2021 al #2 nel 2025. Le configurazioni errate sono più prevalenti nei dati di questo ciclo. Il 3,00% delle applicazioni testate presentava una o più delle 16 CWE in questa categoria. Non sorprende, poiché l'ingegneria del software continua ad aumentare la quantità di comportamenti delle applicazioni basati su configurazioni.
* **[A03:2025 - Software Supply Chain Failures](A03_2025-Software_Supply_Chain_Failures.md)** è un'espansione di [A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) per includere una portata più ampia di compromissioni che si verificano all'interno o attraverso l'intero ecosistema di dipendenze software, sistemi di build e infrastrutture di distribuzione. Questa categoria è stata votata in modo schiacciante come principale preoccupazione nel sondaggio della community. Questa categoria ha 5 CWE e una presenza limitata nei dati raccolti, ma riteniamo che ciò sia dovuto alle difficoltà nel testing e speriamo che i metodi di testing raggiungano questo settore. Questa categoria ha il minor numero di occorrenze nei dati, ma anche i punteggi medi più alti per exploit e impatto tra i CVE.
* **[A04:2025 - Cryptographic Failures](A04_2025-Cryptographic_Failures.md)** scende di due posizioni dal #2 al #4 nella classifica. I dati contribuiti indicano che, in media, il 3,80% delle applicazioni presenta una o più delle 32 CWE in questa categoria. Questa categoria porta spesso a esposizione di dati sensibili o compromissione del sistema.
* **[A05:2025 - Injection](A05_2025-Injection.md)** scende di due posizioni dal #3 al #5 nella classifica, mantenendo la sua posizione relativa rispetto a Cryptographic Failures e Insecure Design. L'Injection è una delle categorie più testate, con il maggior numero di CVE associati alle 38 CWE in questa categoria. L'Injection include una gamma di problemi che va dalle vulnerabilità di Cross-site Scripting (alta frequenza/basso impatto) alla SQL Injection (bassa frequenza/alto impatto).
* **[A06:2025 - Insecure Design](A06_2025-Insecure_Design.md)** scende di due posizioni dal #4 al #6 nella classifica mentre Security Misconfiguration e Software Supply Chain Failures la superano. Questa categoria è stata introdotta nel 2021 e abbiamo registrato miglioramenti evidenti nel settore relativi al threat modeling e una maggiore enfasi sulla progettazione sicura.
* **[A07:2025 - Authentication Failures](A07_2025-Authentication_Failures.md)** mantiene la sua posizione al #7 con una leggera modifica del nome (in precedenza era "[Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)") per riflettere più accuratamente le 36 CWE in questa categoria. Questa categoria rimane importante, ma il maggiore utilizzo di framework standardizzati per l'autenticazione sembra avere effetti benefici sulle occorrenze di fallimenti di autenticazione.
* **[A08:2025 - Software or Data Integrity Failures](A08_2025-Software_or_Data_Integrity_Failures.md)** continua all'#8 nella lista. Questa categoria si concentra sul fallimento nel mantenimento dei confini di fiducia e nella verifica dell'integrità di software, codice e artefatti dati a un livello inferiore rispetto ai Software Supply Chain Failures.
* **[A09:2025 - Security Logging & Alerting Failures](A09_2025-Security_Logging_and_Alerting_Failures.md)** mantiene la sua posizione al #9. Questa categoria ha una leggera modifica del nome (in precedenza [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)) per enfatizzare l'importanza della funzionalità di alerting necessaria per indurre azioni appropriate sugli eventi di logging rilevanti. Un ottimo logging senza alerting è di valore minimo nell'identificazione degli incidenti di sicurezza. Questa categoria sarà sempre sottorappresentata nei dati ed è stata nuovamente votata in una posizione nella lista dai partecipanti al sondaggio della community.
* **[A10:2025 - Mishandling of Exceptional Conditions](A10_2025-Mishandling_of_Exceptional_Conditions.md)** è una nuova categoria per il 2025. Questa categoria contiene 24 CWE incentrate sulla gestione impropria degli errori, errori logici, "failing open" e altri scenari correlati derivanti da condizioni anomale che i sistemi possono incontrare.


## Metodologia

Questa edizione del Top Ten rimane informata dai dati, ma non guidata ciecamente da essi. Abbiamo classificato 12 categorie in base ai dati contribuiti e ne abbiamo consentite due da promuovere o evidenziare dalle risposte del sondaggio della community. Lo facciamo per una ragione fondamentale: esaminare i dati contribuiti equivale essenzialmente a guardare nel passato. I ricercatori di Application Security dedicano tempo all'identificazione di nuove vulnerabilità e allo sviluppo di nuovi metodi di testing. Ci vogliono settimane o anni per integrare questi test in strumenti e processi. Nel momento in cui possiamo testare in modo affidabile una debolezza su larga scala, potrebbero essere passati anni. Ci sono anche rischi importanti che potremmo non essere mai in grado di testare in modo affidabile e che sono presenti nei dati. Per bilanciare questa visione, utilizziamo un sondaggio della community per chiedere ai professionisti di Application Security e sviluppatori in prima linea cosa considerano rischi essenziali che potrebbero essere sottorappresentati nei dati di testing.


## Come sono strutturate le categorie

Alcune categorie sono cambiate rispetto alla precedente edizione dell'OWASP Top Ten. Ecco un riepilogo di alto livello delle modifiche alle categorie.

In questa iterazione, abbiamo richiesto dati senza restrizioni sulle CWE come abbiamo fatto per l'edizione 2021. Abbiamo chiesto il numero di applicazioni testate per un determinato anno (a partire dal 2021) e il numero di applicazioni con almeno un'istanza di una CWE trovata nel testing. Questo formato ci consente di monitorare quanto sia prevalente ogni CWE all'interno della popolazione di applicazioni. Ignoriamo la frequenza ai nostri fini; sebbene possa essere necessaria in altre situazioni, nasconde solo la prevalenza effettiva nella popolazione di applicazioni. Che un'applicazione abbia quattro istanze di una CWE o 4.000 non fa parte del calcolo per il Top Ten. Specialmente perché i tester manuali tendono a elencare una vulnerabilità una sola volta, indipendentemente da quante volte si ripete in un'applicazione, mentre i framework di testing automatizzato elencano ogni istanza di una vulnerabilità come unica. Siamo passati da circa 30 CWE nel 2017, a quasi 400 CWE nel 2021, a 589 CWE in questa edizione da analizzare nel dataset. Prevediamo di effettuare ulteriori analisi dei dati come supplemento in futuro. Questo significativo aumento del numero di CWE richiede modifiche al modo in cui le categorie sono strutturate.

Abbiamo trascorso diversi mesi a raggruppare e categorizzare le CWE e avremmo potuto continuare per mesi ulteriori. Ad un certo punto era necessario fermarsi. Esistono sia tipi di CWE legati alla causa principale che ai sintomi, dove i tipi di causa principale sono come "Cryptographic Failure" e "Misconfiguration" in contrasto con i tipi di sintomo come "Sensitive Data Exposure" e "Denial of Service". Abbiamo deciso di concentrarci sulla causa principale ogni volta che è possibile, in quanto è più logico per fornire indicazioni sull'identificazione e la rimediazione. Concentrarsi sulla causa principale anziché sul sintomo non è un concetto nuovo; il Top Ten è sempre stato un mix di sintomi e cause principali. Anche le CWE sono un mix di sintomi e cause principali; stiamo semplicemente essere più deliberati nel segnalarlo. C'è una media di 25 CWE per categoria in questa edizione, con il limite inferiore a 5 CWE per A03:2025-Software Supply Chain Failures e A09:2025 Security Logging and Alerting Failures fino a 40 CWE in A01:2025-Broken Access Control. Abbiamo deciso di limitare il numero di CWE in una categoria a 40. Questa struttura di categoria aggiornata offre ulteriori vantaggi formativi poiché le aziende possono concentrarsi sulle CWE che hanno senso per un determinato linguaggio/framework.

Ci è stato chiesto perché non passare a una lista di 10 CWE come Top 10, simile alle MITRE Top 25 Most Dangerous Software Weaknesses. Ci sono due ragioni principali per cui utilizziamo più CWE nelle categorie. In primo luogo, non tutte le CWE esistono in tutti i linguaggi di programmazione o framework. Questo causa problemi per gli strumenti e i programmi di formazione/sensibilizzazione poiché parte del Top Ten potrebbe non essere applicabile. La seconda ragione è che esistono più CWE per le vulnerabilità comuni. Ad esempio, ci sono più CWE per Injection generale, Command Injection, Cross-site Scripting, Hardcoded Passwords, Lack of Validation, Buffer Overflow, Cleartext Storage of Sensitive Information e molti altri. A seconda dell'organizzazione o del tester, potrebbero essere utilizzate diverse CWE. Utilizzando una categoria con più CWE possiamo contribuire ad alzare il livello di base e la consapevolezza dei diversi tipi di debolezze che possono verificarsi sotto un nome di categoria comune. In questa edizione del Top Ten 2025, ci sono 248 CWE all'interno delle 10 categorie. Ci sono un totale di 968 CWE nel [dizionario scaricabile da MITRE](https://cwe.mitre.org) al momento di questa pubblicazione.


## Come vengono utilizzati i dati per selezionare le categorie

Analogamente a quanto fatto per l'edizione 2021, abbiamo sfruttato i dati CVE per *Sfruttabilità* e *Impatto (Tecnico)*. Abbiamo scaricato OWASP Dependency Check ed estratto i punteggi CVSS di Exploit e Impact, raggruppandoli per CWE rilevanti elencate con i CVE. Ha richiesto una discreta quantità di ricerca e sforzo, poiché tutti i CVE hanno punteggi CVSSv2, ma ci sono difetti in CVSSv2 che CVSSv3 dovrebbe correggere. Dopo un certo punto nel tempo, a tutti i CVE viene assegnato anche un punteggio CVSSv3. Inoltre, gli intervalli di punteggio e le formule sono stati aggiornati tra CVSSv2 e CVSSv3.

In CVSSv2, sia Exploit che Impatto (Tecnico) potevano arrivare fino a 10,0, ma la formula li abbassava al 60% per Exploit e al 40% per Impact. In CVSSv3, il massimo teorico era limitato a 6,0 per Exploit e 4,0 per Impact. Con la ponderazione considerata, il punteggio di Impact è aumentato, quasi un punto e mezzo in media in CVSSv3, e la sfruttabilità è diminuita di quasi mezzo punto in media.

Ci sono circa 175k record (rispetto ai 125k del 2021) di CVE mappati a CWE nel National Vulnerability Database (NVD), estratti da OWASP Dependency Check. Inoltre, ci sono 643 CWE uniche mappate a CVE (rispetto alle 241 del 2021). Nell'ambito dei quasi 220k CVE estratti, 160k avevano punteggi CVSS v2, 156k avevano punteggi CVSS v3 e 6k avevano punteggi CVSS v4. Molti CVE hanno più punteggi, motivo per cui il totale supera i 220k.

Per il Top Ten 2025, abbiamo calcolato i punteggi medi di exploit e impact nel modo seguente. Abbiamo raggruppato tutti i CVE con punteggi CVSS per CWE e ponderato sia i punteggi di exploit che di impact in base alla percentuale della popolazione che aveva CVSSv3, nonché alla popolazione rimanente con punteggi CVSSv2, per ottenere una media complessiva. Abbiamo mappato queste medie alle CWE nel dataset da utilizzare come punteggi di Exploit e Impatto (Tecnico) per l'altra metà dell'equazione del rischio.

Perché non usare CVSS v4.0? Perché l'algoritmo di punteggio è stato modificato in modo sostanziale e non fornisce più facilmente i punteggi di *Exploit* o *Impact* come fanno CVSSv2 e CVSSv3. Tenteremo di trovare un modo per utilizzare il punteggio CVSS v4.0 nelle versioni future del Top Ten, ma non siamo riusciti a determinare un modo tempestivo per farlo per l'edizione 2025.


## Perché utilizziamo un sondaggio della community

I risultati nei dati sono in gran parte limitati a ciò che il settore riesce a testare in modo automatizzato. Parlate con un professionista esperto di AppSec e vi parleranno di cose che trovano e tendenze che vedono che non sono ancora nei dati. Ci vuole tempo perché le persone sviluppino metodologie di testing per certi tipi di vulnerabilità e poi ancora più tempo perché quei test vengano automatizzati ed eseguiti su una vasta popolazione di applicazioni. Tutto ciò che troviamo guarda nel passato e potrebbe mancare le tendenze dell'ultimo anno, che non sono presenti nei dati.

Per questo motivo, scegliamo solo otto delle dieci categorie dai dati perché sono incompleti. Le altre due categorie provengono dal sondaggio della community del Top 10. Permette ai professionisti in prima linea di votare per ciò che considerano i rischi più elevati che potrebbero non essere nei dati (e che potrebbero non essere mai espressi nei dati).


## Grazie ai nostri contributori di dati

Le seguenti organizzazioni (insieme a diversi donatori anonimi) hanno gentilmente donato dati per oltre 2,8 milioni di applicazioni per rendere questo il dataset di sicurezza applicativa più grande e completo. Senza di voi, questo non sarebbe stato possibile.

* Accenture (Praga)
* Anonimo (multipli)
* Bugcrowd
* Contrast Security
* CryptoNet Labs
* Intuitor SoftTech Services
* Orca Security
* Probely
* Semgrep
* Sonar
* usd AG
* Veracode
* Wallarm

## Autori principali
* Andrew van der Stock - X: [@vanderaj](https://x.com/vanderaj)
* Brian Glas - X: [@infosecdad](https://x.com/infosecdad)
* Neil Smithline - X: [@appsecneil](https://x.com/appsecneil)
* Tanya Janca - X: [@shehackspurple](https://x.com/shehackspurple)
* Torsten Gigler - Mastodon: [@torsten_gigler@infosec.exchange](https://infosec.exchange/@torsten_gigler)

## Segnala problemi e pull request

Si prega di segnalare eventuali correzioni o problemi:

### Link al progetto:
* [Homepage](https://owasp.org/www-project-top-ten/)
* [Repository GitHub](https://github.com/OWASP/Top10)
