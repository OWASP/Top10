# Introduzione alla OWASP Top 10 2021


## Vi presentiamo la the OWASP Top 10 - 2021

![OWASP Top 10 Logo](./assets/TOP_10_logo_Final_Logo_Colour.png){:class="img-responsive"}

Ecco a voi l'ultima versione della OWASP Top 10! La OWASP Top 10 2021 è tutta nuova, con un nuovo design grafico e un'infografica di una pagina che potete stampare o scaricare dalla nostra home page.

Un enorme grazie a tutti coloro che hanno contribuito con il loro tempo e i loro dati per questa versione. Senza di voi, tutto questo non sarebbe stato possibile. **GRAZIE!**

## Cosa è cambiato nella Top 10 2021

Ci sono tre nuove categorie, quattro categorie con cambiamenti nella denominazione e nello scopo, e alcuni consolidamenti nella Top 10 per il 2021. Quando necessario abbiamo cambiato i nomi per concentrarci più sulla causa principale anzichè sui sintomi.

![Mapping](assets/mapping.png)

- **[A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)** sale dalla quinta posizione alla categoria con il più grave rischio per la sicurezza delle applicazioni web; i dati analizzati indicano che in media, il 3,81% delle applicazioni testate aveva una o più Common Weakness Enumerations (CWEs) con più di 318k occorrenze di CWEs in questa categoria di rischio. Le 34 CWE che corrispondevano a Broken Access Control avevano più occorrenze di qualsiasi altra categoria.
- **[A02:2021-Cryptographic Failures](A02_2021-Cryptographic_Failures.md)** si sposta di una posizione alla #2, precedentemente nota come **A3:2017-Sensitive Data Exposure**, che era un sintomo generico piuttosto che la causa principale. Il nome rinnovato si concentra sulle problematiche relative alla crittografia come è stato prima, ma implicitamente. Questa categoria porta spesso all'esposizione di dati sensibili o alla compromissione del sistema.
- **[A03:2021-Injection](A03_2021-Injection.md)** scivola in terza posizione. Il 94% delle applicazioni è stato testato per qualche forma di injection con un tasso di incidenza massimo del 19%, un tasso di incidenza medio del 3,37%, e le 33 CWE che corrispondevano a questa categoria hanno il secondo maggior numero di occorrenze nelle applicazioni, con 274k. In questa edizione il Cross-site Scripting fa parte di questa categoria.
- **[A04:2021-Insecure Design](A04_2021-Insecure_Design.md)** è una nuova categoria per il 2021, con un focus sui rischi relativi ai difetti di progettazione. Se vogliamo veramente "spostarci a sinistra" come industria, abbiamo bisogno di più threat modeling, secure design patterns e architetture di riferimento. Un design insicuro non può essere corretto con un'implementazione perfetta, poiché per definizione i controlli di sicurezza necessari non sono mai stati creati per difendersi da attacchi specifici.
- **[A05:2021-Security Misconfiguration](A05_2021-Security_Misconfiguration.md)** sale dal numero 6 dell'edizione precedente; il 90% delle applicazioni è stato testato per qualche forma di misconfigurazione, con un tasso di incidenza medio del 4,5% e oltre 208k casi di CWE corrispondenti a questa categoria di rischio. Con una tendenza al software altamente configurabile, non è sorprendente vedere questa categoria salire. La precedente categoria per **A4:2017-XML External Entities (XXE)** è ora parte di questa categoria di rischio.
- **[A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)** era precedentemente intitolata "Using Components with Known Vulnerabilities" ed è #2 nel sondaggio della comunità Top 10, ma aveva anche abbastanza numeri per far parte della Top 10 grazie ai dati raccolti e analizzati. Questa categoria sale dalla #9 del 2017 ed è un problema noto per cui facciamo fatica a testare e a valutarne il rischio. È l'unica categoria a non avere alcun Common Vulnerability and Exposures (CVE) corrispondente alle CWE incluse, quindi nel punteggio è stato inserito un peso predefinito per sfruttabilità e impatto di 5.0.
- **[A07:2021-Identification and Authentication Failures](A07_2021-Identification_and_Authentication_Failures.md)** era precedentemente nota come "Broken Authentication" e sta scivolando giù dalla seconda posizione, e ora include CWEs che sono più legate a problematiche di identificazione. Questa categoria è ancora parte integrante della Top 10, ma la maggiore diffusione di framework standard sembra aiutare.
- **[A08:2021-Software and Data Integrity Failures](A08_2021-Software_and_Data_Integrity_Failures.md)** è una nuova categoria per il 2021, che si concentra sul fare ipotesi relative agli aggiornamenti del software, ai dati critici e alle pipeline CI/CD senza verificare l'integrità. Uno dei più alti impatti ponderati dai dati di Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) è stato messo in corrispondenza alle 10 CWE di questa categoria. **A8:2017-Insecure Deserialization** fa ora parte di questa categoria più ampia.
- **[A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)** era precedentemente **A10:2017-Insufficient Logging & Monitoring** e viene aggiunto dal sondaggio della comunità Top 10 (#3), passando dalla precedente #10. Questa categoria è stata ampliata per includere più tipi di problematiche, è difficile da testare e non è ben rappresentata nei dati CVE/CVSS. Tuttavia, le problematiche in questa categoria possono avere un impatto diretto sulla visibilità, sull'alerting degli incidenti e sulle attività forensi.
- **[A10:2021-Server-Side Request Forgery](A10_2021-Server-Side_Request_Forgery_(SSRF).md)** viene aggiunto dal sondaggio della comunità Top 10 (#1). I dati mostrano un tasso di incidenza relativamente basso con una copertura di test superiore alla media, insieme a valutazioni superiori alla media per il potenziale di sfruttabilità e di impatto. Questa categoria rappresenta lo scenario in cui i membri della nostra comunità ci stanno comunicando che è importante, anche se in questo momento non è evidente dai dati.

## Metodologia

Questa versione della Top 10 è più data-driven che mai, ma non ciecamente data-driven. Abbiamo selezionato otto delle dieci categorie dai dati forniti e due categorie dal sondaggio della comunità Top 10. Questo lo facciamo per una ragione fondamentale, guardare i dati forniti è guardare nel passato. I ricercatori nel campo dell'AppSec impiegano tempo per trovare nuove vulnerabilità e nuovi modi per testarle. Ci vuole tempo per integrare questi test negli strumenti e nei processi. Nel momento in cui possiamo testare in modo affidabile una debolezza su larga scala, probabilmente sono passati anni. Per bilanciare questo punto di vista, usiamo un sondaggio comunitario per chiedere agli esperti di sicurezza e sviluppatori di applicazioni in prima linea quali sono le debolezze essenziali che i dati potrebbero non mostrare ancora.

Ci sono alcuni cambiamenti importanti che abbiamo adottato per continuare a migliorare la Top 10.

## Come sono strutturate le categorie

Alcune categorie sono cambiate dalla precedente versione della Top Ten di OWASP. Ecco un riassunto ad alto livello dei cambiamenti relativi alle categorie.

I precedenti sforzi di raccolta dati erano focalizzati su un sottoinsieme prescritto di circa 30 CWE con un campo aperto che ne richiedeva altri. Abbiamo imparato che le organizzazioni si concentravano principalmente solo su quelle 30 CWE e raramente aggiungevano ulteriori CWE che avevano incontrato. In questa iterazione abbiamo chiesto solo dati, senza restrizioni sulle CWE. Abbiamo chiesto il numero di applicazioni testate per un dato anno (a partire dal 2017), e il numero di applicazioni con almeno un'istanza di una CWE trovata nei test. Questo formato ci permette di tracciare quanto sia prevalente ogni CWE all'interno della popolazione delle applicazioni. Per i nostri scopi ignoriamo la frequenza; mentre può essere necessaria per altre situazioni, nasconde solo la reale prevalenza nella popolazione delle applicazioni. Che un'applicazione abbia quattro istanze di una CWE o 4.000 istanze, questo valore non influisce nel calcolo per la Top 10. Siamo passati da circa 30 CWE a quasi 400 CWE da analizzare. In futuro abbiamo in programma di fare ulteriori analisi dei dati come integrazione. Questo aumento significativo del numero di CWE richiede cambiamenti nel modo in cui le categorie sono strutturate.

Abbiamo trascorso diversi mesi a raggruppare e categorizzare le CWE e avremmo potuto continuare per mesi. Ad un certo punto ci siamo dovuti fermare. Ci sono entrambi i tipi di CWE *causa principale* e *sintomo*, dove i tipi *causa principale* sono come "Cryptographic Failures" e "Misconfiguration" in contrasto con i tipi *sintomo* come "Sensitive Data Exposure" e "Denial of Service". Abbiamo deciso di concentrarci sulla *causa principale* ogni volta che è possibile, in quanto è più logico per fornire una guida all'identificazione e al rimedio. Concentrarsi sulla *causa principale* piuttosto che sul *sintomo* non è un concetto nuovo; la Top Ten è stata un mix di *sintomo* e *causa principale*. Anche le CWE sono un mix di *sintomo* e *causa principale*; siamo semplicemente più consapevoli di questo e lo diciamo ad alta voce. C'è una media di 19.6 CWE per categoria in questa versione, con i limiti inferiori a 1 CWE per **A10:2021-Server-Side Request Forgery (SSRF)** a 40 CWE in **A04:2021-Insecure Design**. Questa struttura aggiornata delle categorie offre ulteriori benefici per la formazione in quanto le aziende possono concentrarsi sulle CWE che hanno senso per un linguaggio/framework.

## Come vengono usati i dati per selezionare le categorie

Nel 2017, abbiamo selezionato le categorie in base al tasso di incidenza per determinare la probabilità, poi le abbiamo classificate in base alla discussione con il team sulla base di decenni di esperienza per *Exploitability*, *Detectability* (anche *likelihood*), e *Technical Impact*. Per il 2021, vogliamo usare i dati per *Exploitability* e *(Technical) Impact* se possibile.

Abbiamo scaricato OWASP Dependency Check ed estratto i punteggi CVSS relativi a Exploit e Impact raggruppati per CWE correlati. Ci sono voluti un bel po' di ricerche e sforzi, poiché tutti i CVE hanno punteggi CVSSv2, ma ci sono problematiche in CVSSv2 che CVSSv3 dovrebbe risolvere. Dopo un certo periodo di tempo, a tutti i CVE viene assegnato anche un punteggio CVSSv3. Inoltre, gli intervalli di punteggio e le formule sono stati aggiornati tra CVSSv2 e CVSSv3.

Nel CVSSv2, sia *Exploit* che *(Technical) Impact* potevano essere fino a 10.0, ma la formula li riduceva al 60% per *Exploit* e al 40% per *Impact*. Nel CVSSv3, il massimo teorico era limitato a 6.0 per *Exploit* e 4.0 per *Impact*. Con la ponderazione considerata, il punteggio di Impact si è spostato più in alto, quasi un punto e mezzo in media in CVSSv3, e l'exploitability si è spostato quasi mezzo punto più in basso in media.

Ci sono 125k record di una CVE corrispondente a una CWE nei dati del National Vulnerability Database (NVD) estratti da OWASP Dependency Check, e ci sono 241 CWE uniche corrispondenti a un CVE. 62k corrispondenze di CWE hanno un punteggio CVSSv3, che è circa la metà della popolazione nel set di dati.

Per la Top Ten 2021, abbiamo calcolato i punteggi medi di *Exploit* e *Impact* nel modo seguente. Abbiamo raggruppato tutte le CVE con punteggi CVSS per CWE e ponderato entrambi i punteggi di *Exploit* e *Impact* per la percentuale della popolazione che aveva CVSSv3 più la restante popolazione di punteggi CVSSv2 per ottenere una media complessiva. Abbiamo messo in corrispondenza queste medie alle CWE nel dataset da usare come punteggio di *Exploit* e *(Technical) Impact* per l'altra metà dell'equazione del rischio.

## Perchè non utilizzare dati puramente statistici?

I risultati nei dati sono principalmente limitati a ciò che possiamo testare in modo automatico. Parlate con un professionista esperto di AppSec e vi racconterà delle vulnerabilità che trova e delle tendenze che vede che non sono ancora visibili nei dati. Ci vuole tempo perché le persone sviluppino metodologie di test per certi tipi di vulnerabilità e poi ancora più tempo perché quei test siano automatizzati ed eseguiti su una vasta popolazione di applicazioni. Tutto ciò che troviamo sta guardando indietro nel passato e potrebbe mancare delle tendenze dell'ultimo anno, che non sono presenti nei dati.

Pertanto, prendiamo solo otto delle dieci categorie dai dati perché sono incompleti. Le altre due categorie provengono dal sondaggio della comunità Top 10. Questo permette ai professionisti in prima linea di votare per ciò che identificano come i rischi più alti che potrebbero non essere ancora visibili nei dati (e potrebbero non essere mai espressi nei dati).

## Perchè tasso di incidenza anzichè frequenza?

Ci sono tre fonti primarie di dati. Le identifichiamo come Human-assisted Tooling (HaT), Tool-assisted Human (TaH), e Tooling grezzo.

Tooling e HaT generano una grande quantità di dati. Gli strumenti cercheranno vulnerabilità specifiche e tenteranno instancabilmente di trovare ogni istanza di quella vulnerabilità e genereranno un numero elevato di risultati per alcuni tipi di vulnerabilità. Guardate il Cross-Site Scripting, che è tipicamente di due tipi: o è un errore piccolo e isolato o un problema sistemico. Quando si tratta di un problema sistemico, il conteggio può essere di migliaia per una singola applicazione. Questa alta frequenza copre la maggior parte delle altre vulnerabilità trovate nei report o nei dati.

TaH, d'altra parte, troverà una gamma più ampia di tipi di vulnerabilità, ma con una frequenza molto più bassa a causa dei vincoli temporali. Quando gli esseri umani testano un'applicazione e identificano problematiche come il Cross-Site Scripting, in genere trovano tre o quattro istanze e si fermano. Possono determinare una scoperta sistemica e scrivere nel report consigli per la correzione della problematica sull'intera applicazione. Non c'è bisogno (o tempo) di trovare ogni istanza.

Supponiamo di prendere questi due insiemi di dati distinti e cercare di unirli ina base alla frequenza. In questo caso, i dati di Tooling e HaT sommergeranno i più accurati (ma ampi) dati TaH ed è una buona parte del motivo per cui qualcosa come Cross-Site Scripting è stato così altamente classificato in molte liste quando l'impatto è generalmente basso o moderato. È a causa dell'enorme volume di risultati. (Il Cross-Site Scripting è anche ragionevolmente facile da testare, quindi ci sono molti più test anche per questo).

Nel 2017, abbiamo introdotto l'uso del tasso di incidenza per dare un nuovo sguardo ai dati e fondere in modo pulito i dati di Tooling e HaT con i dati TaH. Il tasso di incidenza chiede quale percentuale della popolazione di applicazioni ha avuto almeno un'istanza di un tipo di vulnerabilità. Non ci interessa se era una tantum o sistemica. Questo è irrilevante per i nostri scopi; abbiamo solo bisogno di sapere quante applicazioni ne avevano almeno un'istanza, il che aiuta a fornire una visione più chiara dei risultati senza rischiare di inquinare i dati con risultati relativi a problematiche ad alta frequenza. Questo corrisponde a una visione legata al rischio, poiché un attaccante ha bisogno di una sola istanza di una determinata vulnerabilità per attaccare con successo un'applicazione.

## Quale è il processo di raccolta e analisi dei dati?

Abbiamo formalizzato il processo di raccolta dati OWASP Top 10 all'Open Security Summit del 2017. I leader di OWASP Top 10 e la comunità hanno trascorso due giorni a formalizzare un processo di raccolta dati trasparente. Per l'edizione 2021 è la seconda volta che abbiamo usato questa metodologia.

Richiediamo i dati attraverso i canali dei social media a nostra disposizione, sia del progetto che di OWASP. Sulla pagina del progetto OWASP, elenchiamo quali variabili e quale struttura stiamo cercando nei dati e come inviarli. Nela pagina GitHub, abbiamo file di esempio che servono come modelli. Lavoriamo con le organizzazioni, se necessario, per aiutarle a capire la struttura e la correlazione delle relative CWE.

Otteniamo dati da organizzazioni che sono aziende che svolgono test di sicurezza, piattaforme di bug bounty e organizzazioni che contribuiscono con dati di test interni. Una volta che abbiamo i dati, li carichiamo insieme ed eseguiamo un'analisi fondamentale, ovvero la corrispondenza delle CWE alle categorie di rischio. C'è una sovrapposizione tra alcune CWE, e altre sono strettamente correlati (es. vulnerabilità crittografiche). Qualsiasi decisione relativa ai dati grezzi presentati è documentata e pubblicata per essere aperti e trasparenti sul processo di normalizzazione dei dati.

Guardiamo le otto categorie con i più alti tassi di incidenza per l'inclusione nella Top 10. Guardiamo anche i risultati del sondaggio della comunità Top 10 per vedere quali possono essere già presenti nei dati. I primi due voti che non sono già presenti nei dati saranno selezionati per gli altri due posti nella Top 10. Una volta che tutti e dieci sono stati selezionati, abbiamo applicato fattori generici per la sfruttabilità e l'impatto; per produrre una Top 10 2021 in un ordine basato sul rischio.

## Etichette dei dati

Ci sono alcune etichette che sono elencati per ciascuna delle 10 categorie principali, ecco cosa significano:

- CWEs corrispondenti: Il numero di CWE corrispondenti a una categoria dal team Top 10.
- Tasso di incidenza:  Il tasso di incidenza è la percentuale di applicazioni vulnerabili a quel CWE dalla popolazione testata da quella org per quell'anno.
- Copertura (di test): La percentuale di applicazioni testate da tutte le organizzazioni per un dato CWE.
- Sfruttabilità pesata: Il sub-score Exploit dai punteggi CVSSv2 e CVSSv3 assegnati ai CVE corrispondenti ai CWE, normalizzati e posizionati su una scala di 10 punti.
- Impatto pesato: Il sub-score di impatto dai punteggi CVSSv2 e CVSSv3 assegnati ai CVE corrispondenti ai CWE, normalizzato e posizionato su una scala di 10 punti.
- Occorrenze totali: Numero totale di applicazioni trovate che hanno i CWE corrispondenti ad una categoria.
- CVE totali: Numero totale di CVE nel DB NVD che sono stati messi in corrispondenza ai CWE relativi a una categoria.

## Ringraziamo chi ha contribuito con i dati

Le seguenti organizzazioni (insieme ad alcuni donatori anonimi) hanno gentilmente donato i dati per oltre 500.000 applicazioni per rendere questo il più grande e completo set di dati sulla sicurezza delle applicazioni. Senza di voi, questo non sarebbe possibile.

- AppSec Labs
- Cobalt.io
- Contrast Security
- GitLab
- HackerOne
- HCL Technologies
- Micro Focus
- PenTest-Tools
- Probely
- Sqreen
- Veracode
- WhiteHat (NTT)

## Grazie ai nostri sponsor

Il team OWASP Top 10 2021 ringrazia il supporto finanziario di Secure Code Warrior e Just Eat.

[![Secure Code Warrior](assets/securecodewarrior.png){ width="256" }](https://securecodewarrior.com)    

[![Just Eats](assets/JustEat.png){ width="256" }](https://www.just-eat.co.uk/)
