# Come avviare un programma di AppSec con la OWASP Top 10 

In precedenza, la OWASP Top 10 non è mai stata progettata per essere la base di un programma AppSec. Tuttavia, per molte aziende che hanno appena iniziato il loro viaggio nella sicurezza delle applicazioni è essenziale avere una base di partenza.
La OWASP Top 10 2021 è un buon inizio come riferimento per le checklist e così via, ma non è di per sé sufficiente.

## Passo 1. Identificare le lacune e gli obiettivi del vostro programma AppSec

Molti programmi di sicurezza delle applicazioni (AppSec) cercano di mettere il carro davanti ai buoi. I programmi eseguiti in questo modo sono destinati a fallire. Noi incoraggiamo fortemente
i CISO e i responsabili della AppSec ad usare [OWASP Software Assurance
Maturity Model (SAMM)](https://owaspsamm.org) per identificare i punti deboli
e le aree di miglioramento su un periodo di 1-3 anni. Il primo passo è quello di
valutare dove siete ora, identificare le lacune nella governance, nel design,
nell'implementazione, nella verifica e nella parte operativa che dovete risolvere immediatamente rispetto a quelle che possono aspettare, e dare la priorità all'implementazione o al migliorare le quindici pratiche di sicurezza OWASP SAMM. OWASP SAMM può aiutarvi a costruire e misurare i miglioramenti nei vostri sforzi per migliorare la sicurezza del software.

## Passo 2. Pianificare per un ciclo di vita del software sicuro su una paved road

Tradizionalmente appannaggio dei cosiddetti "unicorni", il concetto di paved road
è il modo più semplice per ottenere il massimo impatto e scalare le risorse AppSec
con la velocità del team di sviluppo, che aumenta ogni anno.

Il concetto di paved road è "il modo più semplice è anche il modo più sicuro"
e dovrebbe comportare una cultura di partnership profonda tra il
team di sviluppo e il team di sicurezza, preferibilmente in modo che siano nello stesso team. 
La paved road mira a migliorare continuamente, misurare, rilevare e sostituire le alternative insicure 
avendo una lista a livello aziendale di alternative sicure pronte ad essere utilizzate, con strumenti per
aiutare a vedere dove si possono fare miglioramenti grazie alla paved road. Questo
permette agli strumenti di sviluppo esistenti di segnalare le build insicure e aiutare
i team di sviluppo a stare lontano dalle alternative non sicure.

La paved road potrebbe sembrare molto laboriosa da realizzare, ma dovrebbe essere costruita incrementalmente nel tempo. Esistono anche altre forme di programmi AppSec, in particolare il Microsoft Agile Secure Development Lifecycle. Non esiste una metodologia di programma AppSec che si adatti ad ogni tipo di azienda.

## Passo 3. Realizzare la paved road con il team di sviluppo

Le paved road vengono realizzate con il consenso e il coinvolgimento diretto dei team di sviluppo e operativi interessati. La paved road dovrebbe essere allineata strategicamente con il business e aiutare a fornire più velocemente applicazioni più sicure. Realizzare la paved road dovrebbe essere un esercizio olistico che copre l'intera azienda o ecosistema di applicazioni, non un cerotto da applicare alle app, come avveniva in passato.


## Passo 4. Migrare tutte le applicazioni imminenti ed esistenti sulla paved road

Aggiungere strumenti di rilevamento per la paved road nella fase di development e fornire informazioni ai team di sviluppo per migliorare la sicurezza delle loro applicazioni permettendo loro di adottare direttamente elementi della paved road.
Una volta che un aspetto della paved road è stato adottato, le organizzazioni dovrebbero implementare sistemi di continuous integration che ispezionino il codice esistente e che avvertano nel caso di utilizzo di  alternative proibite e avvisino o rifiutino la build. Questo previene che opzioni insicure si insinuino nel codice nel tempo, prevenendo il debito tecnico e un'applicazione insicura.
Questi avvertimenti dovrebbero suggerire l'alternativa sicura, così che il team di sviluppo
riceva immediatamente la risposta corretta. Possono svolgere il refactoring del codice e
adottare rapidamente il componente della paved road.

## Passo 5. Testare che la paved road abbia mitigato le problematriche segnalate dalla OWASP Top 10

I componenti della paved road dovrebbero affrontare una problematica significativa con l'OWASP
Top 10, per esempio, come rilevare o correggere automaticamente i componenti vulnerabili, o un plugin per l'IDE per svolgere l'analisi statica del codice per rilevare injection, o
ancora meglio iniziare ad usare una libreria che è notoriamente sicura contro le injection.
Più queste alternative sicure pronte all'uso vengono fornite ai team, meglio è.
Un compito vitale del team AppSec è quello di garantire che la sicurezza di questi
componenti sia continuamente valutata e migliorata.
Una volta applicate le migliorie, si dovrebbe indicare a chi utilizza il componente che si dovrebbe eseguire un aggiornamento, meglio ancora se avvenisse automaticamente, ma se così non fosse, almeno evidenziarlo su un
dashboard o simile.

## Passo 6. Integrare il tuo processo in un programma di AppSec maturo

Non dovete fermarvi alla Top 10 di OWASP. Copre solo 10 categorie di rischio. 
Incoraggiamo fortemente le organizzazioni ad adottare l'Application
Security Verification Standard e aggiungere progressivamente
componenti e test per il livello 1, 2 e 3, a seconda del livello di rischio delle applicazioni sviluppate.

## Andare oltre

Tutti i grandi programmi AppSec vanno oltre il minimo indispensabile. Tutti devono continuare
ad andare avanti se vogliamo essere al top delle vulnerabilità dell'AppSec.

-   **Integrità concettuale**. I programmi AppSec maturi devono contenere qualche
    concetto di architettura di sicurezza, sia che si tratti di un
    architettura di sicurezza enterprise, cloud o threat modeling.

-   **Automazione e scalabilità**. I programmi AppSec maturi cercano di automatizzare il più
    possibile, usando script per emulare complesse fasi di penetration test, strumenti di analisi statica del codice direttamente a disposizione dei team di sviluppo, assistendo i team di sviluppo nello
    sviluppare unit e integration test per AppSec, e altro ancora.

-   **Cultura**. I programmi AppSec maturi cercano smantellare design insicuri ed 
    eliminare il debito tecnico dal codice esistente essendo una
    parte integrante del team di sviluppo, non accessoria. I team AppSec che
    vedono i team di sviluppo come degli estranei sono destinati a fallire.

-   **Miglioramento continuo**. I programmi AppSec maturi cercano di
    migliorare costantemente. Se qualcosa non funziona, smetti di farlo. Se
    qualcosa è rudimentale o non scalabile, lavorate per migliorarlo. Se
    qualcosa non viene usato dai team di sviluppo e ha un impatto limitato, fate qualcosa di diverso. 
    Solo perché facciamo verifiche documentali dagli anni '70 non significa che sia una buona
    idea. Misurare, valutare e poi costruire o migliorare.
