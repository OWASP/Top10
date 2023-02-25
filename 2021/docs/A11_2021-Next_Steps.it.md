# A11:2021 – Passi seguenti

Per natura, la OWASP Top 10 è limitata ai dieci rischi più impattanti.
Ogni versione della OWASP Top 10 ha dei rischi che sono stati in bilico per quanto riguarda la loro inclusione, ma alla fine non ce l'hanno fatta. In qualsiasi modo avessimo provato ad interpretare o distorcere i dati, gli altri rischi sono risultati comunque più prevalenti e impattanti. 

Le organizzazioni che lavorano verso un programma di AppSec maturo, per consulenze,
o fornitori di strumenti che desiderano espandere la copertura per i loro prodotti,
le seguenti tre problematiche valgono lo sforzo di essere
identificate e risolte.

## Problematiche sulla qualità del codice

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

-   **Descrizione.** I problemi relativi alla qualità del codice includono difetti di sicurezza o pattern noti, il riutilizzo di variabili per scopi multipli, l'esposizione di
    informazioni sensibili nell'output delle istruzioni di debug, errori off-by-one, condizioni time of check/time of use  (TOCTOU), race conditions, errori di conversione, use after free, e altro ancora. La caratteristica di questa
    sezione è che queste problematiche di solito possono essere identificate con settaggi rigorosi dei flag del compilatore, strumenti di analisi statica del codice e plugin dell'IDE per il linting.
    I linguaggi moderni hanno eliminato molti di questi problemi by design, come
    il concetto di memory ownership, di borrowing, e il threading di Rust, lo strict typing e il bounds checking di Go.


-   **Come prevenire**. Abilitare e utilizzare le opzioni di analisi statica del 
    codice e dell'ambiente di sviluppo.
    Considerare l'uso di uno strumento di analisi statica del codice.
    Considerare se potrebbe essere possibile usare o migrare ad un linguaggio o
    framework che elimina intere classi classi di bug, come Rust o Go.

-   **Esempi di scenari d'attacco**. Un attaccante potrebbe ottenere o aggiornare
    informazioni sensibili sfruttando una condizione di race condition con una
    variabile staticamente condivisa da più thread.

-   **Riferimenti**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)


## Denial of Service

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **Descrizione**. Denial of service è sempre possibile date
    risorse sufficienti da parte di un attaccante. Tuttavia, le metodologie di progettazione e programmazione hanno un'influenza significativa sull'entità di questo tipo di attacchi.
    Supponiamo che chiunque abbia il link possa accedere ad un file di grandi dimensioni, o che in ogni pagina venga svolta una transazione computazionalmente costosa. In questo
    caso, lo sforzo per svolgere un attacco di denial of service richiederebbe pochissimo sforzo.

-   **Come prevenire**. Testare le prestazioni del codice per utilizzo di CPU, I/O 
    e memoria. Utilizzare, riarchitettare, ottimizzare o mettere in cache le operazioni più costose.
    Considerare i controlli di accesso per gli oggetti più grandi per assicurare che solo
    persone autorizzate possano accedere a file o oggetti di grandi dimensioni o servirli
    da una edge caching network. 

-   **Esempi di scenari d'attacco**. Un attaccante potrebbe determinare che un'operazione
    richiede 5-10 secondi per essere completata. Quando si eseguono quattro
    thread concorrenti, il server sembra smettere di rispondere. L'attaccante
    utilizza 1000 thread e porta l'intero sistema offline.

-   **Riferimenti**
    - [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Errori di gestione della memoria

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Descrizione**. Le applicazioni web tendono ad essere scritte in
    linguaggi managed, come Java, .NET, o Node.js (JavaScript o
    TypeScript). Tuttavia, questi linguaggi sono scritti con linguaggi di basso livello
    che soffrono di problemi di gestione della memoria, come buffer o heap
    overflow, use after free, integer overflow, e altro. Ci sono stati
    molti attacchi di sandbox escape nel corso degli anni che hanno dimostrato che solo
    perché il linguaggio delle applicazioni web è nominalmente "memory safe", le
    basi sottostanti potrebbero non esserlo.

-   **Come prevenire**. Molte API moderne vengono oramai scritte in linguaggi memory-safe
    come Rust o Go. Nel caso di Rust, la sicurezza della memoria è
    una caratteristica cruciale del linguaggio. Per il codice esistente, l'uso di
    rigorosi flag del compilatore, strong typing, analisi statica del codice e fuzz testing
    possono essere utili per identificare memory leaks, overrun di memoria e array, e altro ancora.

-   **Esempi di scenari d'attacco**. I buffer e gli heap overflow sono stati un
    un pilastro per gli attaccanti nel corso degli anni. L'attaccante invia dei dati ad un programma, che li memorizza in uno stack buffer sottodimensionato. Il risultato è che le informazioni sul call stack vengono sovrascritte, incluso il puntatore di ritorno della funzione. I dati impostano il valore del puntatore di ritorno in modo che quando la funzione termina, trasferisce il controllo al codice maligno contenuto nei dati inviati dall'attaccante.

-   **Riferimenti**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
