# A02:2021 – Cryptographic Failures    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Panoramica

Sale alla seconda posizione, precedentemente conosciuta come *Sensitive Data
Exposure*, che è più un ampio sintomo piuttosto che la causa principale,
l'attenzione è sulle problematiche relative alla crittografia (o la sua mancanza) che spesso portano all'esposizione di dati sensibili. Le Common Weakness Enumerations (CWE) incluse
sono *CWE-259: Use of Hard-coded Password, CWE-327: Broken or Risky Crypto Algorithm, e CWE-331 Insufficient Entropy*.

## Descrizione 

Il primo passo è determinare le esigenze di protezione dei dati in transito
e a riposo. Per esempio, password, numeri di carte di credito, documenti
sanitari, informazioni personali e segreti aziendali richiedono una
protezione adeguata, soprattutto se quei dati ricadono sotto le leggi sulla privacy, ad es.
General Data Protection Regulation (GDPR), o regolamenti, ad es,
protezione dei dati finanziari come il PCI Data Security Standard (PCI DSS).
Per tutti questi dati:

-   I dati sono trasmessi in chiaro? Questo riguarda protocolli come
    come HTTP, SMTP, FTP che utilizzano anche aggiornamenti TLS come STARTTLS. 
    Il traffico internet esterno è pericoloso. Verificare tutto il traffico interno, ad es, 
    tra load balancer, server web o sistemi back-end.

-   Ci sono algoritmi o protocolli crittografici vecchi o deboli utilizzati 
    di default o nel codice più vecchio?

-   Sono utilizzate chiavi crittografiche predefinite, chiavi crittografiche deboli generate o
    riutilizzate, o manca un'adeguata gestione o rotazione delle chiavi?
    Le chiavi crittografiche sono nei repository del codice sorgente?

-   La crittografia non è applicata, ad esempio, ci sono header HTTP (browser)
    direttive di sicurezza o altri header mancanti?

-   Il certificato ricevuto dal server e la chain of trust sono validati correttamente? 

-   I vettori di inizializzazione sono ignorati, riutilizzati o non generati in modo
    sufficientemente sicuro per il funzionamento di una certa modalità crittografica?
    È in uso una modalità crittografica insicura come l'ECB? Viene utilizzata la semplice crittografia
    quando è invece necessario abbinarla anche ad un meccanismo di autenticazione?

-   Le password vengono usate come chiavi crittografiche senza l'utilizzo di una
    funzione di derivazione della chiave basata sulla password?

-   Viene utilizzata una funzione di randomness che non è stata progettata
    per soddisfare i requisiti crittografici? Anche se viene utilizzata la funzione appropriata, 
    il seed deve essere inizializzato dallo sviluppatore, e se no,
    lo sviluppatore ha sovrascritto la funzionalità di seed forte incorporata
    con una che manca di sufficiente entropia/imprevedibilità?

-   Vengono utilizzate funzioni hash deprecate come MD5 o SHA1, o vengono utilizzate
    funzioni hash non crittografiche quando sono necessarie funzioni hash crittografiche?

-   Sono utilizzati metodi deprecati di padding crittografico come PKCS#1 v1.5?

-   I messaggi di errore crittografici o le informazioni ottenute da un side channel sono
    sfruttabili, per esempio per svolgere attacchi padding oracle?

Vedi ASVS Crypto (V7), Data Protection (V9), e SSL/TLS (V10)

## Come prevenire

Fare quanto segue, come minimo, e consultare i riferimenti in calce:

-   Classificare i dati elaborati, memorizzati o trasmessi da un'applicazione.
    Identificare quali dati sono sensibili secondo le leggi sulla privacy,
    requisiti normativi o esigenze aziendali.

-   Non conservare inutilmente i dati sensibili. Eliminarli il prima possibile
    o utilizzare un meccanismo di tokenizzazione conforme a PCI DSS o anche il troncamento.
    I dati che non vengono conservati non possono essere rubati.

-   Assicurarsi di cifrare tutti i dati sensibili a riposo.

-   Utilizzare algoritmi, protocolli e chiavi standard forti e aggiornati.
    Avere un adeguato processo di key management.

-   Crittografare tutti i dati in transito con protocolli sicuri come TLS con
    cifrari che garantiscano la FS (forward secrecy), prioritizzazione dei cifrari da parte del
    server e parametri sicuri. Applicare la crittografia usando direttive
    come HTTP Strict Transport Security (HSTS).

-   Disabilitare il caching per le risposte che contengono dati sensibili.

-   Applicare i controlli di sicurezza adeguati secondo la classificazione dei dati.

-   Non usare protocolli legacy come FTP e SMTP per il trasporto di
    dati sensibili.

-   Memorizzare le password usando forti funzioni di hashing adattive con salt
    con un work factor (delay factor), come Argon2, scrypt, bcrypt o
    PBKDF2.

-   I vettori di inizializzazione devono essere scelti in modo appropriato per il modo di
    funzionamento.  Per molti modi di funzionamento, questo significa usare un CSPRNG (cryptographically
    secure pseudo random number generator).  Per quelli che richiedono un
    nonce, allora il vettore di inizializzazione (IV) non ha bisogno di un CSPRNG.  In tutti i casi, l'IV
    non dovrebbe mai essere usato due volte per una stessa chiave.

-   Usare sempre un meccanismo di crittografia autenticata invece della semplice crittografia.

-   Le chiavi dovrebbero essere generate crittograficamente in modo casuale e memorizzate in
    memoria come array di byte. Se viene usata una password, questa deve essere convertita
    in una chiave tramite un'appropriata funzione di derivazione della chiave basata sulla password.

-   Assicuratevi che la randomness crittografica venga utilizzata laddove appropriato, e
    che non sia stato utilizzato un seed prevedibile o con bassa entropia.
    La maggior parte delle API moderne non richiedono allo sviluppatore di inizializzare il seed della CSPRNG.

-   Evitare funzioni crittografiche e schemi di padding deprecati, come
    MD5, SHA1, PKCS#1 v1.5 

-   Verificare in modo indipendente l'efficacia della configurazione e delle
    impostazioni.

## Esempi di scenari d'attacco

**Scenario #1**: Un'applicazione cifra i numeri delle carte di credito in un
database usando la crittografia automatica del database. Tuttavia, questi dati sono
automaticamente decriptati quando vengono recuperati, permettendo ad una falla di SQL injection di
recuperare i numeri delle carte di credito in chiaro.

**Scenario #2**: Un sito non usa o applica TLS per tutte le pagine o
supporta una crittografia debole. Un aggressore monitora il traffico di rete (ad es.
una rete wireless insicura), svolge il downgrade della connessione da HTTPS a
HTTP, intercetta le richieste e ruba il cookie di sessione dell'utente. 
L'attaccante riproduce questo cookie e dirotta la sessione dell'utente (autenticato)
accedendo o modificando i dati privati dell'utente. 
Oppure potrebbe alterare tutti i dati in transito, ad esempio, modificando il destinatario di un
trasferimento di denaro.

**Scenario #3**: Il database delle password usa hash semplici o senza salt per
memorizzare le password di tutti gli utenti. Una falla nel caricamento dei file permette ad un attaccante di
recuperare il database delle password. Tutti gli hash senza salt possono essere violati
con una rainbow table di hash precalcolati. Gli hash generati da
funzioni hash semplici o veloci possono essere decifrati dalle GPU, anche se in presenza di salt.

## Riferimenti

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)


## Lista dei CWE correlati

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
