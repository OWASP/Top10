# A04:2025 Cryptographic Failures ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## Contesto.

Scendendo di due posizioni al #4, questa debolezza si concentra sui fallimenti legati all'assenza di crittografia, a una crittografia insufficientemente forte, alla divulgazione di chiavi crittografiche e agli errori correlati. Tre delle CWE più comuni in questo rischio riguardano l'uso di un generatore di numeri pseudo-casuali debole: *CWE-327 Use of a Broken or Risky Cryptographic Algorithm, CWE-331: Insufficient Entropy*, *CWE-1241: Use of Predictable Algorithm in Random Number Generator*, e *CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)*.



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
   <td>32
   </td>
   <td>13,77%
   </td>
   <td>3,80%
   </td>
   <td>100,00%
   </td>
   <td>47,74%
   </td>
   <td>7,23
   </td>
   <td>3,90
   </td>
   <td>1.665.348
   </td>
   <td>2.185
   </td>
  </tr>
</table>



## Descrizione.

In linea generale, tutti i dati in transito devono essere cifrati a livello di [trasporto](https://en.wikipedia.org/wiki/Transport_layer) ([livello OSI](https://en.wikipedia.org/wiki/OSI_model) 4). Gli ostacoli precedenti come le prestazioni della CPU e la gestione di chiavi private/certificati sono ora gestiti da CPU con istruzioni progettate per accelerare la cifratura (es. [supporto AES](https://en.wikipedia.org/wiki/AES_instruction_set)) e dalla semplificazione della gestione di chiavi private e certificati da parte di servizi come [LetsEncrypt.org](https://LetsEncrypt.org), con i principali vendor cloud che forniscono servizi di gestione dei certificati ancora più integrati per le loro specifiche piattaforme.

Oltre alla protezione del livello di trasporto, è importante determinare quali dati necessitano di cifratura a riposo e quali dati necessitano di cifratura aggiuntiva in transito (al [livello applicativo](https://en.wikipedia.org/wiki/Application_layer), livello OSI 7). Ad esempio, password, numeri di carta di credito, cartelle cliniche, informazioni personali e segreti aziendali richiedono una protezione aggiuntiva, specialmente se tali dati sono soggetti a leggi sulla privacy, es. il Regolamento Generale sulla Protezione dei Dati (GDPR) dell'UE, o normative come il PCI Data Security Standard (PCI DSS). Per tutti questi dati:



* Vengono utilizzati algoritmi o protocolli crittografici vecchi o deboli, sia per default che nel codice meno recente?
* Vengono utilizzate chiavi crittografiche predefinite, vengono generate chiavi crittografiche deboli, le chiavi vengono riutilizzate, o manca una corretta gestione e rotazione delle chiavi?
* Le chiavi crittografiche vengono inserite nei repository di codice sorgente?
* La cifratura non viene applicata, es. mancano direttive o header di sicurezza HTTP (browser)?
* Il certificato del server ricevuto e la catena di fiducia vengono correttamente validati?
* I vettori di inizializzazione vengono ignorati, riutilizzati o non generati in modo sufficientemente sicuro per la modalità di operazione crittografica? Viene utilizzata una modalità operativa non sicura come ECB? Viene utilizzata la cifratura quando sarebbe più appropriata la cifratura autenticata?
* Le password vengono utilizzate come chiavi crittografiche in assenza di una funzione di derivazione delle chiavi basata su password?
* Viene utilizzata la casualità non progettata per soddisfare i requisiti crittografici? Anche se viene scelta la funzione corretta, deve essere seminata dallo sviluppatore, e in caso contrario, lo sviluppatore ha sovrascritto la forte funzionalità di seeding integrata con un seed privo di sufficiente entropia/imprevedibilità?
* Vengono utilizzate funzioni hash deprecate come MD5 o SHA1, o vengono usate funzioni hash non crittografiche quando sono necessarie funzioni hash crittografiche?
* I messaggi di errore crittografici o le informazioni sui canali laterali sono sfruttabili, ad esempio sotto forma di attacchi padding oracle?
* L'algoritmo crittografico può essere declassato o bypassato?

Vedi i riferimenti ASVS: Cryptography (V11), Secure Communication (V12) e Data Protection (V14).


## Come prevenire.

Fare almeno quanto segue e consultare i riferimenti:



* Classificare ed etichettare i dati elaborati, archiviati o trasmessi da un'applicazione. Identificare quali dati sono sensibili secondo le leggi sulla privacy, i requisiti normativi o le esigenze aziendali.
* Archiviare le chiavi più sensibili in un HSM hardware o cloud.
* Utilizzare implementazioni ben consolidate degli algoritmi crittografici ogni volta che è possibile.
* Non archiviare dati sensibili inutilmente. Eliminarli il prima possibile o utilizzare la tokenizzazione conforme a PCI DSS o anche la troncatura. I dati non conservati non possono essere rubati.
* Assicurarsi di cifrare tutti i dati sensibili a riposo.
* Garantire che algoritmi, protocolli e chiavi standard aggiornati e robusti siano in uso; utilizzare una corretta gestione delle chiavi.
* Cifrare tutti i dati in transito con protocolli >= TLS 1.2 solamente, con cifrari con forward secrecy (FS), eliminare il supporto per i cifrari con cipher block chaining (CBC), supportare algoritmi di cambio chiave quantistici. Per HTTPS, applicare la cifratura utilizzando HTTP Strict Transport Security (HSTS). Verificare tutto con uno strumento.
* Disabilitare la cache per le risposte che contengono dati sensibili. Questo include la cache nel CDN, nel web server e nella cache applicativa (es. Redis).
* Applicare i controlli di sicurezza richiesti in base alla classificazione dei dati.
* Non utilizzare protocolli non cifrati come FTP e STARTTLS. Evitare l'uso di SMTP per trasmettere dati riservati.
* Archiviare le password utilizzando funzioni di hashing adaptive e con salt con un work factor (delay factor), come Argon2, yescrypt, scrypt o PBKDF2-HMAC-SHA-512. Per i sistemi legacy che utilizzano bcrypt, consultare [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
* I vettori di inizializzazione devono essere scelti in modo appropriato per la modalità di operazione. Ciò potrebbe significare l'uso di un CSPRNG (generatore di numeri pseudo-casuali crittograficamente sicuro). Per le modalità che richiedono un nonce, il vettore di inizializzazione (IV) non necessita di un CSPRNG. In tutti i casi, l'IV non deve mai essere usato due volte per una chiave fissa.
* Utilizzare sempre la cifratura autenticata anziché la sola cifratura.
* Le chiavi devono essere generate crittograficamente in modo casuale e archiviate in memoria come array di byte. Se viene utilizzata una password, deve essere convertita in una chiave tramite una funzione appropriata di derivazione delle chiavi basata su password.
* Garantire che la casualità crittografica venga utilizzata dove appropriato e che non sia stata seminata in modo prevedibile o con bassa entropia. La maggior parte delle API moderne non richiede allo sviluppatore di seminare il CSPRNG per essere sicuro.
* Evitare funzioni crittografiche deprecate, metodi di costruzione a blocchi e schemi di padding, come MD5, SHA1, Cipher Block Chaining Mode (CBC), PKCS numero 1 v1.5.
* Garantire che le impostazioni e le configurazioni soddisfino i requisiti di sicurezza facendole rivedere da specialisti della sicurezza, strumenti progettati a tale scopo, o entrambi.
* È necessario prepararsi ora per la crittografia post-quantistica (PQC), vedi riferimento (ENISA), in modo che i sistemi ad alto rischio siano al sicuro entro la fine del 2030.


## Scenari di attacco di esempio.

**Scenario #1:** Un sito non utilizza o non applica TLS per tutte le pagine o supporta cifratura debole. Un attaccante monitora il traffico di rete (es. su una rete wireless non sicura), fa il downgrade delle connessioni da HTTPS a HTTP, intercetta le richieste e ruba il cookie di sessione dell'utente. L'attaccante poi riproduce questo cookie e dirottà la sessione (autenticata) dell'utente, accedendo o modificando i dati privati dell'utente. In alternativa potrebbe alterare tutti i dati trasportati, es. il destinatario di un bonifico bancario.

**Scenario #2:** Il database delle password utilizza hash non salati o semplici per archiviare le password di tutti. Una falla di caricamento file consente a un attaccante di recuperare il database delle password. Tutti gli hash non salati possono essere esposti con una rainbow table di hash pre-calcolati. Gli hash generati da funzioni hash semplici o veloci possono essere violati dalle GPU, anche se erano salati.


## Riferimenti.



* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)


## Lista delle CWE Mappate

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)
* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)
* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)
* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)
* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)
* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)
* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)
* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)
* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)
* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)
* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)
* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)
* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)
* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)
* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)
* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)
* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)
* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)
* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)
* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)
* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
