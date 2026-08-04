# A07:2025 Authentication Failures ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## Contesto.

Authentication Failures mantiene la sua posizione al #7 con una leggera modifica del nome per riflettere più accuratamente le 36 CWE in questa categoria. Nonostante i benefici dei framework standardizzati, questa categoria ha mantenuto il suo rango #7 dal 2021. Tra le CWE degne di nota vi sono *CWE-259 Use of Hard-coded Password*, *CWE-297: Improper Validation of Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, *CWE-384: Session Fixation*, e *CWE-798 Use of Hard-coded Credentials*.


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
   <td>36
   </td>
   <td>15,80%
   </td>
   <td>2,92%
   </td>
   <td>100,00%
   </td>
   <td>37,14%
   </td>
   <td>7,69
   </td>
   <td>4,44
   </td>
   <td>1.120.673
   </td>
   <td>7.147
   </td>
  </tr>
</table>



## Descrizione.

Quando un attaccante riesce a ingannare un sistema facendogli riconoscere come legittimo un utente non valido o non corretto, questa vulnerabilità è presente. Potrebbero esserci debolezze di autenticazione se l'applicazione:

* Permette attacchi automatizzati come il credential stuffing, dove l'attaccante dispone di un elenco violato di username e password validi. Più recentemente questo tipo di attacco è stato esteso a includere attacchi ibridi di credential stuffing (noti anche come password spray attack), dove l'attaccante utilizza variazioni o incrementi delle credenziali trafugate per ottenere l'accesso, ad esempio provando Password1!, Password2!, Password3! e così via.
* Permette attacchi a forza bruta o altri attacchi automatizzati con script che non vengono bloccati rapidamente.
* Permette password predefinite, deboli o ben note, come "Password1" o username "admin" con password "admin".
* Consente agli utenti di creare nuovi account con credenziali già note come violate.
* Consente l'uso di processi di recupero credenziali e di password dimenticate deboli o inefficaci, come le "risposte alle domande di sicurezza", che non possono essere rese sicure.
* Utilizza store di dati di password in chiaro, cifrate o con hashing debole (vedi [A04:2025-Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)).
* Ha un'autenticazione a più fattori assente o inefficace.
* Consente l'uso di fallback deboli o inefficaci se l'autenticazione a più fattori non è disponibile.
* Espone l'identificatore di sessione nell'URL, in un campo nascosto o in un'altra posizione non sicura accessibile al client.
* Riutilizza lo stesso identificatore di sessione dopo un login riuscito.
* Non invalida correttamente le sessioni utente o i token di autenticazione (principalmente token di single sign-on (SSO)) durante il logout o dopo un periodo di inattività.
* Non verifica correttamente l'ambito e il pubblico previsto delle credenziali fornite.

## Come prevenire.

* Dove possibile, implementare e applicare l'uso dell'autenticazione a più fattori per prevenire attacchi automatizzati di credential stuffing, forza bruta e riutilizzo di credenziali rubate.
* Dove possibile, incoraggiare e abilitare l'uso di password manager, per aiutare gli utenti a fare scelte migliori.
* Non distribuire o deployare con credenziali predefinite, in particolare per gli utenti amministratori.
* Implementare controlli sulle password deboli, come testare le password nuove o modificate rispetto all'elenco delle 10.000 password peggiori.
* Durante la creazione di nuovi account e i cambi di password, validare rispetto agli elenchi di credenziali note come violate (es. usando [haveibeenpwned.com](https://haveibeenpwned.com)).
* Allineare le policy di lunghezza, complessità e rotazione delle password con le [linee guida NIST 800-63b nella sezione 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html) per Memorized Secrets o altre policy di password moderne basate su evidenze.
* Non forzare le persone a ruotare le password a meno che non si sospetti una violazione. Se si sospetta una violazione, forzare immediatamente il reset delle password.
* Garantire che i percorsi di registrazione, recupero credenziali e API siano rafforzati contro gli attacchi di account enumeration utilizzando gli stessi messaggi per tutti gli esiti ("Username o password non validi.").
* Limitare o ritardare progressivamente i tentativi di login falliti, ma fare attenzione a non creare uno scenario di denial of service. Registrare tutti i fallimenti e inviare alert agli amministratori quando vengono rilevati o sospettati attacchi di credential stuffing, forza bruta o altri attacchi.
* Utilizzare un session manager integrato, sicuro e lato server che generi un nuovo ID di sessione casuale con alta entropia dopo il login. Gli identificatori di sessione non devono essere nell'URL, devono essere archiviati in modo sicuro in un cookie sicuro e invalidati dopo il logout, il timeout di inattività e il timeout assoluto.
* Idealmente, utilizzare un sistema pre-costruito e ben collaudato per gestire autenticazione, identità e gestione delle sessioni. Trasferire questo rischio ogni volta che è possibile acquistando e utilizzando un sistema rafforzato e ben testato.
* Verificare l'uso previsto delle credenziali fornite, es. per i JWT validare i claim `aud`, `iss` e gli scope.


## Scenari di attacco di esempio.

**Scenario #1:** Il credential stuffing, l'uso di elenchi di combinazioni note di username e password, è ora un attacco molto comune. Più recentemente gli attaccanti hanno trovato il modo di 'incrementare' o altrimenti adattare le password, in base al comportamento umano comune. Ad esempio, cambiando 'Winter2025' in 'Winter2026', o 'ILoveMyDog6' in 'ILoveMyDog7' o 'ILoveMyDog5'. Questo adattamento dei tentativi di password è chiamato attacco ibrido di credential stuffing o password spray attack, e può essere ancora più efficace della versione tradizionale. Se un'applicazione non implementa difese contro le minacce automatizzate (forza bruta, script o bot) o il credential stuffing, l'applicazione può essere usata come oracolo di password per determinare se le credenziali sono valide e ottenere accesso non autorizzato.

**Scenario #2:** La maggior parte degli attacchi di autenticazione riusciti si verifica a causa del continuo utilizzo delle password come unico fattore di autenticazione. Una volta considerate best practice, i requisiti di rotazione e complessità delle password incoraggiano gli utenti sia a riutilizzare le password che a usare password deboli. Si raccomanda alle organizzazioni di interrompere queste pratiche secondo NIST 800-63 e di applicare l'uso dell'autenticazione a più fattori su tutti i sistemi importanti.

**Scenario #3:** I timeout delle sessioni dell'applicazione non sono implementati correttamente. Un utente utilizza un computer pubblico per accedere a un'applicazione e invece di selezionare "logout", chiude semplicemente la scheda del browser e se ne va. Un altro esempio è se una sessione Single Sign On (SSO) non può essere chiusa da un Single Logout (SLO). Cioè, un singolo login ti autentica, ad esempio, al tuo lettore di posta, al tuo sistema di documenti e al tuo sistema di chat. Ma il logout avviene solo per il sistema corrente. Se un attaccante usa lo stesso browser dopo che la vittima pensa di essersi disconnessa con successo, ma con l'utente ancora autenticato ad alcune delle applicazioni, può accedere all'account della vittima.

## Riferimenti.

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## Lista delle CWE Mappate

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)
* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)
* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)
* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)
* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)
* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)
* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)
* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)
