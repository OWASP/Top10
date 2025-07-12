# A07:2021 – Identification and Authentication Failures    ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 7.40                 | 6.50                | 79.51%       | 45.72%       | 132,195           | 3,897      |

## Panoramica

Precedentemente sotto il nome di *Broken Authentication*, questa categoria scende dalla
seconda posizione e ora include le Common Weakness 
Enumerations (CWEs) relative ai fallimenti dei meccanismi di autorizzazione. 
Le CWEs incluse sono *CWE-297: Improper Validation of
Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, e
*CWE-384: Session Fixation*.

## Descrizione 

La verifica dell'identità dell'utente, l'autenticazione e la gestione della sessione
sono fondamentali per proteggersi dagli attacchi legati all'autenticazione. 
Ci possono essere debolezze sui meccanismi di autenticazione se l'applicazione:

-   Permette attacchi automatici come il credential stuffing, dove l'attaccante
    ha una lista di coppie nome utente e password validi.

-   Permette attacchi di brute force o altri attacchi automatizzati.

-   Permette password di default, deboli o ben note, come "Password1"
    o "admin/admin".

-   Utilizza un recupero delle credenziali e delle password dimenticate debole o inefficace
    come le "risposte basate sulla conoscenza", che non possono essere rese
    sicure.

-   Memorizza le password in chiaro, in modo cifrato o con funzioni di hash deboli (vedi
    **A02:2021-Cryptographic Failures**).

-   Non ha un sistema di autenticazione a più fattori o è inefficace.

-   Espone l'identificatore di sessione del URL.

-   Riutilizza l'identificatore di sessione dopo un login avvenuto con successo.

-   Non invalida correttamente l'identificatore di sessione. La sessione dell'utente o i token di autenticazione
    (principalmente token di single sign-on (SSO)) non vengono invalidati in modo opportuno durante il logout o dopo un periodo di inattività

## Come prevenire

-   Dove possibile, implementare l'autenticazione a più fattori per prevenire
    attacchi di credential stuffing, brute force e riutilizzo delle credenziali rubate.

-   Non mettere in produzione sistemi con credenziali di default, in particolare per gli utenti admin.

-   Implementare controlli sulla debolezza delle password, come verificare le password nuove o modificate 
con la lista delle 10,000 password peggiori.

-   Allineare i requisiti di lunghezza delle password, complessità e politiche di rotazione con le linee guida della sezione 5.1.1 del documento  800-63b pubblicato dal National Institute of Standards and Technology (NIST)
   riguardante la memorizzazione dei secret o altre policy relative alle password moderne e basate sui fatti .

-   Assicurarsi che la registrazione, il recupero delle credenziali e le API siano
    robusti contro gli attacchi di enumerazione degli account utilizzando gli stessi
    messaggi generici per tutti i risultati.

-   Limitare o ritardare sempre più i tentativi di login falliti, ma fare attenzione a non creare uno scenario di denial of service. Loggare tutti i tentativi falliti e avvertire gli amministratori quando vengono rilevati attacchi di credential stuffing, brute force o
    altri.

-   Usare un gestore di sessione integrato lato server, che sia sicuro, che generi un
    nuovo ID di sessione casuale con alta entropia dopo il login. L'identificatore di sessione
    non dovrebbe essere nell'URL, deve essere memorizzato in modo sicuro e invalidato dopo il
    logout, un periodo di inattività e avere timeout assoluto.

## Esempi di scenari d'attacco

**Scenario #1:** Il credential stuffing, l'uso di liste di password conosciute, 
è un attacco comune. Supponiamo che un'applicazione non implementi
la protezione automatica contro le minacce o il credential stuffing. In questo caso, 
l'applicazione può essere usata come un oracolo di password per determinare se le
credenziali sono valide.

**Scenario #2:** La maggior parte degli attacchi relativi all'autenticazione si verifica a causa del continuo
uso delle password come singolo fattore. Le best practice,
la rotazione delle password e i requisiti di complessità incoraggiano gli utenti a usare
e riutilizzare password deboli. Si raccomanda alle organizzazioni di interrompere queste
pratiche secondo NIST 800-63 e utilizzare l'autenticazione a più fattori.

**Scenario #3:** I timeout della sessione dell'applicazione non sono gestiti correttamente. Un
utente usa un computer pubblico per accedere a un'applicazione. Invece di
selezionare "logout", l'utente chiude semplicemente la scheda del browser e se ne va
via. Un attaccante usa lo stesso browser un'ora dopo, e l'utente risulta
ancora autenticato.

## Riferimenti

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Authentication](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## Lista dei CWE correlati

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)
