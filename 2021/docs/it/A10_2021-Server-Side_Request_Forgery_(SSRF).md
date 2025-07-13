# A10:2021 – Server-Side Request Forgery (SSRF)    ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 8.28                 | 6.72                | 67.72%       | 67.72%       | 9,503             | 385        |

## Panoramica

Questa categoria è stata aggiunta dal sondaggio della comunità Top 10 (#1). I dati mostrano un
tasso di incidenza relativamente basso con una copertura di test superiore alla media e
valutazioni potenziali di sfruttabilità e di impatto superiori alla media. Poiché le nuove voci sono
probabilmente un singolo o un piccolo gruppo di Common Weakness Enumerations (CWEs)
per l'attenzione e per sensibilizzare, la speranza è che siano oggetto di attenzione e possano essere incluse
in una categoria adeguata in una futura edizione.

## Descrizione 

Le falle SSRF si verificano ogni volta che un'applicazione web recupera una risorsa remota
senza validare l'URL fornito dall'utente. Questo permette ad un attaccante
di forzare l'applicazione ad inviare una richiesta preparata ad hoc ad una destinazione inattesa, 
anche quando è protetta da un firewall, una VPN o un altro tipo di
network access control list (ACL).

Dato che le moderne applicazioni web forniscono agli utenti finali parecchie funzionalità,
scaricare dati da un URL è uno scenario comune. Di conseguenza, l'incidenza di
SSRF è in crescita. Inoltre, la gravità di SSRF sta diventando più alta a causa dei
servizi cloud e alla complessità crescente delle architetture.

## Come prevenire

Gli sviluppatori possono prevenire le SSRF implementando alcuni o tutti i seguenti
controlli di defense in depth:

### **Dal layer di rete:**

-   Segmentare in reti separate le funzionalità che richiedono un accesso alle risorse remote per
    ridurre l'impatto di SSRF

-   Applicare politiche di firewall "deny by default" o regole di controllo
    per bloccare tutto il traffico intranet tranne quello essenziale.<br/> 
    *Suggerimenti:*<br> 
    ~ Stabilire una ownership e un ciclo di vita per le regole del firewall basate sulle applicazioni.<br/>
    ~ Registrare tutti i flussi di rete accettati *e* bloccati sui firewall
    (vedi [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)).
    
### **Dal layer applicativo:**

-   Sanitizzare e convalidare tutti i dati di input forniti dal cliente

-   Far rispettare lo URL schema, la porta e la destinazione con una allow list

-   Non inviare risposte raw ai client

-   Disabilitare i redirect HTTP 

-   Essere consapevoli della URL consistency per evitare attacchi come il DNS
    rebinding e race conditions come "time of check, time of use" (TOCTOU)

Non mitigare la SSRF attraverso l'uso di una deny list o di un'espressione regolare.
Gli attaccanti hanno a disposizione liste di payload, strumenti e abilità per bypassare le deny list.

### **Contromisure addizionali da considerare:**
    
-   Non svolgere il deploy di altri servizi rilevanti per la sicurezza sui sistemi di frontend (es. OpenID). 
    Controllare il traffico locale su questi sistemi (es. localhost)
    
-   Per i frontend con gruppi di utenti dedicati e gestibili, usare la crittografia di rete (es. VPN)
    su sistemi indipendenti che hanno esigenze di protezione molto elevate 

## Esempi di scenari d'attacco

Gli attaccanti possono sfruttare SSRF per attaccare sistemi protetti dietro web
application firewall, firewall o ACL di rete, utilizzando scenari come:

**Scenario #1:** Port scan dei server interni - Se l'architettura di rete
non è segmentata, gli attaccanti possono mappare le reti interne e determinare se
sono presenti porte aperte o chiuse in base ai risultati della connessione o
il tempo trascorso per accettare o rifiutare le connessioni del payload SSRF.

**Scenario #2:** Sensitive data exposure – Gli attaccanti possono accedere a file locali 
o servizi interni per ottenere informazioni sensibili 
come `file:///etc/passwd</span>` e `http://localhost:28017/`.

**Scenario #3:** Accedere allo storage dei metadati dei servizi cloud - La maggior parte dei
provider hanno un metadata storage come `http://169.254.169.254/`. Un
attaccante può leggere i metadati per ottenere informazioni sensibili.

**Scenario #4:** Compromettere i servizi interni - L'attaccante può abusare dei
servizi interni per condurre ulteriori attacchi come Remote Code
Execution (RCE) o Denial of Service (DoS).

## Riferimenti

-   [OWASP - Server-Side Request Forgery Prevention Cheat
    Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery
    (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery
    (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF
    bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming
    Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## Lista dei CWE correlati

[CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
