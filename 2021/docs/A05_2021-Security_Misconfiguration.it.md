# A05:2021 – Security Misconfiguration    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19.84%             | 4.51%              | 8.12                 | 6.56                | 89.58%       | 44.84%       | 208,387           | 789        |

## Panoramica

Sale dalla posizione #6 della scorsa edizione, il 90% delle applicazioni testate sono risultate vulnerabili ad una qualche forma di malconfigurazione, con un tasso medio di incidenza del 4%, e più di 208k occorrenze di Common Weakness Enumeration (CWE) in questa categoria di rischio. Con un trend in crescita verso software sempre più configurabili, non sorprende vedere queste categoria salire in classifica.
Le CWE incluse sono *CWE-16 Configuration* and *CWE-611 Improper
Restriction of XML External Entity Reference*.

## Descrizione 

L'applicazione potrebbe risultare vulnerabile se:

-   Manca l'hardening di sicurezza appropriato in qualsiasi parte dello
    stack applicativo o permessi configurati in modo improprio sui servizi
    cloud.

-   Sono abilitate o installate funzioni non necessarie (ad es.
    porte, servizi, pagine, account o privilegi non necessari).

-   Gli account di default sono ancora abilitati e presentano password predefinite.

-   A seguito di condizioni di errore, vengono rivelate agli utenti stack traces o altri messaggi  di errore troppo verbosi.

-   Per i sistemi aggiornati, le ultime funzionalità di sicurezza sono disabilitate o
    non configurate in modo adeguato.

-   Le impostazioni di sicurezza negli application server, nei framework
    (ad esempio, Struts, Spring, ASP.NET), nelle librerie, database, ecc. non sono configurate su valori sicuri.

-   Il server non invia header o direttive di sicurezza o non sono impostati su valori sicuri.

-   Il software non è aggiornato o è vulnerabile (vedere [A06:2021-Vulnerable
    and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)).

Senza un processo coordinato e ripetibile per la configurazione della sicurezza delle applicazioni, 
i sistemi presentano un rischio maggiore.

## Come prevenire

Dovrebbero essere implementati processi di installazione sicuri, tra cui:

-   Un processo di hardening ripetibile rende veloce e facile il deploy di
    un altro ambiente preconfigurato in modo sicuro. Gli ambienti di sviluppo,
    QA e di produzione dovrebbero essere tutti configurati in modo speculare, con credenziali diverse per ogni ambiente.
    Questo processo dovrebbe essere automatizzato per minimizzare lo sforzo richiesto per
    impostare un nuovo ambiente configurato in modo sicuro.

-   Una piattaforma minimale senza funzionalità,componenti,
    documentazione ed esempi inutili. Rimuovere o non installare funzionalità e
    framework inutilizzati.

-   Un task per rivedere e aggiornare le configurazioni appropriate a tutte le
    security notes, aggiornamenti e patch come parte del processo di gestione delle patch
    (vedere [A06:2021-Vulnerable
    and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)). Revisionare
    i permessi del cloud storage (ad esempio, i permessi dei bucket S3).

-   Un'architettura applicativa segmentata fornisce un'efficace e sicura
    separazione tra componenti o tenant, con segmentazione,
    containerizzazione, o cloud security groups (ACL).

-   L'invio di direttive di sicurezza ai client, ad esempio, i Security Headers.

-   Un processo automatizzato per verificare l'efficacia delle
    configurazioni e impostazioni in tutti gli ambienti.

## Esempi di scenari d'attacco

**Scenario #1:** L'application server viene fornito con applicazioni di esempio
non rimosse dal server di produzione. Queste applicazioni di esempio hanno
falle di sicurezza note che gli attaccanti usano per compromettere il server. Supponiamo che una
di queste applicazioni sia la console di amministrazione e che gli account predefiniti non siano stati cambiati. In questo caso, l'attaccante accede con le password predefinite e
prende il controllo.

**Scenario #2:** La funzionalità di directory listing non è disabilitata sul server. Un
attaccante scopre che si possono elencare tutte le directory. L'attaccante trova
e scarica le classi Java compilate, su cui esegue la decompilazione e il reverse engineering per visualizzare il codice sorgente. L'attaccante trova poi una grave
difetto di controllo degli accessi nell'applicazione.

**Scenario #3:** La configurazione dell'application server permette di restituire agli utenti
messaggi di errore dettagliati, ad esempio la stack trace. Questa problematica
potenzialmente espone informazioni sensibili o problematiche come
versioni dei componenti che sono note per essere vulnerabili.

**Scenario #4:** Un cloud service provider ha dei permessi di condivisione predefiniti
aperti a Internet da altri utenti nell'header Content Security Policy (CSP). Questo permette
l'accesso ai dati sensibili memorizzati nel cloud storage.

## Riferimenti

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   Application Security Verification Standard V19 Configuration

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Lista dei CWE correlati

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
