# A06:2021 – Vulnerable and Outdated Components    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Panoramica

Era già la numero #2 dal sondaggio della community della Top 10, ma aveva anche abbastanza evidenze da poter entrare nella Top 10 grazie ai dati. Vulnerable Components sono una problematica nota che si fatica a testare e a calcolarne il rischio, ed è l'unica categoria per cui non abbiamo Common Weakness Enumerations (CWEs) correlate alle CWE incluse, verrà quindi utilizzato un peso predefinito di 5.0 per sfruttabilità/impatto. CWEs incluse sono *CWE-1104: Use of
Unmaintained Third-Party Components* and the two CWEs from Top 10 2013
and 2017.

## Descrizione 

La vulnerabilità si presenta se:

-   Non conosci le versioni di tutti i componenti utilizzati (sia
    lato client che lato server). Questo include i componenti utilizzati direttamente
    così come le dipendenze annidate.

-   Se il software è vulnerabile, non supportato o non aggiornato. Questo
    include il sistema operativo, il server web/applicazione, il database management system
    (DBMS), applicazioni, API e tutti i componenti, ambienti di esecuzione,
    e librerie.

-   Se non si fa la scansione delle vulnerabilità regolarmente e non si consultano i
    bollettini di sicurezza relativi ai componenti utilizzati.

-   Se non si corregge o non si aggiorna la piattaforma sottostante, i framework,
    e le dipendenze in modo tempestivo e basato sul rischio. Questo comunemente
    accade in ambienti in cui le patch vengono applicate mensilmente o trimestralmente
    sotto change control, lasciando le organizzazioni scoperte per giorni o mesi
    verso vulnerabilità già risolte.

-   Se gli sviluppatori non testano la compatibilità delle librerie aggiornate,
    nuove o patchate.

-   Se i componenti non vengono configurati in modo sicuro (vedere
    A05:2021-Security Misconfiguration).

## Come prevenire

Ci dovrebbe essere un processo di gestione delle patch in atto per:

-   Rimuovere le dipendenze, le funzionalità, i componenti, i file,
    e la documentazione non utilizzate.

-   Inventariare in modo continuo le versioni dei componenti lato client e
    lato server (ad esempio, framework, librerie) e le loro
    dipendenze usando strumenti come OWASP Dependency Check,
    retire.js, ecc. Monitorare continuamente fonti come Common Vulnerability and 
    Exposures (CVE) e il National Vulnerability Database (NVD) per
    vulnerabilità nei componenti. Usare strumenti di software composition per automatizzare il processo. 
    Sottoscrivere avvisi e-mail per le vulnerabilità di sicurezza relative ai componenti utilizzati.

-   Ottenere i componenti solo da fonti ufficiali tramite link sicuri.
    Preferire pacchetti firmati per ridurre la possibilità di includere un componente modificato o dannoso (vedere A08:2021-Software and Data Integrity Failures).

-   Controllare le librerie e i componenti che non sono più mantenuti o che non
    sviluppano più patch di sicurezza per le vecchie versioni. Se il patching non è
    possibile, considerare l'implementazione di una patch virtuale per monitorare, rilevare o
    proteggere dal problema individuato.

Ogni organizzazione deve garantire un piano continuo per il monitoraggio, il triage,
e l'applicazione di aggiornamenti o modifiche di configurazione per tutta la durata dell'applicazione
o del portafoglio.

## Esempi di scenari d'attacco

**Scenario #1:** I componenti solitamente vengono eseguiti con gli stessi privilegi dell'applicazione stessa, 
quindi le falle in qualsiasi componente possono avere un serio
impatto. Tali difetti possono essere accidentali (ad esempio, un errore nel codice) o intenzionali
(ad esempio, una backdoor in un componente). Alcuni esempi di vulnerabilità sfruttabili
scoperte nei componenti sono:

-   CVE-2017-5638, una vulnerabilità di esecuzione di codice remoto di Struts 2 che
    permette l'esecuzione di codice arbitrario sul server, è stata
    causa di breach importanti.

-   Mentre l'internet delle cose (IoT) è spesso difficile o
    impossibile da patchare, l'importanza nel riuscirci è elevata
    (ad esempio, i dispositivi biomedici).

Ci sono strumenti automatici per aiutare gli attaccanti a trovare sistemi non patchati o
sistemi mal configurati. Per esempio, il motore di ricerca Shodan IoT può
aiutare a trovare i dispositivi che soffrono ancora della vulnerabilità Heartbleed
patchata nell'aprile 2014.

## Riferimenti

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## Lista dei CWE correlati

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
