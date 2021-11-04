# A08:2021 – Software and Data Integrity Failures    ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Fattori

| CWEs corrispondenti | Tasso di incidenza Max | Tasso di incidenza Medio | Sfruttabilità pesata | Impatto Medio | Copertura Max | Copertura media | Occorrenze Totali | CVE Totali |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 6.94                 | 7.94                | 75.04%       | 45.35%       | 47,972            | 1,152      |

## Panoramica

Una nuova categoria per il 2021 che è relativa alla verifica dell'integrità di aggiornamenti software, 
dati critici, e pipeline di CI/CD. Uno dei più alti impatti pesati dai dati di 
Common Vulnerability e Exposures/Common Vulnerability Scoring System (CVE/CVSS). 
Le Common Weakness Enumerations (CWEs) incluse sono
*CWE-829: Inclusion of Functionality from Untrusted Control Sphere*,
*CWE-494: Download of Code Without Integrity Check*, e 
*CWE-502: Deserialization of Untrusted Data*.

## Descrizione 

Le problematiche dell'integrità del software e dei dati riguardano il codice e l'infrastruttura
che non ne verificano adeguatamente l'integrità. Un esempio è quando un'applicazione si affida a plugin, librerie o moduli da fonti, repository e content delivery network (CDN) non attendibili.
Una pipeline CI/CD insicura può aprire la porta ad accessi non autorizzati, codice dannoso o compromissione completa del sistema.
Infine, molte applicazioni ora includono funzionalità di auto-aggiornamento, dove gli
aggiornamenti vengono scaricati senza una sufficiente verifica dell'integrità e
applicati all'applicazione. Gli attaccanti potrebbero
potenzialmente caricare i propri aggiornamenti malevoli da distribuire e da eseguire su tutte le
installazioni. Un altro esempio è la deserializzazione insicura, quando gli
oggetti o i dati sono codificati o serializzati in una struttura che un
attaccante può ispezionare e modificare liberamente.

## Come prevenire

-   Usare firme digitali o meccanismi equivalenti per verificare che il software o i dati provengano dalla fonte prevista e non siano stati alterati.

-   Assicurarsi che le librerie e le dipendenze, come npm o Maven, siano collegati a repository affidabili. Se avete un profilo di rischio più alto, considerate l'hosting di un repository interno ben conosciuto e controllato.

-   Assicuratevi che venga usato uno strumento di sicurezza della supply chain del software, come OWASP
    Dependency Check o OWASP CycloneDX, per verificare che i componenti non contengano vulnerabilità note

-   Assicurarsi che ci sia un processo di revisione per le modifiche al codice e alla configurazione per ridurre al minimo la possibilità che codice o configurazione dannosi vengano introdotti nella pipeline del software.

-   Assicurarsi che la pipeline CI/CD sia adeguatamente segregata, configurata adeguatamente e sia presente un meccanismo di controllo degli accessi per assicurare l'integrità del codice che passa attraverso i processi di compilazione e distribuzione.

-   Assicuratevi che i dati serializzati non firmati o non crittografati non vengano inviati a
    client non fidati senza qualche forma di controllo dell'integrità o firma digitale
    per rilevare la manomissione o il replay dei dati serializzati.

## Esempi di scenari d'attacco

**Scenario #1 Aggiornamenti senza firma:** Molti router domestici, set-top box, 
e altri dispositivi non verificano gli aggiornamenti attraverso una
firma. Il firmware non firmato è sempre più spesso un obiettivo per gli attaccanti e 
questo è un trend che sembra non essere destinato a cessare. Questa è una problematica rilevante in quanto molte volte 
non è presente alcun meccanismo per rimediare se non quello di correggere in una versione futura e
aspettare che le versioni precedenti invecchino.

**Scenario #2 Aggiornamento malevolo di SolarWinds**: Gli stati-nazione sono sempre stati noti 
per perpetrare attacchi verso i meccanismi di aggiornamento, con un recente e degno di nota attacco
a SolarWinds Orion. L'azienda che sviluppa il software aveva 
processi per svolgere le build in modo sicuro e controlli sull'integrità degli aggiornamenti. 
Tuttavia, questi controlli sono violati e per parecchi mesi l'azienda distribuì un aggiornamento malevolo altamente mirato
a più di 18,000 organizzazioni, delle quali, circa 100 sono state infettate. Questo è uno dei breach di questa natura di più ampia portata e più significativo nella storia.

**Scenario #3 Deserializzazione insicura:** Un'applicazione React chiama un
insieme di microservizi Spring Boot. Essendo stata scritta nel paradigma funzionale, 
gli sviluppatori hanno cercato di garantire l'immutabilità del codice. La soluzione che hanno trovato
è serializzare lo stato dell'utente e passarlo avanti e indietro ad
ogni richiesta. Un attaccante nota la firma dell'oggetto Java "rO0" (in base64) e
usa lo strumento Java Serial Killer per ottenere esecuzione di codice remoto sul
server dell'applicazione.

## Riferimenti

-   \[OWASP Cheat Sheet: Software Supply Chain Security\](Coming Soon)

-   \[OWASP Cheat Sheet: Secure build and deployment\](Coming Soon)

-    [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) 
 
-   [OWASP Cheat Sheet: Deserialization](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   [SAFECode Software Integrity Controls](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   [A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)

-   [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## Lista dei CWE correlati

[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
