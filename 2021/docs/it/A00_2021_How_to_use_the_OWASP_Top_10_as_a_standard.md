# Come usare la OWASP Top 10 come standard

La OWASP Top 10 è principalmente un documento per diffondere consapevolezza. Tuttavia, questo non ha impedito alle organizzazioni di usarlo come standard _de facto_ per l'AppSec sin dal suo inizio nel 2003. Se volete usare la OWASP Top
10 come standard di codifica o di test, sappiate che è il minimo indispensabile e
solo un punto di partenza.

Una delle difficoltà nell'usare la OWASP Top 10 come standard è che
documentiamo i rischi di sicurezza delle applicazioni, e non necessariamente problematiche facilmente testabili.
Per esempio, **A04:2021-Insecure Design** è oltre la portata della maggior parte delle forme di test. Un altro esempio è il test sul posto, in uso, ed efficace dei log e il monitoraggio degli stessi che può essere fatto solo con interviste e con la richiesta di un
campione di risposte agli incidenti di sicurezza. Uno strumento di analisi statica del codice può cercare l'assenza di istruzioni di logging, ma potrebbe essere impossibile determinare se la logica di business o il controllo degli accessi sta registrando violazioni della sicurezza. I penetration tester possono essere in grado solo di determinare che hanno invocato la procedura di incident response in un ambiente di test, ambienti che sono raramente monitorati allo stesso modo dell'ambiente di produzione.

Ecco le nostre raccomandazioni per quando è appropriato usare la OWASP Top 10:

| Caso d'uso              | OWASP Top 10 2021    | OWASP Application Security Verification Standard |
|-------------------------|:--------------------:|:------------------------------------------------:|
| Awareness               | Si                   |                                                  |
| Training                | Livello base         | Completo                                         |
| Design and architecture | Occasionalmente      | Si                                               |
| Coding standard         | Minimo indispensabile| Si                                               |
| Secure Code review      | Minimo indispensabile| Si                                               |
| Peer review checklist   | Minimo indispensabile| Si                                               |
| Unit testing            | Occasionalmente      | Si                                               |
| Integration testing     | Occasionalmente      | Si                                               |
| Penetration testing     | Minimo indispensabile| Si                                               |
| Tool support            | Minimo indispensabile| Si                                               |
| Secure Supply Chain     | Occasionalmente      | Si                                               |

Incoraggiamo chiunque voglia adottare uno standard di sicurezza per le applicazioni
ad utilizzare lo standard [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
(ASVS), poiché è progettato per essere verificabile e testato, e può essere usato in
tutte le parti del un ciclo di vita di sviluppo sicuro del software.

L'ASVS è l'unica scelta accettabile per chi produce strumenti di testing. Gli strumenti non possono
rilevare, testare o proteggere in modo esaustivo contro la Top 10 di OWASP a causa
della natura di molti dei rischi OWASP Top 10, ad esempio A04:2021-Insecure Design. 
OWASP scoraggia qualsiasi pretesa di copertura completa della OWASP Top 10, perché è semplicemente falso.
