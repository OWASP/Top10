# NDL Note de lansare

## Ce s-a schimbat din 2013 până în 2017?

Schimbarea s-a accelerat în ultimii patru ani, iar Top 10 al OWASP trebuia să se schimbe. Am refacturat complet OWASP Top 10, am restructurat metodologia, am utilizat un nou proces de apel de date, am lucrat cu comunitatea, am reorganizat riscurile noastre, am rescris fiecare risc de la zero și am adăugat referințe la frameworks și limbaje de programare care sunt acum utilizate în mod obișnuit.

În ultimii ani, tehnologia fundamentală și arhitectura aplicațiilor s-au schimbat semnificativ:

* Microserviciile scrise în node.js și Spring Boot înlocuiesc aplicațiile tradiționale monolitice. Microserviciile vin cu propriile provocări de securitate, inclusiv stabilirea încrederii între microservicii, containere, management-ul de parole etc. Cod vechi de la care nu era așteptat să fie accesibil de pe Internet este șade acum în spatele unui API sau serviciu RESTful web care urmează să fie consumat de aplicații cu o singură pagină (Single Page Applications SPA) și aplicații mobile. Așteptările arhitecturale ale codului, prcum apelanți de încredere, nu mai sunt valabile.
* Aplicațiile cu o singură pagină, scrise în framework-uri de JavaScript, precum Angular și React, permit crearea unor aplicații foarte modulare, bogate în caracteristici. Funcționalitatea pe partea client, care a fost livrată în mod tradițional pe partea de server, aduce propriile provocări de securitate.
* JavaScript este acum limbajul de programare primar a web-ului cu node.js pe partea de server care și framework-uri web moderne, cum ar fi Bootstrap, Electron, Angular și React care rulează pe partea de client.

## Probleme noi, vizibile in date

* **A4:2017-XML External Entities (XXE)** este o nouă categorie recunoscută în principal de instrumentele de testare a securității a codului sursă ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)).

## Probleme noi, propuse de comunitate

We asked the community to provide insight into two forward looking weakness categories. După peste 500 de rapoarte trimise și eliminarea problemelor care au fost deja vizibile in date (cum ar fi Expunerea de date sensibile și XXE), cele două noi probleme sunt: 

* **A8:2017-Insecure Deserialization**, which permits remote code execution or sensitive object manipulation on affected platforms.
* **A10:2017-Insufficient Logging and Monitoring**, the lack of which can prevent or significantly delay malicious activity and breach detection, incident response, and digital forensics.

## Merged or retired, but not forgotten

* **A4-Insecure Direct Object References** and **A7-Missing Function Level Access Control** merged into **A5:2017-Broken Access Control**.
* **A8-Cross-Site Request Forgery (CSRF)**, as many frameworks include [CSRF defenses](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)), it was found in only 5% of applications.
* **A10-Unvalidated Redirects and Forwards**, while found in approximately in 8% of applications, it was edged out overall by XXE.

![0x06-release-notes-1](images/0x06-release-notes-1.png)
