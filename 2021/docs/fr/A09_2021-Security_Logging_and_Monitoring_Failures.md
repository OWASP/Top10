# A09:2021 – Carence des systèmes de contrôle et de journalisation    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       4        |       19,23 %        |         6,51 %         |             6,87              |         4,99         |    53,67 %     |      39,97 %       |           53 615           |         242          |

## Aperçu

La journalisation et la surveillance de la sécurité sont issues de l'enquête de la communauté Top 10 (n°3), en légère hausse par rapport à la dixième position dans le Top 10 2017 de l'OWASP. La journalisation et la surveillance peuvent être difficiles à tester, impliquant souvent des entretiens ou demandant si des attaques ont été détectées lors d'un test d'intrusion. Il n'y a pas beaucoup de données CVE/CVSS pour cette catégorie, mais la détection et la réponse aux brèches sont essentielles. Il n'en reste pas moins qu'elle peut avoir un impact considérable sur la responsabilité, la visibilité, l'alerte en cas d'incident et la forensique. Cette catégorie s'étend au-delà de *CWE-778 Insufficient Logging* pour inclure *CWE-117 Improper Output Neutralization for Logs*, *CWE-223 Omission of Security-relevant Information*, et *CWE-532* *Insertion of Sensitive Information into Log File*.

## Description 

De retour dans le Top 10 2021 de l'OWASP, cette catégorie a pour but d'aider à la détection, à l'escalade et à la réponse aux brèches actives. Sans journalisation et surveillance, les brèches ne peuvent être détectées. Une journalisation, une détection, une surveillance et une réponse active insuffisantes peuvent survenir à tout moment :

- les traces d’audit, telles que les accès réussis ou échoués et les transactions sensibles, ne sont pas enregistrées ;
- les alertes et les erreurs générées ne sont pas enregistrées, ou leur journalisation est inadéquate, ou imprécise ;
- les journaux des applications et des API ne sont pas contrôlés pour détecter les actions suspectes ;
- les journaux ne sont stockés que localement ;
- aucun processus de seuil d’alerte convenable ni de remontées d'information pour y répondre n'ont été définis, ou ils sont inadéquats, ou inefficaces ;
- les tests d'intrusion et de balayage avec des outils de test dynamique de sécurité des applications (DAST), tels que OWASP ZAP, ne génèrent pas d'alertes ;
- l’application est incapable de détecter, de générer des remontées d'information et des alertes en temps réel, ou assimilé, en cas d’attaque active.

Vous êtes vulnérable à une fuite d’information en rendant les enregistrements de journalisation et d’alertes accessibles à vos utilisateurs ou attaquants (voir [A01:2021-Contrôles d'accès défaillants](A01_2021-Broken_Access_Control.md)).

## Comment s'en prémunir

Les développeurs doivent mettre en œuvre tout ou partie des contrôles suivants, en fonction du risque de l'application :

- s'assurer que toutes les authentifications, les erreurs de contrôle d'accès et de contrôle des entrées côté serveur sont enregistrées, avec un contexte utilisateur suffisant pour identifier les comptes suspects ou malveillants, et conservées suffisamment longtemps pour permettre une analyse légale différée ;
- s'assurer que les enregistrements des journaux sont dans un format standard pour permettre de les intégrer facilement à une solution de gestion de logs centralisée ;
- veiller à ce que les données des journaux soient correctement encodées afin d'éviter les injections ou les attaques sur les systèmes de journalisation ou de surveillance ;
- s'assurer que les transactions à haute valeur ajoutée ont une piste d'audit, avec un contrôle d'intégrité, pour éviter la modification ou la suppression, comme des tables de bases de données en ajout seul ou équivalent ;
- les équipes DevSecOps devraient mettre en place une supervision et une gestion d'alertes efficaces pour détecter et réagir aux actions suspectes en temps opportun ;
- définir ou adopter un plan de réaction et de reprise sur incident, comme celui du *National Institute of Standards and Technology* (NIST) 800-61r2 ou ultérieur.

On trouve des logiciels, commerciaux ou open source, de protection d'applications tels que OWASP ModSecurity Core Rule Set, et des logiciels de corrélation de journaux, comme la pile Elasticsearch, Logstash, Kibana (ELK), qui propose des tableaux de bord et d'alertes configurables.

## Exemple de scénarios d'attaque

**Scénario n°1** : l'opérateur du site Web d'un fournisseur de soins de santé pour enfants n'a pas pu détecter une violation en raison d'un manque de surveillance et de journalisation. Une partie externe a informé le fournisseur du plan de santé qu'un attaquant avait accédé et modifié des milliers de dossiers médicaux sensibles de plus de 3,5 millions d'enfants. Un examen postérieur à l'incident a révélé que les développeurs du site Web n'avaient pas corrigé d'importantes vulnérabilités. Comme il n'y avait pas de journalisation ou de surveillance du système, la violation de données pourrait être en cours depuis 2013, soit une période de plus de sept ans.

**Scénario n°2** : une grande compagnie aérienne indienne a subi une violation de données portant sur plus de dix ans de données personnelles de millions de passagers, y compris des données de passeport et de carte de crédit. La violation des données s'est produite chez un fournisseur tiers d'hébergement en nuage, qui a informé la compagnie aérienne de la violation après un certain temps.

**Scénario n°3** : une grande compagnie aérienne européenne a subi une violation à déclarer au titre de la RGPD. La violation aurait été causée par des vulnérabilités de sécurité des applications de paiement exploitées par des attaquants, qui ont récolté plus de 400 000 enregistrements de paiement de clients. La compagnie aérienne a été condamnée à une amende de 20 millions de livres sterling en conséquence par le régulateur de la vie privée.

## Références

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP Application Security Verification Standard: V7 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Liste des CWEs associées

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
