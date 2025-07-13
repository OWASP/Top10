# A04:2021 – Conception non sécurisée   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       40       |       24,19 %        |         3,00 %         |             6,46              |         6,78         |    77,25 %     |      42,51 %       |          262 407           |        2 691         |

## Aperçu

Une nouvelle catégorie pour 2021, l'accent est mis sur les risques liés aux failles de conception et d'architecture, avec un appel à l'augmentation du recours aux modèles de menaces, aux modèles et principes de conceptions sécurisés et aux architectures de référence. En tant que communauté, nous devons ajouter des contrôles en amont du développement, ces phases sont vitales pour une conception sécurisée. Les *Common Weakness Enumerations* (CWE) notables incluses sont *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation* et *CWE-522: Insufficiently Protected Credentials*.

## Description

Conception non sécurisée est une vaste catégorie représentant différentes insuffisances, exprimées par « contrôles de conception manquants ou inefficaces ». La conception non sécurisée n'est pas la source de toutes les autres catégories de risques du Top 10. Il existe une différence entre une conception non sécurisée et une implémentation non sécurisée. Nous différencions les défauts de conception et les défauts d'implémentation pour une raison, ils ont des causes racines et des mesures correctives différentes. Une conception sécurisée peut toujours présenter des défauts d'implémentations conduisant à des vulnérabilités pouvant être exploitées. Une conception non sécurisée ne peut pas être corrigée par une implémentation parfaite car, par définition, les contrôles de sécurité nécessaires n'ont jamais été créés pour se défendre contre des attaques spécifiques. L'un des facteurs qui contribuent à la conception non sécurisée est le manque de profilage des risques commerciaux inhérent au logiciel ou au système en cours de développement, et donc l'incapacité à déterminer le niveau de sécurité requis.

### Gestion des exigences et des ressources

Recueillez et négociez les exigences métier pour une application avec les équipes fonctionnelles, y compris les exigences de sécurité concernant la confidentialité, l'intégrité, la disponibilité et l'authenticité de l'ensemble des données et de la logique métier attendue. Prenez compte du degré d'exposition de votre application et si vous avez besoin de séparer les tenants (en plus du contrôle d'accès). Rassemblez les exigences techniques, y compris les exigences de sécurité fonctionnelles et non fonctionnelles. Planifiez et négociez le budget couvrant l'ensemble de la conception, de la construction, des tests et de l'exploitation, y compris les activités de sécurité.

### Conception sécurisée

La conception sécurisée est une culture et une méthodologie qui évalue en permanence les menaces et garanti que le code est conçu et testé de manière robuste pour empêcher les méthodes d'attaques connues. La modélisation des menaces doit être intégrée aux sessions de *refinement* (ou activités similaires) et rechercher des changements dans les flux de données et le contrôle d'accès. Dans les *user stories*, déterminez le cas passant et les états d'échecs, assurez-vous qu'ils sont bien compris et acceptés par les parties responsables et impactées. Analysez les hypothèses et les conditions pour les cas passants et en échecs, assurez-vous qu'ils sont toujours exacts et souhaités. Déterminez comment valider les hypothèses et mettez en place les conditions nécessaires pour un comportement approprié. Assurez-vous que les résultats sont documentés dans la *user story*. Apprenez de vos erreurs, incitez et faites la promotion des améliorations. La conception sécurisée n'est ni un module complémentaire, ni un outil que vous pouvez ajouter au logiciel.

### Cycle de développement sécurisé

Un logiciel sécurisé nécessite un cycle de vie de développement sécurisé, une méthode de conception sécurisée, une voie pavée, une bibliothèque de composants sécurisés, des outils et une modélisation des menaces. Faites appel à vos spécialistes de la sécurité tout au long du projet et de la maintenance de votre logiciel. Essayez de tirer parti de l'[OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) pour vous aider à structurer vos efforts de développement sécurisé.

## Comment s'en prémunir

- mettez en place et utilisez un cycle de vie de développement sécurisé avec des professionnels de la sécurité applicative pour aider à évaluer et à concevoir des contrôles liés à la sécurité et à la confidentialité ;
- mettez en place et utilisez une bibliothèque de modèles de conception sécurisés ou de composants prêts à l'emploi pour une voie pavée ;
- utilisez la modélisation des menaces pour l'authentification critique, le contrôle d'accès, la logique métier et la gestion de clés ;
- intégrez les contrôles de sécurité dans les *user stories* ;
- intégrez des contrôles de vraisemblance à chaque niveau de votre application (du frontend au backend) ;
- écrivez des tests unitaires et d'intégration pour valider que tous les flux critiques sont résistants aux modèles de menaces. Assemblez des cas d'usage *et* des cas de détournement pour chaque niveau de votre application ;
- séparez les couches systèmes et réseaux en fonction de l'exposition et des besoins de protection ;
- séparez les tenants via une conception robuste sur l'ensemble des niveaux ;
- restreignez les ressources par utilisateur ou service.

## Exemple de scénarios d'attaque

**Scénario 1 :** Un processus de récupération d'informations d'identification peut inclure des «&nbsp;questions secrètes&nbsp;», ce qui est interdit par le NIST 800-63b, l'OWASP ASVS et le Top 10 de l'OWASP. Les questions et les réponses ne peuvent pas être considérées comme une preuve d'identité, car plus d'une personne peut connaître les réponses, c'est pourquoi elles sont interdites. Un tel code doit être supprimé et remplacé par une conception plus sécurisée.

**Scénario 2 :** Une chaîne de cinéma permet des réductions sur les réservations de groupe et compte un maximum de quinze participants avant d'exiger un acompte. Les attaquants pourraient modéliser ce cas d'usage et tester s'ils peuvent réserver six cents places et tous les cinémas à la fois en quelques demandes, provoquant une perte massive de revenus.

**Scénario 3 :** Le site e-commerce d'une chaîne de vente au détail n'est pas protégé contre les robots qui achètent des cartes vidéo haut de gamme pour les revendre sur le marché noir. Cela crée une mauvaise publicité pour les fabricants de cartes vidéo et les propriétaires de chaînes de vente au détail, provoque du ressentiment de la part des acheteurs qui ne peuvent pas se procurer ces cartes quel qu'en soit le prix. Des règles prudentes de conception anti-bot, telles que les achats effectués dans les quelques secondes suivant la disponibilité, peuvent identifier des achats non authentiques et rejeter de telles transactions.

## Références

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## Liste des CWEs associées

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)
