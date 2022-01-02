# A06:2021 – Composants vulnérables et obsolètes    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Couverture max | Couverture moyenne | Exploitation pondérée moyenne | Impact pondéré moyen | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:--------------:|:------------------:|:-----------------------------:|:--------------------:|:--------------------------:|:--------------------:|
|       3        |       27,96 %        |         8,77 %         |    51,78 %     |      22,47 %       |             5,00              |         5,00         |           30 457           |          0           |

## Aperçu

Il figurait au deuxième rang lors du sondage communautaire du Top 10, mais il contenait également suffisamment de données pour l'intégrer par ce biais. Les composants vulnérables sont un problème connu pour lequel nous avons du mal à tester et à évaluer les risques. Elle est la seule catégorie à ne pas avoir de *Common Vulnerability and Exposures* (CVEs) associées aux CWEs concernées, en conséquence les coefficients d'impact et de poids ont été renseignés à 5.0 par défaut. Les CWEs notables incluses sont *CWE-1104: Use of Unmaintained Third-Party Components* et les deux CWE des Top 10 de 2013 et 2017.

## Description 

Vous êtes probablement vulnérable :

-   si vous ne savez pas quels sont tous les composants que vous utilisez (à la fois côté client et côté serveur). Cela comprend les composants que vous utilisez directement ou par l'intermédiaire des dépendances imbriquées ;
-   si le logiciel est vulnérable, sans support ou obsolète. Cela concerne le système d'exploitation, le serveur web/application, le système de gestion de base de données (SGBD), les applications, API et autres composants, les environnements d'exécution et les bibliothèques ;
-   si vous ne faites pas de recherche régulière de vulnérabilités et de souscription aux bulletins de sécurité des composants que vous utilisez ;
-   si vous ne corrigez pas ni mettez à jour vos plateformes sous-jacentes, vos frameworks et leurs dépendances sur la base d'une analyse de risque, dans un délai convenable. Cela apparaît fréquemment dans les environnements où les mises à jour sont faites sur une base mensuelle ou trimestrielle au rythme des évolutions logicielles, ce qui laisse les organisations exposées inutilement, des jours et des mois, à des failles avant de corriger les vulnérabilités ;
-   si les développeurs de logiciels ne testent pas la compatibilité des évolutions, des mises à jour et des correctifs des bibliothèques ;
-   si vous ne sécurisez pas les configurations des composants (voir **A05:2021-Mauvaise configuration de sécurité**).

## Comment s'en prémunir

Vous devez mettre en place une gestion des mises à jour pour :

- supprimer les dépendances inutiles et les fonctionnalités, composants, fichiers et documentation non nécessaires ;
- faire un inventaire en continu des versions de composants à la fois client et serveur (ex : frameworks, bibliothèques) et de leurs dépendances avec des outils tels que versions, OWASP Dependency Check, retire.js, etc. Surveiller en permanence les sources comme *Common Vulnerability and Exposures* (CVE) et *National Vulnerability Database* (NVD) pour suivre les vulnérabilités des composants. Utiliser des outils d'analyse de composants logiciels pour automatiser le processus. Souscrire aux alertes par courriel concernant les vulnérabilités sur les composants que vous utilisez ;
- ne récupérer des composants qu'auprès de sources officielles via des liens sécurisés. Préférer des paquets signés pour minimiser les risques d'insertion de composants modifiés malicieux (voir A08:2021-Manque d'intégrité des données et du logiciel) ;
- surveiller les bibliothèques et les composants qui ne sont plus maintenus ou pour lesquels il n'y a plus de correctifs de sécurité. Si les mises à jour ne sont pas possibles, penser à déployer des mises à jour virtuelles pour surveiller, détecter et se protéger d'éventuelles découvertes de failles.

Chaque organisation doit s'assurer d'avoir un projet continu de surveillance, de tri, d'application des mises à jour et de modification de configuration pour la durée de vie d'une application ou de sa gamme.

## Exemple de scénarios d'attaque

**Scénario 1** : Les composants s'exécutent généralement avec le même niveau de privilèges que l'application, et donc les failles d'un quelconque composant peuvent aboutir à un impact sévère. Les failles peuvent être accidentelles (ex : erreur de développement) ou intentionnelles (ex : porte dérobée dans un composant). Voici quelques exemples de découvertes de vulnérabilités de composants exploitables :

- CVE-2017-5638, une vulnérabilité d'exécution à distance de Struts 2, qui permet l'exécution de code arbitraire sur le serveur, a été responsable d'importantes violations ;
- bien que l'internet des objets (IoT) soit souvent difficile, voire impossible à mettre à jour, l'importance de ces mises à jour peut être énorme (ex : objets biomédicaux).

Il existe des outils automatiques qui aident les attaquants à trouver des systèmes mal configurés ou non mis à jour. Par exemple, le moteur de recherche IoT de Shodan peut vous aider à trouver des objets qui sont encore vulnérables à la faille Heartbleed corrigée en avril 2014.

## References

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

## List of Mapped CWEs

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
