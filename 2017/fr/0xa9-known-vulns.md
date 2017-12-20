# A9:2017 Utilisation de Composants avec des Vulnérabilités Connues

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilités           | Impacts               |
| -- | -- | -- |
| Accès Lvl : Exploitation 2 | Fréquence 3 : Détection 2 | Techniques 2 : Métier ?  |
| Bien qu'il soit facile de trouver des exploits prêts à l'emploi pour de multiples vulnérabilités, d'autres vulnérabilités demandent un effort soutenu pour développer un exploit adapté. | La fréquence de ce problème est très élevée. Les modèles de développement à composants multiples peuvent conduire à ce que des équipes de développement ne sachent même pas quels composants ils utilisent dans leur application ou API, et soient donc encore moins susceptibles de les maintenir à jour. Des scanners comme retire.js aident à la détection, mais l'exploitation demande un effort supplémentaire. | Alors que quelques vulnérabilités connues ont seulement des impacts mineurs, certaines des violations les plus importantes jusqu'à aujourd'hui reposent sur l'exploitation de vulnérabilités connues dans des composants. Suivant les actifs que vous avez à protéger, ce risque pourra être l'un de vos risques majeurs. |

## Suis-je Vulnérable ?

Vous êtes probablement vulnérable:

* Si vous ne savez pas quels sont tous les composants que vous utilisez (à la fois côté client et côté serveur). Cela comprend les composants que vous utilisez directement ou par l'intermédiaire des dépendances imbriquées.
* Si le logiciel est vulnérable, sans support, ou obsolète. Cela concerne le système d'exploitation, le serveur web/application, le système de gestion de base de données (SGBD), les applications, APIs et autres composants, les environments d'exécution, et les bibliothèques.
* Si vous ne faites pas de recherche régulières de vulnérabilités et de souscription aux bulletins de sécurité des composants que vous utilisez.
* Si vous ne corrigez pas ni mettez à jour vos plateformes sous-jacentes, vos frameworks, et leurs dépendances sur la base d'une analyse de risque, dans un délai convenable. Cela apparaît fréquemment dans les environnements où les mises à jour sont faites  sur une base mensuelle ou trimestrielle au rythme des évolutions logicielles, ce qui laisse les organisations exposées inutilement, des jours et des mois, à des failles avant de corriger les vulnérabilités.
* Si les développeurs de logiciels ne testent pas la compatibilité des évolutions, des mises à jour et des correctifs des bibliothèques.
* Si vous ne sécurisez pas les configurations des composants (voir **A6:2017-Mauvaise Configuration de Sécurité**).

## Comment s'en Prémunir ?

Vous devez mettre en place une gestion des mises à jour pour:

* Supprimer les dépendances inutiles et les fonctionnalités, composants, fichiers et documentation non nécessaires.
* Faire un inventaire en continu des versions de composants à la fois client et serveur (ex. frameworks, bibliothèques) et de leurs dépendances avec des outils tels que versions, DependencyCheck, retire.js, etc. 
* Surveiller en permanence les sources comme CVE et NVD pour suivre les vulnérabilités des composants. Utiliser des outils d'analyse de composants logiciels pour automatiser le processus. Souscrire aux alertes par courriel concernant les vulnérabilités sur les composants que vous utilisez.
* Ne récupérer des composants qu'auprès de sources officielles via des liens sécurisés. Préférer des paquets signés pour minimiser les risques d'insertion de composants modifiés malicieux.
* Surveiller les bibliothèques et les composants qui ne sont plus maintenus ou pour lesquels il n'y a plus de correctifs de sécurité. Si les mises à jour ne sont pas possibles, penser à déployer des mises à jour virtuelles pour surveiller, détecter et se protéger d'éventuelles découvertes de failles.

Chaque organisation doit s'assurer d'avoir un projet continu de surveillance, de tri, d'application des mises à jour et de modification de configuration pour la durée de vie d'une application ou de sa gamme.

## Exemple de Scénario d'Attaque

**Scénario #1**: Les composants s'exécutent généralement avec le même niveau de privilèges que l'application, et donc les failles d'un quelconque composant peuvent aboutir à un impact sévère. Les failles peuvent être accidentelles (ex. erreur de codage) ou intentionnelles (ex. porte dérobée dans un composant). 
Voici quelques exemples de découvertes de vulnérabilités exploitables de composants  :

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), une vulnérabilité d'exécution à distance de Struts 2, qui permet l'éxecution de code arbitraire sur le serveur, a été responsable d'importantes violations.
* Bien que [l'internet des objets (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) soit souvent difficile voire impossible à mettre à jour, l'importance de ces mises à jour peut être énorme (ex. objets biomédicaux).

Il existe des outils automatiques qui aident les attaquants à trouver des systèmes malconfigurés ou non mis à jour. Par exemple, le [moteur de recherche IoT de Shodan](https://www.shodan.io/report/89bnfUyJ) peut vous aider à trouver des objets qui sont encore vulnérables à la faille [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) corrigée en Avril 2014.

## Références

### OWASP

* [OWASP Standard de Vérification de Sécurité Applicative: V1 Architecture, conception et modélisation des menaces](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Contrôle des Dépendences (pour les bibliothèques Java et .NET)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Guide de Test - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Meilleures pratiques de Mises à Jour Virtuelles](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Externes

* [La regrettable réalité des bibliothèques non sécurisées](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [L'organisation MITRE maintient le dictionnaire de recherche des Common Vulnerabilities and Exposures (CVE)](https://www.cvedetails.com/version-search.php)
* [Base de Données Nationale de Vulnérabilité (NVD)](https://nvd.nist.gov/)
* [Retire.js pour la détection de vulnérabilités connues des bibliothèques JavaScript](https://github.com/retirejs/retire.js/)
* [Bibliothèques des alertes de Sécurité Node.js](https://nodesecurity.io/advisories)
* [Base de Données des alertes de Sécurité des bibliothèques Ruby et Outils](https://rubysec.com/)
