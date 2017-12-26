# A6:2017 Mauvaise configuration de Sécurité

| Agents de menace/Vecteurs d'attaque | Vulnérabilité de Sécuité           | Impacts               |
| -- | -- | -- |
| Niveau d'accès : Exploitation 3 | Fréquence 3 : Détection 3 | Technique 2 : Métier |
| Les attaquants tentent fréquemment d'exploiter des vulnérabilités non corrigées ou d'accéder aux comptes par défaut, aux pages inutilisées, aux fichiers et répertoires non protégés, etc... afin d'obtenir des accès non autorisés et une meilleure connaissance du système visé. | Une mauvaise de configuration de sécurité peut survenir sur l'ensemble des couches protocolaires, dont les services de réseau, la plateforme, le serveur Web, le serveur d'application, la base de données, les frameworks, les codes spécifiques, et les machines virtuelles pré-installées, les conteneurs, et le stockage. Les scanners automatisés sont utiles pour détecter les erreurs de configurations, l'utilisation de comptes ou de configurations par défaut, les services inutiles, les options héritées de configurations précédentes, etc. | De tels défauts ou vulnérabilités fournissent souvent aux attaquants un accès non autorisés à certains données du système, ou à des fonctionnalités. Il arrive parfois que de tels vulnérabilités ou défauts entraînent une compromission complète du système. L'impact métier dépend des exigences de protection sécurité portées par l'application et les données. |

## Suis-je Vulnérable ?

L'application peut être vulnérable si :

* elle n'a pas fait l'objet d'un durcissement sécurité approprié sur l'ensemble des couches protocolaires applicatives, ou si les permissions sont mal configurées sur les services cloud.
* des fonctionnalités inutiles sont activées ou installées (ex. des ports, des services, des pages, des comptes ou des privilèges inutiles).
* les comptes par défaut et leurs mots de passe sont toujours activés et inchangés.
* le traitement des erreurs révèle aux utilisateurs des traces des piles protocolaires ou d'autres messages d'erreur laissant transpirer trop d'informations.
* pour les systèmes à jour ou mis à niveau, les dernières fonctionnalités de sécurité sont désactivées ou ne sont pas configurées de manière sécurisée.
* les paramètres de sécurité dans les serveurs d'application, les frameworks applicatifs (ex. Struts, Spring, ASP.NET), les bibliothèques, les bases de données, etc. ne sont pas paramétrés avec des valeurs correctes du point de vue de la sécurité.
* le serveur n'envoie pas d'en-têtes ou de directives de sécurité, ou s'ils ne sont pas paramétrés avec des valeurs correctes du point de vue de la sécurité.
* La version du logiciel est obsolète ou vulnérable (voir **A9:2017 Utilisation de Composants avec des Vulnérabilités Connues**).

Sans un processus concerté et répétable de configuration de la sécurité des applications, les systèmes courent un risque plus élevé.

## Comment s'en Prémunir

Des processus d'installation sécurisés doivent être mis en œuvre, avec notamment :

* Un processus de durcissement répétable qui permette de déployer rapidement et facilement un autre environnement correctement sécurisé avec une configuration verrouillée. Les environnements de développement, d'assurance qualité et de production doivent tous être configurés de manière identique, avec des droits différents pour chaque environnement. Ce processus devrait être automatisé afin de réduire au minimum les efforts requis pour mettre en place un nouvel environnement sécurisé.

* Une plate-forme minimale sans fonctionnalités, composants, documentation et échantillons inutiles. Supprimez ou n'installez pas les fonctionnalités et frameworks inutilisés.

* Une tâche pour revoir et mettre à jour les configurations appropriées à tous les avis de sécurité, toutes les mises à jour et tous les correctifs dans le cadre du processus de gestion des correctifs (voir **A9:2017 Utilisation de Composants avec des Vulnérabilités Connues**). En particulier, examinez les permissions de stockage dans le Cloud (ex. les permissions des buckets AWS S3).

* Une architecture d'application segmentée qui fournit une séparation efficace et sécurisée entre les composants ou les environnement hébergés, avec de la segmentation, de la mise en conteneurs ou l'utilisation de groupes de sécurité dans le Cloud (ACL).

* L'envoi de directives de sécurité aux clients, par exemple [En-têtes de sécurité] (https://www.owasp.org/index.php/OWASP_Secure_Headers_Project).

* Un processus automatisé pour vérifier l'efficacité des configurations et des réglages dans tous les environnements.

## Exemple de Scénario d'Attaque

**Scénario #1** : Le serveur d'application est livré avec des applications classiques qui ne sont pas supprimées du serveur mis en production. Ces mêmes applications ont des failles de sécurité connues que les attaquants utilisent afin de compromettre le serveur. Si l'une de ces applications est la console d'administration, et que les comptes par défaut n'ont pas été modifiés, l'attaquant se connecte avec les mots de passe par défaut et prend la main sur la cible.

**Scénario #2**** : La fonctionnalité de listage des répertoires n'est pas désactivée sur le serveur. Un attaquant découvre qu'il peut simplement lister les répertoires. L'attaquant trouve et télécharge les classes Java compilées, qu'il décompose et fait l'ingéniérie inversée pour visualiser le code. L'attaquant trouve alors un grave défaut dans le contrôle d'accès de l'application.

**Scénario #3**: La configuration du serveur d'application permet de renvoyer aux utilisateurs des messages d'erreur détaillés, par exemple avec des traces des couches protocolaires applicatives. Cela peut ainsi exposer des informations sensibles ou des vulnérabilités sous-jacentes telles que les versions de composants dont on sait qu'elles sont vulnérables.

**Scénario #4**: Un fournisseur de services Cloud (CSP) a positionné des droits de partage par défaut qui sont ouverts sur  Internet par d'autres utilisateurs du CSP. Cela permet d'accéder à des données sensibles stockées dans le stockage Cloud.

## Références

### OWASP

* [OWASP Testing Guide: Configuration Management](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [OWASP Testing Guide: Testing for Error Codes](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

Pour des exigences supplémentaires dans ce domaine, voir la Norme de vérification de la sécurité des applications : Application Security Verification Standard [V19 Configuration](https://www.owasp.org/index.php/ASVS_V19_Configuration).

### Externes

* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
* [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
