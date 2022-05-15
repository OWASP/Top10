# A05:2021 – Mauvaise configuration de sécurité    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       20       |       19,84 %        |         4,51 %         |             8,12              |         6,56         |    89,58 %     |      44,84 %       |          208 387           |         789          |

## Aperçu

En progression depuis la sixième place, 90&nbsp;% des applications ont été testées pour une forme de mauvaise configuration, avec un taux d'incidence moyen de 4,51&nbsp;% et plus de 208&nbsp;000 occurrences de *Common Weakness Enumeration* (CWE) dans cette catégorie. Avec une plus grande part de logiciels offrant une configuration riche, il n'est pas surprenant de voir cette catégorie gagner une place. Les CWEs notables incluses sont *CWE-16 Configuration* et *CWE-611 Improper Restriction of XML External Entity Reference*.

## Description 

L'application peut être vulnérable si :

-   elle n'a pas fait l'objet d'un durcissement de la sécurité approprié sur l'ensemble des couches protocolaires applicatives, ou si les permissions sont mal configurées sur les services cloud ;
-   des fonctionnalités inutiles sont activées ou installées (ex : des ports, des services, des pages, des comptes ou des privilèges inutiles) ;
-   les comptes par défaut et leurs mots de passe sont toujours activés et inchangés ;
-   le traitement des erreurs révèle aux utilisateurs des traces des piles protocolaires ou d'autres messages d'erreur laissant transpirer trop d'informations ;
-   pour les systèmes à jour ou mis à niveau, les dernières fonctionnalités de sécurité sont désactivées ou ne sont pas configurées de manière sécurisée ;
-   les paramètres de sécurité dans les serveurs d'application, les frameworks applicatifs (ex : Struts, Spring, ASP.NET), les bibliothèques, les bases de données, etc. ne sont pas paramétrés avec des valeurs correctes du point de vue de la sécurité ;
-   le serveur n'envoie pas d'en-têtes ou de directives de sécurité, ou s'ils ne sont pas paramétrés avec des valeurs correctes du point de vue de la sécurité ;
-   La version du logiciel est obsolète ou vulnérable (voir [A06:2021-Composants vulnérables et obsolètes](A06_2021-Vulnerable_and_Outdated_Components.md)).

Sans un processus concerté et répétable de configuration de la sécurité des applications, les systèmes courent un risque plus élevé.

## Comment s'en prémunir

Des processus d'installation sécurisés doivent être mis en œuvre, avec notamment :

- un processus de durcissement répétable qui permette de déployer rapidement et facilement un autre environnement correctement sécurisé avec une configuration verrouillée. Les environnements de développement, d'assurance qualité et de production doivent tous être configurés de manière identique, avec des droits différents pour chaque environnement. Ce processus devrait être automatisé afin de réduire au minimum les efforts requis pour mettre en place un nouvel environnement sécurisé ;
- une plate-forme minimale sans fonctionnalité, composant, documentation et échantillon inutile. Supprimer ou ne pas installer des fonctionnalités et frameworks inutilisés ;
- une tâche pour revoir et mettre à jour les configurations appropriées à tous les avis de sécurité, toutes les mises à jour et tous les correctifs dans le cadre du processus de gestion des correctifs (voir [A06:2021-Composants vulnérables et obsolètes](A06_2021-Vulnerable_and_Outdated_Components.md)). En particulier, examiner les permissions de stockage dans le Cloud (ex. les permissions des buckets AWS S3) ;
- une architecture d'application segmentée qui fournit une séparation efficace et sécurisée entre les composants ou les environnements hébergés, avec de la segmentation, de la mise en conteneurs ou l'utilisation de groupes de sécurité dans le Cloud (ACL) ;
- l'envoi de directives de sécurité aux clients, par exemple [En-têtes de sécurité](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project) ;
- un processus automatisé pour vérifier l'efficacité des configurations et des réglages dans tous les environnements.

## Exemple de scénarios d'attaque

**Scénario 1** : Le serveur d'application est livré avec des applications classiques qui ne sont pas supprimées du serveur mis en production. Ces mêmes applications ont des failles de sécurité connues que les attaquants utilisent afin de compromettre le serveur. Si l'une de ces applications est la console d'administration, et que les comptes par défaut n'ont pas été modifiés, l'attaquant se connecte avec les mots de passe par défaut et prend la main sur la cible.

**Scénario 2** : La fonctionnalité de listage des répertoires n'est pas désactivée sur le serveur. Un attaquant découvre qu'il peut simplement lister les répertoires. L'attaquant trouve et télécharge les classes Java compilées, qu'il décompose et fait de l'ingénierie inversée pour visualiser le code. L'attaquant trouve alors un grave défaut dans le contrôle d'accès de l'application.

**Scénario 3** : La configuration du serveur d'application permet de renvoyer aux utilisateurs des messages d'erreur détaillés, par exemple avec des traces des couches protocolaires applicatives. Cela peut ainsi exposer des informations sensibles ou des vulnérabilités sous-jacentes telles que les versions de composants dont on sait qu'elles sont vulnérables.

**Scénario 4** : Un fournisseur de services Cloud (CSP) a positionné des droits de partage par défaut qui sont ouverts sur Internet par d'autres utilisateurs du CSP. Cela permet d'accéder à des données sensibles stockées dans le stockage Cloud.

## Références

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   [Application Security Verification Standard V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Liste des CWEs associées

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

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
