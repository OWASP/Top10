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

## How to Prevent

There should be a patch management process in place to:

-   Remove unused dependencies, unnecessary features, components, files,
    and documentation.

-   Continuously inventory the versions of both client-side and
    server-side components (e.g., frameworks, libraries) and their
    dependencies using tools like versions, OWASP Dependency Check,
    retire.js, etc. Continuously monitor sources like Common Vulnerability and 
    Exposures (CVE) and National Vulnerability Database (NVD) for
    vulnerabilities in the components. Use software composition analysis
    tools to automate the process. Subscribe to email alerts for
    security vulnerabilities related to components you use.

-   Only obtain components from official sources over secure links.
    Prefer signed packages to reduce the chance of including a modified,
    malicious component (See A08:2021-Software and Data Integrity
    Failures).

-   Monitor for libraries and components that are unmaintained or do not
    create security patches for older versions. If patching is not
    possible, consider deploying a virtual patch to monitor, detect, or
    protect against the discovered issue.

Every organization must ensure an ongoing plan for monitoring, triaging,
and applying updates or configuration changes for the lifetime of the
application or portfolio.

## Example Attack Scenarios

**Scenario #1:** Components typically run with the same privileges as
the application itself, so flaws in any component can result in serious
impact. Such flaws can be accidental (e.g., coding error) or intentional
(e.g., a backdoor in a component). Some example exploitable component
vulnerabilities discovered are:

-   CVE-2017-5638, a Struts 2 remote code execution vulnerability that
    enables the execution of arbitrary code on the server, has been
    blamed for significant breaches.

-   While the internet of things (IoT) is frequently difficult or
    impossible to patch, the importance of patching them can be great
    (e.g., biomedical devices).

There are automated tools to help attackers find unpatched or
misconfigured systems. For example, the Shodan IoT search engine can
help you find devices that still suffer from Heartbleed vulnerability
patched in April 2014.

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
