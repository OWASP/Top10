
# Risque - Risques liés à la sécurité des applications

## Quels sont les risques pour la sécurité des applications ?

Les attaquants peuvent potentiellement utiliser de nombreux chemins différents à travers votre application pour nuire à votre entreprise ou organisation. Chacune de ces voies représente un risque qui peut, ou non, être suffisamment grave pour justifier une attention particulière.

![Risques de sécurité de l'application](images/0x10-risk-1.png)

Parfois ces chemins sont triviaux à trouver et à exploiter, et parfois ils sont extrêmement difficiles. De même, le préjudice causé peut être sans conséquence, ou il peut vous mettre en faillite. Pour déterminer le risque pour votre organisation, vous pouvez évaluer la probabilité associée à chaque agent de menace, vecteur d'attaque et faiblesse de sécurité et la combiner avec une estimation de l'impact technique et commercial pour votre organisation. Ensemble, ces facteurs déterminent votre risque global.

## Quel est mon risque ?

Le [Top 10 de l'OWASP](https://www.owasp.org/index.php/Top10) se concentre sur l'identification des risques les plus sérieux pour la sécurité des applications Web d'un large éventail d'organisations. Pour chacun de ces risques, nous fournissons des informations génériques sur la probabilité et l'impact technique à l'aide du système de notation simple suivant, qui est basé sur la méthodologie de notation des risques de l'OWASP.  

| Agents de menace | Exploitabilité | Prévalence de la faiblesse | Détectabilité de la faiblesse | Impacts techniques | Impacts commerciaux |
| --- | --- | --- | --- | --- | --- |
| Appli-   | Facile 3 | Répandu 3 | Facile 3 | Sévère 3 | Commercial     |
| cation   | Moyen 2 | Commun 2 | Moyen 2 | Modéré 2 | Specifique |
| Specifique | Difficile 1 | Rare 1 | Difficile 1 | Mineur 1 |       |

Dans la présente édition, nous avons mis à jour le système d'évaluation des risques pour faciliter le calcul de la probabilité et de l'incidence d'un risque donné. Pour plus de détails, voir la [Note sur les risques](0xc0-note-about-risks.md). 

Chaque organisation est unique, de même que les acteurs de la menace pour cette organisation, leurs objectifs et l'impact de toute violation. Si une organisation d'intérêt public utilise un système de gestion de contenu (SGC) pour l'information publique et qu'un système de santé utilise le même SGC pour les dossiers de santé sensibles, les acteurs de la menace et les impacts commerciaux peuvent être très différents pour le même logiciel. Il est essentiel de comprendre le risque pour votre organisation en fonction des agents de menace et des répercussions commerciales applicables.

Dans la mesure du possible, les noms des risques figurant dans le Top 10 sont alignés sur les faiblesses [Common Weakness Enumeration](https://cwe.mitre.org/) (CWE) afin de promouvoir des conventions d'appellation généralement acceptées et de réduire la confusion.

## Références

### OWASP

* [Méthodologie d'évaluation des risques de l'OWASP](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Article sur la modélisation des menaces et des risques](https://www.owasp.org/index.php/Application_Threat_Modeling)

### Externe

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://acsc.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
