#Données et Methodologie

## Aperçu

Durant l'OWASP Project Summit (Belfast, mai 2017), les membres OWASP et les communautés participantes se sont mis d'accord sur une liste de vulnérabilités issue de sources quantitatives (données reçues suite à l'appel de données) et qualitatives (réponses aux sondages).
 
## Données qualitatives: Sondage à la Communauté

Les classes de vulnérabilités qui avaient préalablement été considérées mais rejetées de peu, ainsi que celles  mentionnées dans les évaluations de la proposition 2017 RC1 (via la liste de diffusion) ont été retenues pour le sondage. Nous avons demandé à la communauté de sélectionner les quatre classes de vulnérabilités les plus importantes à inclure dans l'édition 2017 du Top 10 OWASP. La collecte s'est déroulée du 2 août au 18 septembre 2017 (48 jours) et 516 réponses ont été soumises, triées ci-après:

| Rang | Classe de vulnérabilité | Score |
| -- | -- | -- |
| 1 | Fuites de Données Personnelles [CWE-359] | 748 |
| 2 | Utilisations Incorrectes de la Cryptographie [CWE-310/311/312/326/327]| 584 |
| 3 | Déserialisations de Données Sans Validation Préalable [CWE-502] | 514 |
| 4 | Contournements d'Autorisation par Modification de Références [CWE-639] | 493 |
| 5 | Journalisation et Surveillance Insuffisantes [CWE-223 / CWE-778]| 440 |

Les fuites de données personnelles occupent la première position avec une avance significative mais peuvent être assimilées à l'entrée pré-existante **A3:2017-Divulgation de données sensibles**. Tout comme les utilisations incorrectes de la cryptographie. Les désérialisations de données sans validation préalable occupent la 3ème position, elles ont été ajoutées au classement final sous **A8:2017-Désérialisation vulnérable** après calcul du risque. La quatrième entrée (contournements d'autorisations par modification de références) est incluse dans l'entrée préexistante **A5:2017-Contrôle d'accès défaillant**, le sondage valide la proposition initiale de la RC1. La cinquième classe de vulnérabilités, journalisation et surveillance insuffisantes, a été retenue sous **A10:2017-Journalisation et Surveillance insuffisantes**. Nous avons atteint un stade où les applications devraient produire des journaux et des alertes permettant des processus d'escalade et de réponse aux incidents appropriés.

## Données quantitatives: rapports de tests anonymisés 

Dans les versions précédentes du Top 10, la fréquence d'apparition des vulnérabilités dans les données (rapports de tests) fournies par la communauté a été retenue. Cette méthode était toutefois limitée: les écarts entre un rapport généré automatiquement (où la vulnérabilité X apparaît N fois) et un rapport généré manuellement (où la vulnérabilité X est mentionnée 1 fois pour N occurrences) empêchaient une comparaison statistiquement valide.

Pour le Top 10 2017, les prévalences des vulnérabilités ont été calculées via l'agrégation de deux informations (lorsque les données remises par les fournisseurs le permettaient): la prévalence d'une vulnérabilité dans un lot de données, d'une part, et la prévalence des applications qui contenaient la dite vulnérabilité. Bien que toujours imparfaite, cette méthode nous a permis d'identifier les écarts entre les échantillons de "programmes assistés par des humains" et ceux provenant d'"humains assistés par des programmes." Les données source et les analyses sont [accessibles via GitHub](https://github.com/OWASP/Top10/tree/master/2017/datacall). Ces analyses seront améliorées dans les versions futures du Top 10.

Plus de 40 lots de données nous ont été remis par 23 entreprises et organisations suite à notre appel, couvrant ainsi près de 114'000 applications (n=114'000). Lorsque le lot le permettait, l'analyse a été restreinte à l'année (j<=365) et les données regroupées par contributeur (n=23). Les applications analysées sont majoritairement "uniques" bien que des répétitions soient possibles (p.ex.: certains lots proviennent de tests annuels effectués par l'entreprise Veracode). Les 23 lots de données résultants ont ensuite été classés selon le type de source (rapports de tests manuels vs. rapports de tests automatisés) et les incidences/prévalences adaptées en conséquence. Dans les cas où la prévalence d'une vulnérabilité (nb. d'applications contenant la vulnérabilité X) était supérieure à 1, la valeur 1 a été retenue. La prévalence indiquée dans les scores de risque prend en compte l'incidence et la prévalence de chaque vulnérabilité.
