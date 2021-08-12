# I Introduction

## Bienvenue dans le  Top 10 OWASP - 2017

Cette mise à jour majeure ajoute plusieurs nouveaux problèmes, dont deux sélectionnés par la communauté - A8:2017- Désérialisation sans validation et A10:2017- Journalisation et surveillance insuffisantes. Les deux différences clé par rapport aux précédents Tops 10 OWASP sont les importants retours de la communauté et l'immense masse de données rassemblées par des douzaines d'organismes : sans doute la quantité la plus importante jamais collectée pour préparer une norme de sécurité applicative. Cela nous permet de supposer raisonnablement que le nouveau TOP 10 OWASP répond aux risques sécuritaires applicatifs les plus graves rencontrés par les entreprises.

Le Top 10 OWASP 2017 est principalement fondé sur les données fournies par plus de quarante entreprises spécialisées dans la sécurité applicative, ainsi que sur un sondage effectué auprès de plus de 500 personnes. Ces données concernent des vulnérabilités collectées auprès de centaines d'organismes et provenant de plus de 100 000 applications et APIs existantes. Les éléments du Top 10 sont sélectionnés et prioritisés selon leur fréquence constatée, ainsi que selon un consensus d'estimations en matière d'exploitabilité, de détectabilité et d'impact potentiel.

Un des buts fondamentaux du Top 10 OWASP est d'éduquer les développeurs, concepteurs, architectes, gestionnaires et organismes sur les conséquences des failles de sécurité les plus fréquentes et les plus importantes des applications web. Le Top 10 propose des techniques fondamentales pour se protéger contre ces problèmes à haut risque ainsi que des pistes sures pour aller plus loin.

## Avertissement

**Ne vous arrêtez pas à 10**. Il existe des centaines de problèmes susceptibles d'altérer la sécurité globale d'une application web, comme expliqué dans le [Guide du Développeur OWASP](https://github.com/OWASP/DevGuide) et la série des [aide-mémoire OWASP](https://cheatsheetseries.owasp.org/). Ce sont des lectures essentielles pour quiconque développe des applications web et des APIs. Des conseils sur la façon d'identifier des vulnérabilités dans des applications web et des APIs sont fournies dans le [Guide de test OWASP](https://owasp.org/www-project-web-security-testing-guide/).

**Evolution constante**. Le Top 10 OWASP évolue. Même sans modifier une quelconque ligne du code de votre application, celle-ci pourrait devenir vulnérable suite à la découverte d'une nouvelle faille et/ou à l'évolution d'une méthode d'attaque. Reportez-vous pour plus d'information aux conseils figurant en annexes à la fin du Top 10.

**Pensez positif !**. Quand vous serez prêt à arrêter de chasser les vulnérabilités et à vous concentrer sur l'établissement de solides contrôles de sécurité des applications, l'OWASP a publié le projet [Contrôles proactifs](https://owasp.org/www-project-proactive-controls/) comme point de départ pour aider les développeurs à intégrer la sécurité dans leurs applications et le [Standard de Vérification de Sécurité Applicative (ASVS, _Application Security Verification Standard_)](https://owasp.org/www-project-application-security-verification-standard/) comme guide pour les entreprises et les auditeurs d'applications sur ce qu'il faut vérifier.

**Utilisez les outils sagement !**. Les failles de sécurité peuvent être complexes et profondément enfouies dans le code. Très souvent, l'approche la moins coûteuse pour identifier et éliminer ces faiblesses passe par des experts humains armés d'outils avancés. Se reposer uniquement sur ces outils peut procurer un sentiment de sécurité trompeur et est déconseillé.

**Allez plus loin !**. Faites de la sécurité une partie intégrante de la culture de votre entreprise. Pour en savoir plus, reportez-vous au projet OWASP [SAMM (_Software Assurance Maturity Model_)](https://owasp.org/www-project-samm/).

## Remerciements

Nous tenons à remercier toutes les organisations qui ont transmis leurs données de vulnérabilités pour participer à la mise à jour 2017. Nous avons reçu plus de 40 réponses à notre requête de données. Pour la première fois, toutes les données ayant contribué à cette mise à jour ainsi que la liste des contributeurs est publiquement disponible. C'est certainement une des plus grandes et plus riches collections de données de vulnérabilités jamais rassemblées publiquement.

La liste des contributeurs excédant largement la place disponible ici, nous avons ajouté une page dédiée à la reconnaissance de ces contributions. Nous souhaitons remercier du fond du coeur tous ces organismes pour avoir tenu à être sur la ligne de front en partageant publiquement leurs données de vulnérabilités. Nous espérons voir leur nombre croître et encourageons d'autres entreprises à procéder de même sur ce qui est sans doute un élément clé de la sécurité fondée sur les faits. Le Top 10 OWASP ne pourrait exister sans ces fantastiques contributions. 

Un grand merci aux individus (plus de 500 !) qui ont pris le temps de répondre à l'étude industrielle. Votre voix a aidé à retenir deux nouveaux ajouts au Top 10. Les commentaires, messages d'encouragements et critiques ont tous été appréciés. Nous savons que votre temps est précieux et tenons à vous dire merci.

Nous aimerions également remercier ceux qui ont contribués par des commentaires constructifs et ont consacrés du temps à relire cette mise à jour du Top 10. Nous les avons autant que possible cités sur la page de Remerciements.

Enfin, nous souhaitons remercier par avance tous les traducteurs qui vont traduire cette version du Top 10 dans différentes langues, aidant ainsi à la rendre disponible sur toute la planète. 
