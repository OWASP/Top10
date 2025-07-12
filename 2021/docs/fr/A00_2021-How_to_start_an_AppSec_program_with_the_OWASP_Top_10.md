# Comment démarrer un programme de sécurité des applications (SecApp) avec l'OWASP Top 10

Auparavant, l'OWASP Top 10 n'avait jamais été conçu pour servir de base à un programme SecApp. Cependant, il est essentiel de commencer quelque part pour de nombreuses organisations qui commencent tout juste leur parcours en matière de sécurité des applications. Le Top 10 OWASP 2021 est un bon début en tant que référence pour les listes de contrôle, etc., mais il n'est pas suffisant en soi.

## Étape 1. Identifiez les lacunes et les objectifs de votre programme de sécurité des applications

De nombreux programmes de sécurité des applications (SecApp) essaient de courir avant de savoir marcher. Ces efforts sont voués à l'échec. Nous encourageons fortement les RSSI et les dirigeants SecApp à utiliser l'[OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) pour identifier les faiblesses et les domaines à améliorer sur une période de 1 à 3 ans. La première étape consiste à évaluer où vous en êtes maintenant, à identifier les lacunes en matière de gouvernance, de conception, de mise en œuvre, de vérification et d'opérations que vous devez résoudre immédiatement par rapport à celles qui peuvent attendre, et de prioriser la mise en œuvre ou l'amélioration des quinze pratiques de sécurité OWASP SAMM. OWASP SAMM peut vous aider à créer et à mesurer des améliorations dans vos efforts d'assurance logicielle.

## Étape 2. Planifier un cycle de vie de développement sécurisé pour une voie pavée

Traditionnellement l'apanage des soi-disant "licornes", le concept de voie pavée est le moyen le plus simple d'avoir le plus d'impact et de faire évoluer les ressources SecApp avec la vélocité de l'équipe de développement, qui n'augmente que chaque année.

Le concept de voie pavée est "le moyen le plus simple est aussi le moyen le plus sûr" et devrait impliquer une culture de partenariats profonds entre l'équipe de développement et l'équipe de sécurité, de préférence de telle sorte qu'ils forment une seule et même équipe. La voie pavée vise à améliorer, mesurer, détecter et remplacer en permanence les alternatives non sécurisées en disposant d'une bibliothèque de remplacements sécurisés à l'échelle de l'entreprise, avec des outils pour aider à voir où des améliorations peuvent être apportées en adoptant la voie pavée. Cela permet aux outils de développement existants de signaler les versions non sécurisées et d'aider les équipes de développement à se corriger elles-mêmes des alternatives non sécurisées.

La voie pavée peut sembler beaucoup de choses à digérer, mais elle devrait être construite progressivement au fil du temps. Il existe d'autres formes de programmes SecApp, notamment le cycle de vie du développement de la sécurité de Microsoft. Toutes les méthodologies de programme SecApp ne conviennent pas à toutes les entreprises.

## Étape 3. Mettez en place la voie pavée avec vos équipes de développement

Les voies pavées sont construites avec le consentement et la participation directe des équipes de développement et d'exploitation concernées. La voie pavée doit être alignée sur la stratégie de l'entreprise et aider à fournir plus rapidement des applications plus sécurisées. Développer la voie pavée devrait être un exercice holistique couvrant l'ensemble de l'entreprise ou de l'écosystème d'applications, et non un pansement par application, comme autrefois.

## Étape 4. Migrer toutes les applications à venir et existantes vers la voie pavée

Ajoutez des outils de détection à la voie pavée au fur et à mesure que vous les développez et fournissez des informations aux équipes de développement pour améliorer la sécurité de leurs applications en leur expliquant comment elles peuvent adopter directement des éléments de la voie pavée. Une fois qu'un aspect de la voie pavée a été adopté, les organisations doivent mettre en œuvre des contrôles d'intégration continue qui inspectent le code existant et les nouvelles contributions qui utilisent des alternatives interdites et avertissent ou rejettent la version ou la contribution. Cela empêche les options non sécurisées de s'infiltrer dans le code au fil du temps, évitant ainsi une dette technique et une application non sécurisée défectueuse. De tels avertissements doivent être liés à l'alternative sécurisée, afin que l'équipe de développement reçoive immédiatement la bonne réponse. Ils peuvent remanier et adopter rapidement le composant de la voie pavée.

## Étape 5. Tester que la voie pavée a atténué les problèmes signalés dans le Top 10 de l'OWASP

Les composants de la voie pavée devraient résoudre un problème important signalé dans l'OWASP Top 10, par exemple, comment détecter ou réparer automatiquement les composants vulnérables, ou un plugin IDE d'analyse de code statique pour détecter les injections, ou encore mieux, commencer à utiliser une dépendance connue pour être sécurisée contre les injections. Plus ces remplacements sécurisés sont fournis aux équipes, mieux c'est. Une tâche vitale de l'équipe SecApp est de s'assurer que la sécurité de ces composants est continuellement évaluée et améliorée. Une fois qu'ils sont améliorés, une forme de voie de communication avec les consommateurs du composant doit indiquer qu'une mise à niveau doit se produire, de préférence automatiquement, mais sinon, au moins mise en évidence sur un tableau de bord ou similaire.

## Étape 6. Transformez votre programme en un programme SecApp mature

Il ne faut pas s'arrêter au Top 10 de l'OWASP. Il ne couvre que 10 catégories de risques. Nous encourageons fortement les organisations à adopter l'OWASP Application Security Verification Standard (ASVS) et à ajouter progressivement des composants et des tests de voies pavées pour les niveaux 1, 2 et 3, en fonction du niveau de risque des applications développées.

## Aller plus loin

Les meilleurs programmes SecApp vont au-delà du strict minimum. Tout le monde doit continuer les efforts si nous voulons un jour maîtriser les vulnérabilités.

-   **Intégrité conceptuelle**. Les programmes SecApp matures doivent contenir un certain concept d'architecture de sécurité, qu'il s'agisse d'une architecture formelle de sécurité cloud ou d'entreprise ou d'une modélisation des menaces ;
-   **Automatisation et échelle**. Les programmes SecApp matures essaient d'automatiser autant que possible leurs livrables, en utilisant des scripts pour émuler des tests d'intrusion complexes, des outils d'analyse de code statique directement disponibles pour les équipes de développement, en aidant les équipes de développement à créer des tests unitaires et d'intégration de sécurité, et plus encore.
-   **Culture**. Les programmes SecApp matures essaient de supprimer les conceptions non sécurisées et d'éliminer la dette technique du code existant en faisant partie de l'équipe de développement et non à côté. Les équipes SecApp qui voient les équipes de développement comme "nous" et "eux" sont vouées à l'échec.
-   **Amélioration continue**. Les programmes SecApp matures cherchent à s'améliorer constamment. Si quelque chose ne fonctionne pas, arrêtez de le faire. Si quelque chose est poussif ou non évolutif, travaillez pour l'améliorer. Si quelque chose n'est pas utilisé par les équipes de développement et n'a pas ou peu d'impact, faites quelque chose de différent. Ce n'est pas parce que nous avons fait des tests comme des contrôles administratifs depuis les années 1970 que c'est une bonne idée. Mesurez, évaluez, puis construisez ou améliorez.
