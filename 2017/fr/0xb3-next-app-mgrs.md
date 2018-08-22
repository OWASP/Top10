# +A: 	Perspectives pour les gestionnaires d'applications

## Gestion de la totalité du cycle de vie de l'application

Les applications appartiennent aux systèmes les plus complexes régulièrement créées et maintenues par des humains. La gestion informatique d'une application doit être effectuée par les spécialistes responsables du cycle de vie informatique total de l'application. Nous préconisons que ce rôle de gestionnaire d'application soit la contrepartie technique de celui du propriétaire de l'application. Le gestionnaire d'application est responsable du cycle de vie total de l'application d'un point de vue 'technologies de l'information', depuis le recueil des exigences jusqu'au retrait des systèmes - un point souvent négligé.

## Gestion des besoins et des ressources

* Recueillez et confrontez les exigences métier d'une application au métier concerné. Cela inclut les nécessités de protection relatives à la confidentialité, à l'authentification, à l'intégrité et à la disponibilité des ressources en données, ainsi que la logique de travail attendue.
* Rassemblez les exigences techniques, y compris les contraintes de sécurité fonctionnelles et non-fonctionnelles.
* Préparez et ponderez un budget recouvrant tous les aspects de la conception, du codage, des tests et de la mise en oeuvre, y compris les activités sécuritaires.

## Recueil de propositions (RFP, _Request for Proposals_) et contractualisation

* Retravaillez les exigences avec des développeurs internes ou externes, y compris des règles de conduite et des exigences sécuritaires provenant de votre programme de sécurité (SDLC) et des pratiques recommandées.
* Evaluez le degré d'achèvement de toutes les exigences techniques, avec une phase de prévision et de conception.
* Analysez toutes les exigences techniques, y compris conception, sécurité et niveaux de service attendus (SLA, _Service level Agreements_).
* Adoptez des modèles et des checklists, comme [OWASP Secure Software Contract Annex](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex). **Remarque** : Cette annexe respectant la loi américaine sur les contrats, consultez un expert juridique pertinent avant de l'employer.

## Planification et conception

* Etudiez la planification et la conception avec des développeurs et les parties prenantes internes, comme les spécialistes en sécurité.
* Définissez l'architecture de sécurité, les contrôles et les contre-mesures adaptés aux besoins de protection ainsi qu'au niveau de menace estimé. Cela doit être approuvé par des spécialistes en sécurité.
* Assurez-vous que le propriétaire de l'application accepte les risques restants ou procure des ressources additionnelles.
* Vérifiez qu'à chaque étape des scénarios de sécurité soient créés, incluant des contraintes supplémentaires d'exigences non-fonctionnelles.

## Déploiement, Tests et Retrait

* Automatisez le déploiement sécurisé de l'application, des interfaces et de tous les composants nécessaires, y compris les autorisations indispensables.
* Testez les fonctions techniques et l'intégration avec l'architecture du système d'information et coordonnez les tests métier.
* Créez des cas de test d'utilisation "normale" et "abusive" selon des perspectives techniques et de métier.
* Gérez des tests de sécurité adaptés aux processus internes, aux besoins de protection et au niveau de menaces estimé pour l'application.
* Mettez en poeuvre l'application et effectuez si nécessaire la migration depuis les applications antérieurement employées.
* Finalisez toute la documentation, y compris la la base de données de gestion des modifications (CMDB, _Change Management DataBase_) et l'architecture de sécurité.

## Gestion des mises en oeuvre et des modifications

* Les mises en oeuvre doivent inclure des règles de conduite pour la gestion de la sécurité de l'application (par exemple, gestion des correctifs).
* Développez la conscience sécuritaire des utilisateurs et arbitrez les conflits entre employabilité et sécurité.
* Prévoyez et gérez les modifications, par exemple la migration vers de nouvelles versions de l'application ou d'autres composants tels le système d'exploitation, des composants logiciels tiers ou des bibliothèques.
* Mettez à jour toute la documentation, y compris la base de données de gestion des modifications et l'architecture de sécurité.

## Purge des systèmes

* Toute donnée utile doit être archivée. Les autres données doivent être effacées de façon sécurisée.
* Supprimez l'application de manière sécurisée, y compris les comptes, rôles et autorisations inemployés.
* Fixez l'état de l'application à Supprimé dans la CMDB.
