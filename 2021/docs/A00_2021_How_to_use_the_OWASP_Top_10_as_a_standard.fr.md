# Comment utiliser le Top 10 OWASP en tant que standard

Le Top 10 OWASP est avant tout un document informatif. Cependant, cela n'a
pas empêché un bon nombre d'organisations de l'utiliser en tant que standard
de facto dans l'industrie de la sécurité des applications depuis son lancement
en 2003. Si vous souhaitez utiliser le TOP 10 OWASP en tant que standard
de développement ou de réalisation de tests, sachez qu'il doit être considéré
comme point de départ et qu'il ne couvre que le strict minimum.

Une des difficultés à utiliser le TOP 10 OWASP en tant que standard est que
nous ne documentons que les risques de sécurité des applications et que
certains problèmes ne sont pas nécessairement simples à tester. Par exemple,
le [A04:2021-Conception non sécurisée] va au-delà de la plupart des méthodes
de tests. Un autre exemple est le test de l'efficacité des pratiques de
journalisation et de surveillance en place, qui ne peut être fait que par le biais
d'interviews et d'une demande d'exemples concrets de réponses à incident.
Un outil d'analyse de code statique peut vérifier l'absence de journalisation,
mais il lui sera sans doute incapable de déterminer si les parties de
logique métier ou de contrôle d'accès journalisent les atteintes critiques à 
la sécurité. De même des pentesters ne pourraient qu'être capables de déterminer
s'ils ont provoqué une réponse à incident dans un environnement de test,
qui est rarement surveillé de la même manière qu'un environnement de
production.

Voici nos recommendations sur les utilisations appropriées du Top 10 OWASP :

| Cas d'utilisation                | OWASP Top 10 2021 | Standard OWASP de vérification de la sécurité applicative |
|----------------------------------|:-------------------:|:--------------------------------------------------:|
| Sensibilisation                  | Oui               |                                                           |
| Entraînement                     | Niveau débutant   | Global                                                    |
| Conception et architecture       | Parfois           | Oui                                                       |
| Normes de codage                 | Strict minimum    | Oui                                                       |
| Revue de code                    | Strict minimum    | Oui                                                       |
| Examen par des pairs (checklist) | Strict minimum    | Oui                                                       |
| Tests unitaires                  | Parfois           | Oui                                                       |
| Tests d'integration              | Parfois           | Oui                                                       |
| Tests d'intrusion                | Strict minimum    | Oui                                                       |
| Outil de support                 | Strict minimum    | Oui                                                       |
| Chaîne logistique sécurisée      | Parfois           | Oui                                                       |

Nous encourageons quiconque voulant adopter un standard de sécurité des applications
à utiliser le [Standard de vérification de sécurité des applications OWASP](https://owasp.org/www-project-application-security-verification-standard/)
(SVSA), celui-ci est conçu pour la vérification et les tests et peut
être utilisé au cours de chaque étape d'un cycle de développement sécurisé.

Le SVSA est le seul choix acceptable pour les fournisseurs de solutions.
Les outils ne peuvent pas tester, détecter ou protéger de tous les risques
du Top 10 OWASP en raison de la nature de plusieurs de ceux-ci 
(ex. A04:2021-Conception non sécurisée). L'OWASP décourage toute affirmation
qu'un outil offre une couverture complète du Top 10 OWASP, car c'est
simplement faux.
