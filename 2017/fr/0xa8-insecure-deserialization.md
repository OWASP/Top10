# A8:2017 Insecure Deserialization

| Agents de menaces/Vecteurs d'attaques | Vulnérabilité | Impacts               |
| -- | -- | -- |
| Niveau d'accès : Exploitation 1 | Fréquence 2 : Détection 2 | Technique 3 : Métier |
| Il arrive que l'exploitation d'une désérialisation soit difficile car les codes d'exploitation génériques fonctionnent rarement sans une adaptation à l'application ciblée. | Cette vulnérabilité est incluse dans le Top 10 [sur la base d'un questionnaire rempli par des professionnels de la sécurité](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) et non sur des données quantifiables. Certains outils peuvent détecter des erreurs de désérialisation, mais une assistance humaine est souvent nécessaire pour valider le problème. Il faut s'attendre à une augmentation des défauts de désérialisation trouvés dans les applications à mesure que des outils sont développés pour aider à les identifier et à y remédier. | L'impact des erreurs de désérialisation ne doit pas être sous-estimé. Ces failles peuvent conduire à des attaques d'exécution de code à distance, l'une des attaques les plus graves qui soient. L'impact métier dépend des besoins de protection de l'application et des données. |

## Suis-je vulnérable aux défauts de désérialisation?

Les applications et les API seront vulnérables si elles désérialisent des objets hostiles ou altérés fournis par un attaquant.

Cela peut entraîner deux principaux types d'attaques:

* Attaques liées aux objets et à la structure de données où l'attaquant modifie la logique de l'application ou exécute du code arbitraire. Pour cela, il doit exister des classes dans l'application qui peuvent modifier le comportement pendant ou après la désérialisation.

* Attaques par falsification de données lorsque des structures sérialisées sont utilisées pour du contrôle d'accès et que le contenu est modifié par l'attaquant.

La sérialisation peut être utilisée dans des applications pour:

* Communication distante et inter-processus (RPC/IPC)
* Protocoles connectés, Web services, message brokers
* Mise en cache / Persistance
* Bases de données, serveurs de cache, systèmes de fichiers
* Cookies HTTP, paramètres de formulaire HTML, jetons d'authentification API

## Comment l'empêcher

La seule architecture logicielle sûre est de ne pas accepter les objets sérialisés provenant de sources non fiables ou d'utiliser des supports de sérialisation qui autorisent uniquement les types de données primitifs.

Si ce n'est pas possible, envisagez l'une des solutions suivantes:

* Implémenter des contrôles d'intégrité tels que des signatures numériques sur tous les objets sérialisés pour empêcher la création d'objets dangereux ou la falsification de données.
* Appliquer des contraintes de typage fort lors de la désérialisation avant la création de l'objet car le code attend généralement un ensemble définissable de classes. Des contournements de cette technique ont été démontrés, il est donc déconseillé de se fier uniquement à elle.
* Isoler et exécuter le code qui désérialise dans des environnements à faible privilège lorsque cela est possible.
* Journaliser les exceptions et échecs de désérialisation, par exemple lorsque le type entrant n'est pas le type attendu, ou que la désérialisation génère des exceptions.
* Restreindre ou surveiller la connectivité réseau entrante et sortante des conteneurs ou des serveurs utilisés pour la désérialisation.
* Faire une surveillance des désérialisations, alerter si un utilisateur désérialise constamment.

## Exemples de scénarios d'attaque

**Scenario #1**: Une application React appelle un ensemble de microservices Spring Boot. Sensibles à la programmation fonctionnelle, les développeurs essaient de s'assurer que leur code est immutable. La solution qu'ils ont trouvée consiste à sérialiser l'état de l'utilisateur et à le transmettre à chaque requête. Un attaquant remarque la signature d'objet Java "R00" et utilise [l'outil Java Serial Killer](https://github.com/NetSPI/JavaSerialKiller) pour effectuer une exécution de code à distance sur le serveur d'applications.



**Scenario #2**: Un forum utilise la sérialisation des objets PHP pour enregistrer un cookie, contenant l'ID utilisateur, le rôle, le condensat du mot de passe et les autres attributs de l'utilisateur.

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Un attaquant modifie l'objet sérialisé pour se donner des privilèges d'administrateur:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Références

### OWASP

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### External

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
