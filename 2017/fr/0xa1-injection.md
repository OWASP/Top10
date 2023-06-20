# A1:2017 Injection

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilité    | Impacts  |
| -- | -- | -- |
| Accès Lvl : Exploitation 3 | Fréquence 2 : Détection 3 | Technique 3 : Métier |
| Considérez que n’importe qui peut envoyer des données non fiables au système, y compris les utilisateurs externes, internes, et administrateurs. Presque toute source de données peut être un vecteur d’injection, y compris les variables d'environnement, les paramètres et les web services internes et externes. [Les failles d'injection](https://www.owasp.org/index.php/Injection_Flaws) surviennent lorsqu’une application envoie des données non fiable à un interpréteur.  | Les failles d’injection sont très fréquentes, surtout dans le code ancien. On les retrouve souvent dans les requêtes SQL, LDAP, XPath, noSQL, commandes OS, parseurs XML, arguments de programme, etc. Les failles d’Injection sont faciles à découvrir lors d’un audit de code, mais plus difficilement via des tests. Scanners et Fuzzers aident les attaquants à les trouver. | L’Injection peut résulter en une perte ou une corruption de données, une divulgation à des tiers non autorisés, une perte de droits, ou un refus d’accès. L’Injection peut parfois mener à une prise de contrôle totale du serveur. Considérez la valeur métier de la donnée impactée et la plateforme exécutant l’interpréteur. Toute donnée pourrait être volée, modifiée ou supprimée. Votre réputation pourrait-elle en pâtir?|


## Suis-je vulnérable à l’Injection?

Une application est vulnérable quand :
* les données venant de l'utilisateur ne sont pas validées, filtrées ou nettoyées par l'application ;
* des requêtes dynamiques ou des appels non paramétrés sans échappage par rapport au contexte sont envoyés à l'interpréteur ;
* des données hostiles sont utilisées au sein de paramètres de recherche de mapping objet - relationnel (ORM) pour extraire des données supplémentaires sensibles ;
* des données hostiles sont utilisées directement ou concaténées, par exemple lors de la construction de requête dynamiques, de commandes ou de procédures stockées pour des requêtes SQL ou des commandes OS ;
* les injections les plus courantes se font dans le SQL, le NoSQL, les commandes OS, le mapping objet - relationnel, le LDAP, l'Expression Language et le Object Graph Navigation Library (OGNL). La façon de faire est la même pour tous les interpréteurs. La revue de code source est la meilleure manière de détecter si une application est vulnérable à l'Injection, suivie de près par le test automatique de toutes les données d'entrée via les paramètres, en-têtes, URL, cookies, JSON, SOAP et XML. Les organisations peuvent tirer profit de la puissance des outils d'analyse statique de code (SAST) ou d'analyse dynamique de l'application (DAST) en les intégrant dans leur chaine d'intégration continue (CI / CD) pour identifier avant déploiement en production les vulnérabilités liées aux injections. 

## Comment empêcher l'Injection?

Prévenir l’Injection exige de séparer les données non fiables des commandes et requêtes.

* La meilleure option est d’utiliser une API saine qui évite complètement l’utilisation de l’interpréteur ou fournit une interface paramétrable, ou bien de migrer pour utiliser les outils d'Object Relational Mapping Tools (ORMs). **Note**: Attention aux API, telles les procédures stockées, qui sont paramétrables, mais qui pourraient introduire une Injection SQL si PL/SQL ou T-SQL concatène requêtes et données ou exécute des données non saines avec EXECUTE IMMEDIATE ou exec().
* Pour les données en entrée, la « whitelist » avec normalisation est recommandée, mais n’est pas une défense complète dans la mesure où de nombreuses applications requièrent des caractères spéciaux, par exemple les zones de texte ou les API pour les applications mobiles.
* Pour les requêtes dynamiques restantes, vous devriez soigneusement échapper les caractères spéciaux en utilisant la syntaxe d’échappement spécifique à l’interpréteur. **Note**: Les structures SQL  telles que les noms de table, les noms de colonne, et d'autres ne peuvent pas être échappées et les noms de structures venant de l'utilisateur doivent donc être considérés comme dangereuses. Ceci est un problème courant dans les logiciels d'aide à l'écriture de rapports.
* Il est conseillé d'utiliser LIMIT et autres contrôles SQL à l'intérieur des requêtes pour empêcher les divulgations massives de données dans le cas d'injection SQL.

## Exemples de scénarios d'attaque

**Scenario #1**: L’application utilise des données non fiables dans la construction de l’appel SQL vulnérable suivant:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Scenario #2**: De même, la confiance aveugle d'une application dans les frameworks qu'elle utilise peut faire que ses requêtes sont toujours vulnérables (par exemple Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

Dans les deux cas, l'attaquant modifie le paramètre ‘id’ dans son navigateur en : ' UNION SELECT SLEEP(10);--. Par exemple :

`http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

Ceci change le sens de chacune des requêtes pour récupérer tous les enregistrements de la table des comptes. Dans le pire des cas, l’attaquant exploite cette faiblesse pour modifier ou détruire des données, ou appeler des procédures stockées de la base de données.

## Références

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Externes

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
