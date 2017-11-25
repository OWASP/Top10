# A1:2017 Injection

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilité           | Impacts Techniques               |
| Impacts Métiers | -- | -- |
| Accès Lvl : Exploitation 3 | Fréquence 2 : Détection 3 | Impact 3 : Business |
| Considérez que n’importe qui peut envoyer des données non fiables au système, y compris les utilisateurs externes, internes, et administrateurs. Presque toute source de données peut être un vecteur d’injection, y compris des sources internes.[Les failles d'injection](https://www.owasp.org/index.php/Injection_Flaws) surviennent lorsqu’une application envoie des données non fiable à un interpréteur.  | Les failles d’injection sont très fréquentes, surtout dans le code ancien. On les retrouve souvent dans les requêtes SQL, LDAP, XPath, commandes OS, parseurs XML, arguments de programme, etc. Les failles d’Injection sont faciles à découvrir lors d’un audit de code, mais plus difficilement via test. Scanners et Fuzzers aident les attaquants à les trouver. |L’Injection peut résulter en une perte ou une corruption de données, une perte de droits, ou un refus d’accès. L’Injection peut parfois mener à une prise de contrôle totale du serveur. Considérez la valeur métier de la donnée impactée et la plateforme exécutant l’interpréteur. Toute donnée pourrait être volée, modifiée ou supprimée. Votre réputation pourrait-elle en pâtir?|


## Suis-je vulnérable à l’Injection?

Le meilleur moyen de savoir si une application est vulnérable à l’Injection est de vérifier que toute utilisation d’interpréteurs sépare explicitement les données non fiables de la commande ou de la requête. Pour les appels SQL, cela signifie utiliser des variables liées dans toutes les instructions préparées et procédures stockées, en évitant les requêtes dynamiques.
Vérifier le code est un moyen rapide et adéquat pour s’assurer que l’application utilise sainement les interpréteurs. Les outils d’analyse de code peuvent aider à localiser l’usage des interpréteurs et tracer leur flux de données à travers l’application. Les Pentesters peuvent valider ces problèmes en concevant des exploits qui confirment la vulnérabilité.
Le scan dynamique peut donner un aperçu des failles d’Injection existantes. Les scanners ne savent pas toujours atteindre les interpréteurs, ni si une attaque a réussi. Une mauvaise gestion d’erreur aide à trouver les failles.

## How To Prevent

Preventing injection requires keeping data separate from commands and queries.

* The preferred option is to use a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs). **Note**: Even when parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data, or executes hostile data with EXECUTE IMMEDIATE or exec().
* Use positive or "whitelist" server-side input validation. This is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications.
* For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter. **Note**: SQL structure such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software.
* Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.

## Example Attack Scenarios

**Scenario #1**: An application uses untrusted data in the construction of the following vulnerable SQL call:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Scenario #2**: Similarly, an application’s blind trust in frameworks may result in queries that are still vulnerable, (e.g. Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

In both cases, the attacker modifies the ‘id’ parameter value in their browser to send:  ' or '1'='1. For example:

`http://example.com/app/accountView?id=' or '1'='1`

This changes the meaning of both queries to return all the records from the accounts table. More dangerous attacks could modify or delete data, or even invoke stored procedures.

## References

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### External

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
