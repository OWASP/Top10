# A03:2021 – Injection    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"} 

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       33       |       19,09 %        |         3,37 %         |             7,25              |         7,15         |    94,04 %     |      47,90 %       |          274 228           |        32 078        |

## Aperçu

Injection glisse à la troisième place. 94&nbsp;% des applications ont été testées pour une forme d'injection avec un taux d'incidence maximal de 19&nbsp;%, un taux d'incidence moyen de 3&nbsp;% et 274&nbsp;000 occurrences. Les *Common Weakness Enumerations* (CWEs) notables incluses sont *CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, and *CWE-73: External Control of File Name or Path*.

## Description 

Une application est vulnérable quand :

- les données venant de l'utilisateur ne sont pas validées, filtrées ou nettoyées par l'application&nbsp;;
- des requêtes dynamiques ou des appels non paramétrés sans échappement par rapport au contexte sont envoyés à l'interpréteur&nbsp;;
- des données hostiles sont utilisées au sein de paramètres de recherche de mapping objet - relationnel (ORM) pour extraire des données supplémentaires sensibles&nbsp;;
- des données hostiles sont utilisées directement ou concaténées, par exemple lors de la construction de requêtes dynamiques, de commandes ou de procédures stockées pour des requêtes SQL ou des commandes OS.

Les injections les plus courantes se font dans le SQL, le NoSQL, les commandes OS, le mapping objet - relationnel, le LDAP, l'Expression Language et le Object Graph Navigation Library (OGNL). La façon de faire est la même pour tous les interpréteurs. La revue de code source est la meilleure manière de détecter si une application est vulnérable à l'injection. Le test automatique de toutes les données d'entrée via les paramètres, en-têtes, URL, cookies, JSON, SOAP et XML est fortement encouragé. Les organisations peuvent tirer profit de la puissance des outils d'analyse statique de code (SAST) ou d'analyse dynamique de l'application (DAST) en les intégrant dans leur chaine d'intégration continue (CI / CD) pour identifier avant déploiement en production les vulnérabilités liées aux injections.

## Comment s'en prémunir

Prévenir l’injection exige de séparer les données non fiables des commandes et requêtes :

- la meilleure option est d’utiliser une API saine qui évite complètement l’utilisation de l’interpréteur ou fournit une interface paramétrable, ou bien de migrer pour utiliser les outils d'Object Relational Mapping Tools (ORMs).<br/>**Note** : Attention aux API, telles les procédures stockées, qui sont paramétrables, mais qui pourraient introduire une Injection SQL si PL/SQL ou T-SQL concatène requêtes et données ou exécute des données non saines avec EXECUTE IMMEDIATE ou exec() ;
- pour les données en entrée, une liste autorisée avec normalisation est recommandée, mais n’est pas une défense complète dans la mesure où de nombreuses applications requièrent des caractères spéciaux, par exemple les zones de texte ou les API pour les applications mobiles ;
- pour les requêtes dynamiques restantes, vous devriez soigneusement échapper les caractères spéciaux en utilisant la syntaxe d’échappement spécifique à l’interpréteur.<br/>**Note** : Les structures SQL telles que les noms de table, les noms de colonne, et d'autres ne peuvent pas être échappées et les noms de structures venant de l'utilisateur doivent donc être considérés comme dangereuses. Ceci est un problème courant dans les logiciels d'aide à l'écriture de rapports ;
- il est conseillé d'utiliser LIMIT et autres contrôles SQL à l'intérieur des requêtes pour empêcher les divulgations massives de données dans le cas d'injection SQL.

## Exemple de scénarios d'attaque

**Scenario #1** : L’application utilise des données non fiables dans la construction de l’appel SQL vulnérable suivant :
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Scenario #2** : De même, la confiance aveugle d'une application dans les frameworks qu'elle utilise peut faire que ses requêtes sont toujours vulnérables (par exemple Hibernate Query Language (HQL)) :
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Dans les deux cas, l'attaquant modifie le paramètre ‘id’ dans son navigateur en : ' UNION SELECT SLEEP(10);--. Par exemple :
```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Ceci change le sens de chacune des requêtes pour récupérer tous les enregistrements de la table des comptes. Dans le pire des cas, l’attaquant exploite cette faiblesse pour modifier ou détruire des données, ou appeler des procédures stockées de la base de données.

## Références

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Liste des CWEs associées

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
