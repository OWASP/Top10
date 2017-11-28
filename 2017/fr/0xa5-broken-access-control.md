# A5:2017 Broken Access Control

| Facteurs de menace/Vecteurs d'attaque | Vulnérabilité  | Impacts |
| -- | -- | -- |
| Niveau d'accès : Exploitation 2 | Fréquence 2 : Détection 2 | Impact 3 : Métier |
| L'exploitation des contrôles d'accès est une des principales compétences des attaquants. Les outils [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) and [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) peuvent détecter l'absence de contrôles d'accès mais ne peuvent vérifier s'ils sont efficaces quand ils existent. Les contrôles d'accès peuvent être détectés par des tests manuels, leur absence peut être détectée par des contrôles automatiques dans certains frameworks. | Les vulnérabilités de contrôles d'accès surviennent souvent par le manque de détection automatique, et le manque de tests fonctionnels effectifs par les développeurs d'applications. La detection des contrôles d'accès ne se prête pas bien aux tests statiques ou dynamiques. Les tests manuels sont la meilleure méthode de détecter des contrôles d'accès manquant ou défectueux, Ceci inclut mes méthodes HTTP (GET vs PUT, etc), les contrôleurs, les références directes d'objets, etc. | Techniquement parlant, l'impact est qu'un attaquant peut obtenir les droits d'un utilisateur ou d'un administrateur, ou qu'un utilisateur obtienne des droits privilégiés ou qu'il puisse créer, lire ou supprimer tout enregistrement de son choix. L'impact métier est dépendant du niveau de protection nécessité par l'application et ses données. |

## Suis-je vulnérable ?

Les contrôles d'accès appliquent une politique assurant que les utilisateurs respectent leurs permissions. Une faille entraînera généralement des fuites d'informations, des corruptions ou destructions de données, ou permettra des actions en dehors des autorisations de l'utilisateur. Les vulnérabilités de contrôle d'accès consistent généralement :

* A contourner les contrôles d'accès en modifiant l'URL, l'état interne de l'application, ou la page HTML ; ou simplement en utilisant un outil dédié d'attaque d'API.
* A permettre la modification de la clef primaire pour pointer sur l'enregistrement d'un autre utilisateur, donnant ainsi la possibilité de voir ou modifier le compte de quelqu'un d'autre.
* A permettre une élévation de privilège, c'est à dire permettre d'agir comme un utilisateur connecté, ou comme administrateur alors que l'on est connecté comme utilisateur.
* A permettre les manipulations de meta-données, comme le rejeu ou la modification de JSON Web Token (JWT), de cookies ou de champs cachés, afin d'élever les privilèges, ou d'abuser les invalidation JWT.
* A permettre l'accès non-autorisé à des API, par mauvaise configuration CORS.
* A permettre la navigation forcée vers des pages soumises à authentification sans être authentifié, ou à des pages soumise à accès privilégié en étant connecté comme simple utilisateurs. A permettre l'accès à des API sans contrôle pour POST, PUT et DELETE.

## Comment s'en prémunir ?

Les contrôles d'accès ne sont efficaces que s'ils sont appliqués dans du code de confiance côté serveur ou dans des API server-less, là ou un attaquant ne peut pas modifier les vérifications des contrôles ni les meta-données.

* A l'exception des ressources publiques, tout doit être bloqué par défaut.
* Centraliser l'implémentation des mécanismes de contrôle d'accès et les réutiliser dans l'ensemble de l'application. Cela comprend de minimiser l'utilisation de CORS.
* Le modèle de contrôle d'accès doit vérifier l'appartenance des enregistrements, plutôt que de permettre à l'utilisateur de créer, lire, modifier ou supprimer n'importe quel enregistrement.
* Les exigences spécifiques métier de l'application doivent être appliquées par domaines.
* Désactiver le listing de dossier sur le serveur web, et vérifier que les fichier de meta-données (ex: .git) et de sauvegardes ne se trouvent pas dans l'arborescence web.
* Tracer les échecs de contrôles d'accès, les alertes administrateur quand c'est approprié (ex: échecs répétés).
* Limiter la fréquence d'accès aux API et aux contrôleurs d'accès, afin de minimiser les dégats que causeraient des outils d'attaques automatisés.
* Les jetons JWT doivent être invalidés côté serveur après une déconnexion.
* Les développeurs et les testeurs qualité doivent procéder à des tests unitaires et d'intégration sur les fonctionnalités de contrôle d'accès.

## Exemple de scénarii d'attaque

**Scénario #1**: L'application utilise des données non vérifiées dans un appel SQL qui accède aux informations d'un compte :

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

En modifiant simplement le paramètre 'acct' dans le navigateur, un attaquant peut envoyer le numéro de compte qu'il veut. Si ce numéro n'est pas vérifié, l'attaquant peut accéder à n'importe quel compte utilisateur.

`http://example.com/app/accountInfo?acct=notmyacct`

**Scénario #2**: Un attaquant force le navigateur à visiter des URLs arbitraires. Il faut imposer des droits pour accéder à une page d'administration.

```
  http://example.com/app/getappInfo
  http://example.com/app/admin_getappInfo
```

Si un utilisateur non-authentifié peut accéder à l'une des pages, c'est une faille. Si un non-administrateur peut accéder à une page d'administration, c'est une faille.

## Références

### OWASP

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Authorization Testing](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Externes

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
