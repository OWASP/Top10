# A4:2017 XML Entités externes (XXE)

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilité | Impacts  |
| -- | -- | -- |
| Niveau d'accès : Exploitation 2 | Fréquence 2 : Détection 2 | Technique 3 : Métier |
| Des attaquants peuvent exploiter des processeurs XML vulnérables s'ils peuvent télécharger du XML ou inclure du contenu hostile dans un document XML, en exploitant du code vulnérable, des dépendances ou des intégrations. | Par défaut, de nombreux anciens processeurs XML permettent de spécifier une entité externe : une URI déréférencée et évaluée lors du traitement XML. Les outils [SAST](https://owasp.org/www-community/Source_Code_Analysis_Tools) peuvent découvrir ces problèmes en inspectant les dépendances et la configuration. Les outils [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) nécessitent des étapes manuelles supplémentaires pour détecter et exploiter ces problèmes. Des testeurs doivent être formés à la façon manuelle de tester les XXE, car elles n'étaient pas couramment testées en 2017. | Ces failles peuvent être utilisées pour extraire des données, exécuter une requête à distance sur un serveur, découvrir des systèmes internes, lancer des attaques par déni de service ou même exécuter d'autres attaques. |

## L'application est-elle vulnérable?

Des applications et en particulier les services Web basés sur XML ou les intégrations en aval peuvent être vulnérables aux attaques si :


* L'application accepte directement du XML ou les uploads XML, en particulier ceux provenant de sources non fiables, ou injecte des données non fiables dans des documents XML, qui sont ensuite analysés par un processeur XML.
* N'importe quels moteur XML d'une application ou des services Web basés sur SOAP à un [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) activé. Comme le mécanisme exact de désactivation du traitement de DTD varie selon le moteur, il est recommandé de consulter une référence telle que la [OWASP Cheat Sheet 'XXE Prevention'](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).
* Si l'application utilise SAML pour le traitement de l'identité à des fins de sécurité fédérée ou d'authentification unique. SAML utilise XML pour les assertions d'identité et peut être vulnérable.
* Si l'application utilise SOAP avant la version 1.2, il est probable que des attaques XXE se produisent si des entités XML sont transmises à la structure SOAP.
* Être vulnérable aux attaques XXE signifie probablement que l'application est vulnérable aux attaques par déni de service, y compris l'attaque Billion Laughs.

## Comment empêcher

La formation des développeurs est essentielle pour identifier et atténuer les XXE. De plus, prévenir des XXE nécessite :

* Autant que possible, utiliser des formats de données moins complexes tels que JSON et éviter la sérialisation des données sensibles.
* Corriger ou mettre à niveau tous les moteurs et bibliothèques XML utilisés par l'application ou sur le système d'exploitation sous-jacent. Utiliser des vérificateurs de dépendance. Mettre à jour SOAP vers SOAP 1.2 ou supérieur.
* Désactiver le traitement des entités externes XML et des DTD dans tous les moteur XML de l’application, [OWASP Cheat Sheet 'XXE Prevention'](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).
* Implémenter une validation, un filtrage ou une désinfection des entrées côté serveur positives ("liste blanche") pour empêcher les données hostiles dans les documents XML, les en-têtes ou les nœuds.
* Vérifier que la fonctionnalité de téléchargement de fichier XML ou XSL valide le XML entrant à l'aide de la validation XSD ou similaire.
* Les outils SAST peuvent aider à détecter XXE dans le code source, bien que la relecture manuelle du code soit la meilleure alternative dans les applications volumineuses et complexes comportant de nombreuses intégrations.
Si ces contrôles sont impossibles, envisagez d'utiliser des correctifs virtuels, des passerelles de sécurité d'API ou des pare-feu d'applications Web (WAF) pour détecter, surveiller et bloquer les attaques XXE.

## Exemple de scénarios d'attaque

De nombreux problèmes XXE ont été rendu public, notamment des attaques sur des périphériques intégrés. XXE se produit dans de nombreux endroits inattendus, y compris des dépendances profondément imbriquées. Le moyen le plus simple est d'uploader un fichier XML illicite, s’il est accepté :

**Scenario #1** : L'attaquant tente d'extraire des données du serveur :


```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```


**Scenario #2** : Un attaquant scan le réseau privé du serveur en modifiant la ligne ENTITY ci-dessous en :

```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```


**Scenario #3** : Un attaquant tente une attaque par déni de service en incluant un fichier potentiellement sans fin :


```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Références

### OWASP

* [OWASP Application Security Verification Standard](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [OWASP Testing Guide: Testing for XML Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
* [OWASP XXE Vulnerability](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: XML Security](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)

### Externes

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
