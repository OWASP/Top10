# A4:2017 XML External Entities (XXE)

| Facteurs de menace/Vecteurs d'attaque | Vulnérabilités           | Impacts               |
| -- | -- | -- |
| Accessibilité : Exploitation 2 | Fréquence 2 : Détection 3 | Impact 3 : Sévère |
| L'attaquant peut exploiter des parseurs XML vulnérables s'ils peuvent uploader du XML ou inclure du contenu hostile dans un document XML, exploiter du code vulnérable, des dépendances ou des intégrations. | Par défaut, nombre de vieux parseurs XML permettent la spécification d'une entité externe, une URI est déréférencée et évaluée durant le parsage du XML. [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) ces outils peuvent découvrir ce problème en inspectant les dépendences et la configuration. [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) ces outils requièrent des étapes manuelles supplémentaires pour détecter et exploiter ce problème.
Des testeurs humains doivent être entrainées aux tests de type XXE, qui reste peu répandu en 2017.
 | Ces failles peuvent être utilisées pour extraire les données, exécuter une requête distante depuis le serveur, scanner des systèmes de fichiers internes, effectuer une attaque de type dénis de service, ainsi qu'exécuter d'autres attaques. |

## L'application est-elle vulnérable ?

Les applications, et en particulier les services web construits sur XML, ou des intégrations sous-jacentes peuvent être vulnérables si :

* L'applicatin accepte XML directement ou des fichiers en XML, en particulier depuis des sources non sûres, ou insert des données non échappées dans des documents XML, qui est ensuite analysé par le parseur XML.
* L'un des parseurs XML de l'application ou du services web SOAP dispose des [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) activés. Comme le méchnisme exact pour désactiver la compréhension des DTD varie par processeur, il convient de consulter une documentation de référence telle que [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Si l'application utilise SAML pour les services d'authentification ou à des fins d'authentification unique (SSO). SAML utilise XML pour modéliser les identités et peut être vunlérable.
* Si l'application utilise SOAP avant sa version 1.2, elle est fortement susceptible d'être vulnérable aux attaques XXS si les entités XML sont transmises au framework SOAP.
* Être vulnérable aux attaques XXS signifie que l'application est vunlérable aux attaques par dénis de service, y compris l'attaque dite du Billion Laughs.

## Comment s'en protéger

Entrainer les développeurs est essentiel pour identifier et réduire l'impact des XXS. S'en protéger requiert également :

* Quand c'est possible, utiliser des formats de données moins complexes, tels que JSON, et éviter de sérialiser des données sensibles.
* Patcher ou mettre à jour tous les parseurs XML et les librairies utilisées par l'application ou sur le système d'exploitation sous-jacent. Utiliser des vérificateurs de dépendances. Mettre à jour SOAP vers SOAP 1.2 ou plus récent.
* Désactiver le parsage des entités XML externes et du processing des DTD dans tous les parseurs XML de l'application, tel qu'indiqué dans la [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Implémenter une validatino des entrées côté serveur positive (liste blanche), du filtrage ou de la sanitization pour empêcher les donnés hostiles dans un document XML, des en-têtes, ou des noeuds.
* Vérifier que les fonctionnalités d'envoi de fichiers XML ou XSL valident le XML entrant en utilisant une validation XSD ou similaire.
* Les outils SAST peuvent aider détecter les XSS dans du code source, bien qu'une revue de code manuelle reste la meilleure alternative dans de larges et complexes applications avec beaucoup d'intégrations.

Si ces contrôles ne sont pas possibles, considérez utiliser du patching virtuel, des passerelles de sécurité pour API, ou des Web Application Firewall (WAFs) pour détecter, monitorer, et bloque des attaques XXE.

## Exemple de scénarios d'attaque

De nombreuses problématiques XXS ont été découvertes, y compris l'attaque de périphériques embarqués. XXE est présent dans de nombeux endroits inattendus, comme dans des dépendances très lontaines. La façon la plus facile est de soumettre en fichier XML malveillant, si accepté :

**Scenario #1**: L'attaquant tente d'extraire des données depuis le serveur :

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Scenario #2**: L'attaquant accède au réseau privé du serveur en changeant la ligne ENTITY précédente par:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Scenario #3**: L'attaquant tente un une attaque de type déni de service en incluant un fichier potentiellement infini :

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Références

### OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### External

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
