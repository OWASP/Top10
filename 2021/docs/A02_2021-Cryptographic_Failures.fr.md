# A02:2021 – Défaillances cryptographiques    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       29       |       46,44 %        |         4,49 %         |             7,29              |         6,81         |    79,33 %     |      34,85 %       |          233 788           |        3 075         |

## Aperçu

En deuxième position, en progression d'une place. Auparavant connu sous le nom d'*Exposition de données sensibles*, qui est plus un symptôme générique qu'une cause racine. L'accent est mis sur les défaillances liées à la cryptographie (ou son absence). Cela entraîne souvent l'exposition de données sensibles. Les *Common Weakness Enumerations* (CWE) notables incluses sont *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky Crypto Algorithm*, et *CWE-331 Insufficient Entropy*.

## Description 

Déterminer d’abord quelles données doivent bénéficier d’une protection chiffrée (mots de passe, données patients, numéros de cartes, données personnelles, etc.), lors de leur transfert ou leur stockage. Pour chacune de ces données :

- Les données circulent-elles en clair ? Ceci concerne les protocoles tels que HTTP, SMTP et FTP. Le trafic externe sur internet est particulièrement dangereux. Vérifiez tout le réseau interne, par exemple entre les équilibreurs de charge, les serveurs Web ou les systèmes backend.
- Des algorithmes faibles ou désuets sont-ils utilisés, soit par défaut, soit dans le code source existant ?
- Est-ce que des clefs de chiffrement par défaut sont utilisées ? Des clefs de chiffrement faibles sont-elles générées ou réutilisées ? Leur gestion et rotation sont-elles prises en charge ? Est-ce que des clés sont présentes dans l'outil de versionnement de code source ?
- Les réponses transmises au navigateur incluent-elles les directives/en-têtes de sécurité adéquats ?
- Est-ce que le certificat serveur reçu et la chaîne de confiance sont correctement validés ?
- Est-ce que les vecteurs d'initialisation sont ignorés, réutilisés ou générés avec une sécurité insuffisante pour le mode d'opération cryptographique ?
- Est-ce que les mots de passe sont utilisés sans fonction de dérivation de clé ?
- Est-ce que la fonction de génération aléatoire utilisée a été conçue pour répondre aux exigences cryptographiques ? Même si la bonne fonction est utilisée, est-ce que la graine aléatoire doit être fournie par le développeur, et sinon, le développeur a-t-il réécrit la fonction robuste embarquée de génération de graine par une graine aléatoire qui manque d'entropie ou d'imprévisibilité ?
- Est-ce que des fonctions de hachage dépréciées telles que MD5 ou SHA1 sont utilisées ou est-ce que des fonctions de hachage non cryptographiques sont utilisées là où des fonctions de hachage cryptographiques sont nécessaires ?
- Est-ce que des méthodes cryptographiques de remplissage dépréciées, comme PKCS 1 v1.5 sont utilisées ?
- Est-ce que des messages d'erreurs cryptographiques ou des informations par canal auxiliaire sont exploitables, par exemple sous la forme d'attaque par oracle de remplissage ?

Se référer à l'*ASVS* *Crypto* (V7), *Data Protection* (V9), et *SSL/TLS* (V10).

## Comment s'en prémunir

On veillera au minimum à suivre les recommandations suivantes, mais il reste nécessaire de consulter les références.

- Classifier les données traitées, stockées ou transmises par l'application. Identifier quelles données sont sensibles selon les lois concernant la protection de la vie privée, les exigences réglementaires ou les besoins métier.
- Ne pas stocker de données sensibles sans que cela ne soit nécessaire. Les rejeter ou utiliser une tokenisation conforme à la norme de sécurité de l’industrie des cartes de paiement (PCI DSS) ou même une troncature. Les données que l’on ne possède pas ne peuvent être volées.
- S'assurer de chiffrer toutes les données sensibles au repos.
- Choisir des algorithmes éprouvés et générer des clés robustes. S'assurer qu'une gestion des clés est en place.
- Chiffrer toutes les données transmises avec des protocoles sécurisés tels que TLS avec des chiffres à confidentialité persistante (forward secrecy - FS). Chiffrer en priorité sur le serveur. Utiliser des paramètres sécurisés. Forcer le chiffrement en utilisant des directives comme HTTP Strict Transport Security (HSTS).
- Désactiver le cache pour les réponses contenant des données sensibles.
- Appliquer les contrôles de sécurité requis selon la classification de la donnée.
- Ne pas utiliser de vieux protocoles tels que FTP et SMTP pour échanger des données sensibles.
- Stocker les mots de passe en utilisant des fonctions de hachage avec salage et facteur de travail (facteur de délai), telles que Argon2, scrypt, bcrypt ou PBKDF2.
- Les vecteurs d'initialisation doivent être choisis de façon appropriée au mode d'opération. Pour la plupart des modes, cela signifie utiliser un générateur de nombres pseudo-aléatoires cryptographiquement sécurisé (CSPRNG en anglais). Pour les modes requérant un nonce, alors le vecteur d'initialisation (VI) ne nécessite pas un CSPRNG. Dans tous les cas, un vecteur d'initialisation ne devrait pas être utilisé deux fois pour une clé fixe.
- Utiliser toujours un chiffrement authentifié plutôt qu'un chiffrement simple
- Les clés devraient toujours être générées de façon cryptographiquement aléatoire et stockées en mémoire sous la forme de tableau d'octets. Si un mot de passe est utilisée, alors il faut obligatoirement le transformer en clé via une fonction de dérivation de clé appropriée.
- S'assurer qu'une génération cryptographiquement aléatoire est utilisée là où c'est approprié, et qu'elle n'a pas une graine aléatoire prévisible ou avec une faible entropie. La plupart des APIs modernes ne demandent pas au développeur de fournir une graine au CSPRNG pour être sécurisé.
- Ne pas utiliser de fonctions cryptographiques et de méthodes de remplissage dépréciées telles que MD5, SHA1, PKCS 1 v1.5.
- Vérifier indépendamment l'efficacité de la configuration et des paramètres.

## Exemple de scénarios d'attaque

**Scénario 1** : Une application chiffre des numéros de cartes de crédit dans une base de données utilisant un chiffrement en base automatique. Cependant, ces données sont automatiquement déchiffrées lorsqu'elles sont récupérées, permettant, à une injection SQL de récupérer des numéros de carte de crédit en clair.

**Scénario 2** : Un site n'utilise pas ou ne force pas l'utilisation de TLS sur toutes les pages ou supporte des protocoles de chiffrement faibles. Un attaquant surveille le trafic réseau (par exemple sur un réseau sans fil non sécurisé), dégrade les connexions de HTTPS à HTTP, intercepte les requêtes et vole le cookie de session d'un utilisateur. L'attaquant réutilise alors ce cookie et détourne la session de l'utilisateur (authentifié), pouvant ainsi accéder aux données privées de l'utilisateur ou les modifier. Un attaquant pourrait également modifier toutes les données en transit, par exemple le destinataire d'un virement d'argent.

**Scénario 3** : La base de données contenant les mots de passe n'utilise pas de sel, ou alors de simples hachés pour stocker les mots de passe de chacun. Une faille d'upload de fichier permet à un attaquant de récupérer la base de données de mots de passe. Tous les hachés non salés peuvent alors être révélés avec une rainbow table de hachés pré-calculés. Des hachés générés par des fonctions de hachage simples ou rapides peuvent être déchiffrés par des GPUs, même salés.

## Références

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)


## Liste des CWEs associées

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
