# A3:2017 Exposition de données sensibles

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilité | Impacts Techniques |
| -- | -- | -- |
| Niveau d'accès : Exploitation 2 | Fréquence 3 : Détection 2 | Impact 3 : Métier |
| La cryptanalyse (cassage de l’algorithme ou de la clé) reste rare. On préfère obtenir les clefs, effectuer des attaques du type man-in-the-middle, accéder aux données en clair sur le serveur, en transit, ou depuis le client de l'utilisateur, par exemple le navigateur. Une attaque manuelle est requise dans la majorité des cas. Des bases de données de mots de passe précédemment récupérées peuvent étre brute forcées par des processeurs graphiques (GPU). | Au cours des dernières années, cela a été l'attaque impactante la plus courante. La principale erreur est de ne pas chiffrer les données sensibles. Les autres erreurs fréquentes sont: génération de clés faibles, choix et configuration incorrects des algorithmes et protection insuffisante des mots de passe. En ce qui concerne les données en transit, les faiblesses côté serveur sont pour la plupart faciles à détecter. C'est plus difficile pour les données déjà stockées. | L’exploitation peut résulter en la compromission ou la perte de données personnelles, médicales, financières, d’éléments de cartes de crédit ou d’authentification. Ces données nécessitent souvent une protection telle que définie par le Règlement Général sur la Protection des Données ou les lois locales sur la vie privée. |

## Suis-je vulnérable ?

Déterminer d’abord quelles données doivent bénéficier d’une protection chiffrée (mots de passe, données patient, numéros de cartes, données personnelles, etc.), lors de leur transfert et/ou leur stockage. Pour chacune de ces données :

* Les données circulent-elles en clair ? Ceci concerne les protocoles tels que HTTP, SMTP, et FTP. Le trafic externe sur inernet est particulièrement dangereux. Vérifiez tout le réseau interne, par exemple entre les équilibreurs de charge, les serveurs Web, ou les systèmes backend.
* Des algorithmes faibles ou désuets sont-ils utilisés, soit par défaut, soit dans le code source existant ?
* Est-ce que des clefs de chiffrement par défaut sont utilisées ? Des clefs de chiffrement faibles sont-elles générées ou réutilisées ? Leur gestion et rotation sont-elles prises en charge?
* Les réponses transmises au navigateur incluent-elles les directives/en-têtes de sécurité adéquats ?
* Est-ce que l'agent utilisateur (l'application ou le client mail, par exemple) vérifie que le certificat envoyé par le serveur est valide ?

Pour une liste complète de contrôles, se référer à l’ASVS : [Crypto (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [Data Protection (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection) et [SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications).

## Comment s'en prémunir ?

On veillera au minimum à suivre les recommandations suivantes, mais il reste nécessaire de consulter les références.

* Classifier les données traitées, stockées ou transmises par l'application. Identifier quelles données sont sensibles selon les lois concernant la protection de la vie privée, les exigances réglementaires, ou les besoins métier.
* Appliquer des contrôles selon la classification.
* Ne pas stocker de données sensibles sans que cela ne soit nécessaire. Les rejeter ou utiliser une tokenisation conforme à la norme de sécurité de l’industrie des cartes de paiement (PCI DSS) ou même une troncature. Les données que l’on ne possède pas ne peuvent être volées!
* S'assurer de chiffrer toutes les données sensibles au repos.
* Choisir des algorithmes éprouvés et générer des clés robustes. S'assurer qu'une gestion des clés est en place.
* Chiffrer toutes les données transmises avec des protocoles sécurisés tels que TLS avec des chiffres à confidentialité persistante (perfect forward secrecy - PFS). Chiffrer en priorité sur le serveur. Utiliser des paramètres sécurisés. Forcer le chiffrement en utilisant des directives comme HTTP Strict Transport Security (HSTS).
* Désactiver le cache pour les réponses contenant des données sensibles.
* Stocker les mots de passe au moyen de puissantes fonctions de hachage adaptatives, avec sel et facteur de travail (ou facteur de retard), comme [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) ou [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Vérifier indépendamment l'efficacité de la configuration et des paramètres.

## Exemples de scénarios d'attaque

**Scenario #1**: Une application chiffre des numéros de cartes de crédit dans une base de données utilisant un chiffrement en base automatique. Cependant, ces données sont automatiquement déchiffrées lorsqu'elles sont récupérées, permettant, à une injection SQL de récupérer des numéros de carte de crédit en clair. 

**Scenario #2**: Un site n'utilise pas ou ne force pas l'utilisation de TLS sur toutes les pages, ou supporte des protocoles de chiffrement faibles. Un attaquant surveille le trafic réseau (par exemple sur un réseau sans fil non sécurisé), dégrade les connexions de HTTPS à HTTP, intercepte les requêtes, et vole le cookie de session d'un utilisateur. L'attaquant réutilise alors ce cookie et détourne la session de l'utilisateur (authentifié), pouvant ainsi accéder aux données privées de l'utilisateur ou les modifier. Un attaquant pourrait également modifier toutes les données en transit, par exemple le destinataire d'un virement d'argent.

  **Scenario #3**: La base de données contenant les mots de passe n'utilise pas de sel, ou alors de simples hashs pour stocker les mots de passe de chacun. Une faille d'upload de fichier permet à un attaquant de récupérer la base de données de mots de passe. Tous les hashs non salés peuvent alors être révélés avec une rainbow table de hashs pré-calculés. Des hashs générés par des fonctions de hachage simples ou rapides peuvent être décrytés par des GPUs, même salés.

## Références

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) and [Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Externe

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
