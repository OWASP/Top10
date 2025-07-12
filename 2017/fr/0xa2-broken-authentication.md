# A2:2017 Authentification de mauvaise qualité

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilité    | Impacts  |
| -- | -- | -- |
| Accès  Lvl : Exploitabilité 3 | Fréquence 2 : Détection 2 | Technique 3 : Métier |
| Les attaquants ont des accès à des centaines de millions de combinaisons de logins et mots de passe, des comptes par défaut d’administration, d’outils de force brute automatisés. Les attaques de gestion de session sont bien connues, en particulier en ce qui concerne les jetons de sessions non expirés. |
Le prévalence de la violation de l’authentification est généralement liée à une erreur de conception ou de mise en œuvre dans la plupart des contrôles d’identités et d’accès. La gestion des sessions est la base  de l’authentification et du contrôle d’accès. Les attaquants peuvent détecter une violation de l’authentification avec des tests manuels et les exploiter avec des outils automatisés utilisant des listes de mots de passe et des attaques par dictionnaires. | Les attaquants doivent avoir accès à seulement quelques comptes ou à un seul compte admin pour compromettre le système. Selon le domaine de l'application, cela peut permettre le blanchiment d'argent, une fraude à la sécurité sociale et le vol d'identité, ou divulguer des informations hautement sensibles protégées par la loi. |

## Suis-je vulnérable ? 

La confirmation de l'identité, de l'authentification et de la session de l'utilisateur est essentielle pour se protéger des attaques liées à l'authentification. 

Il peut y avoir des faiblesses d'authentification si l'application :

* Autorise les attaques automatisées telles que le [credential stuffing](https://wiki.owasp.org/index.php/Credential_stuffing), où l'attaquant dispose d'une liste de noms d'utilisateurs valides et mots de passe.
* Permet la force brute ou d'autres attaques automatisées
* Autorise les mots de passe par défaut, faibles ou bien connus, tels que "Password1" ou "admin / admin".
* Utilise des processus de récupération des informations d'identification faibles ou inefficaces et des processus de mot de passe oublié, tels que « "Questions secrètes" », qui ne peuvent être sécurisées.
* Utilise des mots de passe en texte brut, chiffrés ou faiblement hachés (voir A3 : Exposition de données sensibles 2017).
* Absence ou utilisation inefficace de l’authentification multi-facteur.
* Exposition des ID de session dans l'URL. (ex : réécriture)
* Non rotation des ID de session après une connexion réussie
* N'invalide pas correctement les ID de session. Les sessions utilisateurs ou les jetons d'authentification (en particulier les jetons SSO) ne sont pas correctement invalidés lors de la déconnexion ou après une période d'inactivité.

## Comment protéger l'application ? 

* Lorsque cela est possible, implémentez l'authentification multifacteur pour éviter les attaques automatisées, le bourrage des informations d'identification, le brute force et la réutilisation des informations d'identification volées.
* Ne pas livrer ou déployer avec des informations d'identification par défaut, en particulier pour les utilisateurs avec privilèges.
* Intégrer des tests de mots de passes faibles, à la création ou au changement. Comparer ce mot de passe avec la liste des [tops 10000 mots de passe faibles](https://github.com/danielmiessler/SecLists/tree/master/Passwords).  
* Respecter la longueur, la complexité et la rotation des mots de passe par rapport aux directives [NIST 800-63 B à la section 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) 
NIST 800-63 B à la section 5.1.1 ou autre directives modernes
* Assurez-vous que l'inscription, la récupération des informations d'identification et les chemins d'accès aux API sont durcis contre les attaques d'énumération de compte en utilisant le même message pour tous les résultats
* Limiter ou retarder de plus en plus les tentatives de connexions infructueuses. Enregistrer tous les échecs et alerter les administrateurs lors du bourrage des informations d'identification, de brute force ou d'autres attaques détectées.
 * Utilisez un gestionnaire de session intégré et sécurisé côté serveur qui génère un nouvel ID de session aléatoire avec une entropie élevée après la connexion. Les ID de session ne doivent pas se trouver dans l'URL, ils doivent être stockés de manière sécurisée et être invalidés après la déconnexion, une inactivité et une certaine durée. 
 
## Exemples de scenarios d'attaques

**Scénario #1** : La réutilisation de mots de passe, l’utilisation de mots de passe connus, est une attaque classique. Si une application n’implémente une protection automatisée contre le [bourrage d'informations](https://wiki.owasp.org/index.php/Credential_stuffing), ou l'utilisation des [mots de passe connus](https://github.com/danielmiessler/SecLists).

**Scénario #2** : La plupart des attaques d’authentification se produisent en raison de l’utilisation de mots de passe comme facteur unique. Une fois considéré, les exigences de rotation et de complexité des mots de passe, sont considérées comme encourageant les utilisateurs à utiliser et réutiliser des mots de passe faibles. Il est maintenant recommandé d’arrèter ces pratiques NIST 800-63 et d’utiliser du multifacteur.

**Scénario #3** : Les timeouts de session d’application ne sont pas paramétrés correctement. Un utilisateur utilise un ordinateur public pour accéder à une application. A la place de se déconnecter correctement, l’utilisateur ferme le navigateur et quitte l’ordinateur. Un attaquant utilise ensuite le même navigateur quelques temps après et l’utilisateur est toujours authentifié. 

## References

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://wiki.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://wiki.owasp.org/index.php/Testing_Identity_Management)
 and [Authentication](https://wiki.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://wiki.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://wiki.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://wiki.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://wiki.owasp.org/index.php/Session_Management_Cheat_Sheet)
* [OWASP Automated Threats Handbook](https://wiki.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Externes

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - for thorough, modern, evidence-based advice on authentication. 
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
