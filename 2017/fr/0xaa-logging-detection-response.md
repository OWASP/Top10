# A10:2017 Supervision et Journalisation Insuffisantes

| Facteurs de Menace/Vecteurs d'Attaque | Vulnérabilités           | Impacts               |
| -- | -- | -- |
| Accès Lvl : Exploitation 2 | Fréquence 3 : Détection 1 | Techniques 2 : Métier  |
| L’exploitation  des insuffisances de supervision et de journalisation sont à la base de presque tous les incidents majeurs. Les carences dans la supervision et la gestion de réactions, rapides et adéquates, permettent aux attaquants de réaliser leurs objectifs sans être détectés.| Ce problème a été intégré dans le Top 10 suite à l’enquête auprès d’un panel d’entreprises (voir [enquête industrie](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html)). Une des méthodes pour s’assurer que vous avez une journalisation suffisante est de contrôler les journaux après un test d’intrusion. La journalisation des actions du testeur doit permettre de comprendre quels dommages ont été faits.| La plupart des attaques réussies commencent par des tests de vulnérabilités. Laisser faire de tels tests en continu conduira à une exploitation réussie avec une probabilité proche de 100%. En 2016, reconnaître une attaque prenait [en moyenne 191 jours](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&), ce qui laisse beaucoup de temps pour faire des dégâts. |

## Suis-je Vulnérable ?

L'insuffisance de journalisation, de détection, de supervision et de réaction aux incidents est avérée si :
* Les traces d’audit, telles que les accès réussis ou échoués et les transactions sensibles, ne sont pas enregistrées.
* Les alertes et les erreurs générées ne sont pas enregistrées, ou leur journalisation est inadéquate, ou imprécise.
* Les journaux des applications et des API ne sont pas contrôlés pour détecter les actions suspectes.
* Les journaux ne sont stockés que localement.
* Aucun processus de seuil d’alerte convenable ni de remontées d'information pour y répondre n'ont été définis, ou ils sont inadéquats, ou inefficaces.
* Les tests d'intrusion et de balayage avec des outils [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) (tels que [OWASP ZAP](https://owasp.org/www-project-zap/)) ne génèrent pas d'alertes.
* L’application est incapable de détecter, de générer des remontées d'information et des alertes en temps réel, ou assimilé, en cas d’attaque active.

Vous êtes vulnérable à une fuite d’information si les enregistrements de journalisation et d’alertes sont accessibles à vos utilisateurs ou attaquants (voir A3:2017-Exposition de Données Sensibles).

## Comment s'en Prémunir ?

Conformément aux risques évalués sur les données stockées ou gérées par l'application :
* S'assurer que toutes les authentifications, les erreurs de contrôle d'accès et de contrôle des entrées côté serveur sont enregistrées, avec un contexte utilisateur suffisant pour identifier les comptes suspects ou malveillants, et conservées suffisamment longtemps pour permettre une analyse légale différée.
* S'assurer que les enregistrements des journaux sont dans un format standard pour permettre de les intégrer facilement à une solution de gestion de logs centralisée.
* S'assurer que les transactions à haute valeur ajoutée ont une piste d'audit, avec un contrôle d'intégrité, pour éviter la modification ou la suppression, comme des tables de bases de données en ajout seul ou équivalent.
* Mettre en place une supervision et une gestion d'alertes efficaces pour détecter et réagir aux actions suspectes en temps opportun.
* Définir ou adopter un plan de réaction et de reprise sur incident, comme celui du [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) ou ultérieur.

On trouve des logiciels, commerciaux ou open source, de protection d'applications tel que [OWASP AppSensor](https://owasp.org/www-project-appsensor/), de pare-feux d'application web (WAF) tel que [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/) et de logiciels de corrélation de journaux avec des tableaux de bord et d'alertes configurables. 

## Exemples de Scénarios d'Attaque

**Scénario #1** : Un forum, pour un projet de développement open source d’une petite équipe, a été piraté à cause d’une faille logicielle. Les attaquants ont effacé le dépôt du code source de la future version et tout le contenu du forum. Bien que le code ait pu être récupéré, le manque de supervision, de journalisation et d’alertes ont conduit à une atteinte bien plus grave. Le résultat étant que le projet a été arrêté.  

**Scénario #2** : Un attaquant teste des accès utilisateurs avec un mot de passe commun. Il pourra accéder à tous les comptes ayant ce mot de passe. Pour tous les autres utilisateurs, ce test ne laisse qu'une trace de tentative d'accès échoué. Quelques jours après, ce test peut être réalisé avec un autre mot de passe.  

**Scénario #3** : Un grand distributeur américain a rapporté qu'une sandbox d’analyse de malware de fichiers attachés, aurait détecté un logiciel suspect, mais que personne n'a réagi à cette détection. Il y a eu plusieurs alertes avant que la brèche ne soit découverte par une banque externe à cause d'une transaction par carte frauduleuse.

## Références

### OWASP
* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

### Externes
* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
