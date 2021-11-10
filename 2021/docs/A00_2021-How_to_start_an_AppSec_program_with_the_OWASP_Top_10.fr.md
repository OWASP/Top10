# Comment démarrer un programme de sécurité des applications (SecApp) avec l'OWASP Top 10

Auparavant, l'OWASP Top 10 n'avait jamais été conçu pour servir de base à un programme SecApp. Cependant, il est essentiel de commencer quelque part pour de nombreuses organisations qui commencent tout juste leur parcours en matière de sécurité des applications. Le Top 10 OWASP 2021 est un bon début en tant que référence pour les listes de contrôle, etc., mais il n'est pas suffisant en soi.

## Étape 1. Identifiez les lacunes et les objectifs de votre programme de sécurité des applications

De nombreux programmes de sécurité des applications (SecApp) essaient de courir avant de savoir marcher. Ces efforts sont voués à l'échec. Nous encourageons fortement les RSSI et les dirigeants SecApp à utiliser l'[OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) pour identifier les faiblesses et les domaines à améliorer sur une période de 1 à 3 ans. La première étape consiste à évaluer où vous en êtes maintenant, à identifier les lacunes en matière de gouvernance, de conception, de mise en œuvre, de vérification et d'opérations que vous devez résoudre immédiatement par rapport à celles qui peuvent attendre, et de prioriser la mise en œuvre ou l'amélioration des quinze pratiques de sécurité OWASP SAMM. OWASP SAMM peut vous aider à créer et à mesurer des améliorations dans vos efforts d'assurance logicielle.

## Étape 2. Planifier un cycle de vie de développement sécurisé pour une voie pavée

Traditionnellement l'apanage des soi-disant "licornes", le concept de voie pavée est le moyen le plus simple d'avoir le plus d'impact et de faire évoluer les ressources SecApp avec la vélocité de l'équipe de développement, qui n'augmente que chaque année.

Le concept de voie pavée est "le moyen le plus simple est aussi le moyen le plus sûr" et devrait impliquer une culture de partenariats profonds entre l'équipe de développement et l'équipe de sécurité, de préférence de telle sorte qu'ils forment une seule et même équipe. La voie pavée vise à améliorer, mesurer, détecter et remplacer en permanence les alternatives non sécurisées en disposant d'une bibliothèque de remplacements sécurisés à l'échelle de l'entreprise, avec des outils pour aider à voir où des améliorations peuvent être apportées en adoptant la voie pavée. Cela permet aux outils de développement existants de signaler les versions non sécurisées et d'aider les équipes de développement à se corriger elles-mêmes des alternatives non sécurisées.

La voie pavée peut sembler beaucoup de choses à digérer, mais elle devrait être construite progressivement au fil du temps. Il existe d'autres formes de programmes SecApp, notamment le cycle de vie du développement de la sécurité de Microsoft. Toutes les méthodologies de programme SecApp ne conviennent pas à toutes les entreprises.

## Stage 3. Implement the paved road with your development teams

Paved roads are built with the consent and direct involvement of the
relevant development and operations teams. The paved road should be
aligned strategically with the business and help deliver more secure
applications faster. Developing the paved road should be a holistic
exercise covering the entire enterprise or application ecosystem, not a
per-app band-aid, as in the old days.

## Stage 4. Migrate all upcoming and existing applications to the paved road

Add paved road detection tools as you develop them and provide
information to development teams to improve the security of their
applications by how they can directly adopt elements of the paved road.
Once an aspect of the paved road has been adopted, organizations should
implement continuous integration checks that inspect existing code and
check-ins that use prohibited alternatives and warn or reject the build
or check-in. This prevents insecure options from creeping into code over
time, preventing technical debt and a defective insecure application.
Such warnings should link to the secure alternative, so the development
team is given the correct answer immediately. They can refactor and
adopt the paved road component quickly.

## Stage 5. Test that the paved road has mitigated the issues found in the OWASP Top 10

Paved road components should address a significant issue with the OWASP
Top 10, for example, how to automatically detect or fix vulnerable
components, or a static code analysis IDE plugin to detect injections or
even better start using a library that is known safe against injection.
The more of these secure drop-in replacements provided to teams, the better.
A vital task of the appsec team is to ensure that the security of these
components is continuously evaluated and improved.
Once they are improved, some form of communication pathway with
consumers of the component should indicate that an upgrade should occur,
preferably automatically, but if not, as least highlighted on a
dashboard or similar.

## Stage 6. Build your program into a mature AppSec program

You must not stop at the OWASP Top 10. It only covers 10 risk
categories. We strongly encourage organizations to adopt the Application
Security Verification Standard and progressively add paved road
components and tests for Level 1, 2, and 3, depending on the developed
applications' risk level.

## Going beyond

All great AppSec programs go beyond the bare minimum. Everyone must keep
going if we're ever going to get on top of appsec vulnerabilities.

-   **Conceptual integrity**. Mature AppSec programs must contain some
    concept of security architecture, whether a formal cloud or
    enterprise security architecture or threat modeling

-   **Automation and scale**. Mature AppSec programs try to automate as
    much of their deliverables as possible, using scripts to emulate
    complex penetration testing steps, static code analysis tools
    directly available to the development teams, assisting dev teams in
    building appsec unit and integration tests, and more.

-   **Culture**. Mature AppSec programs try to build out the insecure
    design and eliminate the technical debt of existing code by being a
    part of the development team and not to the side. AppSec teams who
    see development teams as "us" and "them" are doomed to failure.

-   **Continuous improvement**. Mature AppSec programs look to
    constantly improve. If something is not working, stop doing it. If
    something is clunky or not scalable, work to improve it. If
    something is not being used by the development teams and has no or
    limited impact, do something different. Just because we've done
    testing like desk checks since the 1970s doesn't mean it's a good
    idea. Measure, evaluate, and then build or improve.
