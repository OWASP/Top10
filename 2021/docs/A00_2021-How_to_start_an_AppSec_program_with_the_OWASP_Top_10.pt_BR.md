[comment]: <> ([WIP - Working in progress])

# Como iniciar um programa AppSec com o OWASP Top 10

Antes, o OWASP Top 10 nunca foi projetado para ser a base de um programa AppSec.
No entanto, é essencial começar de algum lugar para muitas organizações que
estão apenas começando em sua jornada de segurança de aplicações.
O OWASP Top 10 2021 é um bom começo como base para listas de verificação de segurança
e assim por diante, mas não é suficiente por si só.

## Etapa 1. Identifique as lacunas e os objetivos de seu programa appsec

Muitos programas de Aplicações de Segurança (AppSec) tentam correr antes 
que possam engatinhar ou andar. Esses esforços estão fadados ao fracasso. 
Incentivamos fortemente os CISOs e a liderança de AppSec a usar
o Modelo de Maturidade de Garantia de Software OWASP 
(Software Assurance Maturity Model - SAMM)\[<https://owaspsamm.org>\] para identificar 
pontos fracos e áreas de melhoria em um período de 1-3 anos. A primeira etapa
é avaliar onde você está agora, identificar as lacunas na governança,
design, implementação, verificação e operações que você precisa resolver
imediatamente em comparação com aquelas que podem esperar, e priorizar
a implementação ou melhoria das quinze práticas de segurança OWASP SAMM.
O OWASP SAMM pode ajudá-lo a construir e medir melhorias em seus
esforços de garantia de software.

## Etapa 2. Plano para um ciclo de vida de desenvolvimento seguro de estrada pavimentada

Traditionally the preserve of so-called "unicorns," the paved road
concept is the easiest way to make the most impact and scale AppSec
resources with development team velocity, which only increases every
year.

The paved road concept is "the easiest way is also the most secure way"
and should involve a culture of deep partnerships between the
development team and the security team, preferably such that they are
one and the same team. The paved road aims to continuously improve,
measure, detect and replace insecure alternatives by having an
enterprise-wide library of drop-in secured replacements, with tooling to
help see where improvements can be made by adopting the paved road. This
allows existing development tools to report on insecure builds and help
development teams self-correct away from insecure alternatives.

The paved road might seem a lot to take in, but it should be built
incrementally over time. There are other forms of appsec programs out
there, notably the Microsoft Agile Secure Development Lifecycle. Not
every appsec program methodology suits every business.

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
even better a library that is known safe against injection, such as
React or Vue. The more of these secure drop-in replacements provided to
teams, the better. A vital task of the appsec team is to ensure that the
security of these components is continuously evaluated and improved.
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
