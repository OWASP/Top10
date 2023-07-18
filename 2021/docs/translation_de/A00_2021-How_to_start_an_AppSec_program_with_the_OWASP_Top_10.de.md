# Wie baue ich mit den Top 10 ein Programm zur Anwendungssicherheit auf?

Die OWASP Top 10 waren ursprünglich nicht als Grundlage für ein Programm zur Anwendungssicherheit gedacht. 
Ein definierter Startpunkt ist jedoch für viele Organisationen, die gerade erst mit Anwendungssicherheit beginnen, elementar.
Die OWASP Top 10 2021 stellen eine gute Baseline für Checklisten dar; sie alleine sind jedoch nicht ausreichend.

## Schritt 1. Identifizieren Sie Gaps und Ziele ihres Programms zur Anwendungssicherheit

Viele Programme zur Anwendungssicherheit versuchen, den zweiten Schritt vor dem ersten zu machen.
Solche Ansätze sind bereits zum Scheitern verurteilt.
CISOs und Verantwortlichen der Anwendungssicherheit empfehlen wir,
das [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) einzusetzen,
um Schwächen und Verbesserungspotentiale über einen Zeitraum von 1-3 Jahren zu identifizieren.
Der erste Schritt bedeutet, die Ist-Situation zu bewerten,
*jene* Gaps in Bezug auf Governance, Entwurf, Implementierung, Qualitätssicherung und Betrieb zu identifizieren,
die *umgehend* geschlossen werden müssen,
und die Prioritäten in der Umsetzung oder Verbesserung der 15 OWASP SAMM Sicherheitsmaßnahmen zu setzen.
OWASP SAMM kann dabei helfen, 
die Sicherheitslage ihrer Anwendungen zu messen und diese zu verbessern.

## Schritt 2. Ebnen Sie den Weg für einen Sicheren Entwicklungs-Lebenszyklus

Lange den "Einhörnern" vorbehalten, stellt das Konzept eines "geebneten Weges" die einfachste Möglichkeit dar,
einen größtmöglichen Ausschlag zu geben
und ihre Ressourcen für Anwendungssicherheit mit der jährlich steigenden Velocity der Teams zu skalieren.

The paved road concept is "the easiest way is also the most secure way" and should involve a culture of deep partnerships between the development team and the security team, preferably such that they are one and the same team. The paved road aims to continuously improve, measure, detect and replace insecure alternatives by having an enterprise-wide library of drop-in secured replacements, with tooling to help see where improvements can be made by adopting the paved road. This allows existing development tools to report on insecure builds and help development teams self-correct away from insecure alternatives.

The paved road might seem a lot to take in, but it should be built incrementally over time. There are other forms of appsec programs out there, notably the Microsoft Agile Secure Development Lifecycle. Not every appsec program methodology suits every business.

## Schritt 3. Implement the paved road with your development teams

Paved roads are built with the consent and direct involvement of the relevant development and operations teams. The paved road should be aligned strategically with the business and help deliver more secure applications faster. Developing the paved road should be a holistic exercise covering the entire enterprise or application ecosystem, not a per-app band-aid, as in the old days.

## Schritt 4. Migrate all upcoming and existing applications to the paved road

Add paved road detection tools as you develop them and provide information to development teams to improve the security of their applications by how they can directly adopt elements of the paved road. Once an aspect of the paved road has been adopted, organizations should implement continuous integration checks that inspect existing code and check-ins that use prohibited alternatives and warn or reject the build or check-in. This prevents insecure options from creeping into code over time, preventing technical debt and a defective insecure application. Such warnings should link to the secure alternative, so the development team is given the correct answer immediately. They can refactor and adopt the paved road component quickly.

## Schritt 5. Test that the paved road has mitigated the issues found in the OWASP Top 10

Paved road components should address a significant issue with the OWASP Top 10, for example, how to automatically detect or fix vulnerable components, or a static code analysis IDE plugin to detect injections or even better start using a library that is known safe against injection. The more of these secure drop-in replacements provided to teams, the better. A vital task of the appsec team is to ensure that the security of these components is continuously evaluated and improved. Once they are improved, some form of communication pathway with consumers of the component should indicate that an upgrade should occur, preferably automatically, but if not, at least highlighted on a dashboard or similar.

## Schritt 6. Build your program into a mature AppSec program

You must not stop at the OWASP Top 10. It only covers 10 risk categories. We strongly encourage organizations to adopt the Application Security Verification Standard and progressively add paved road components and tests for Level 1, 2, and 3, depending on the developed applications' risk level.

## Weitere Schritte

Alle guten Programme zur Anwendungssicherheit gehen über das Minimum hinaus.
Alle Beteiligten müssen weiterhin Alles geben, um jemals Herr über die Schwachstellen in den Anwendungen zu werden.

-   **Conceptual integrity**. Mature AppSec programs must contain some concept of security architecture, whether a formal cloud or enterprise security architecture or threat modeling

-   **Automation and scale**. Mature AppSec programs try to automate as much of their deliverables as possible, using scripts to emulate
    complex penetration testing steps, static code analysis tools directly available to the development teams, assisting dev teams in building appsec unit and integration tests, and more.

-   **Culture**. Mature AppSec programs try to build out the insecure design and eliminate the technical debt of existing code by being a part of the development team and not to the side. AppSec teams who see development teams as "us" and "them" are doomed to failure.

-   **Continuous improvement**. Mature AppSec programs look to constantly improve. If something is not working, stop doing it. If something is clunky or not scalable, work to improve it. If something is not being used by the development teams and has no or limited impact, do something different. Just because we've done testing like desk checks since the 1970s doesn't mean it's a good idea. Measure, evaluate, and then build or improve.
