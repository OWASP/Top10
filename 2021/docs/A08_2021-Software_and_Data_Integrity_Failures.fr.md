# A08:2021 – Manque d'intégrité des données et du logiciel    ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Facteurs

| CWEs associées | Taux d'incidence max | Taux d'incidence moyen | Exploitation pondérée moyenne | Impact pondéré moyen | Couverture max | Couverture moyenne | Nombre total d'occurrences | Nombre total de CVEs |
|:--------------:|:--------------------:|:----------------------:|:-----------------------------:|:--------------------:|:--------------:|:------------------:|:--------------------------:|:--------------------:|
|       10       |       16,67 %        |         2,05 %         |             6,94              |         7,94         |    75,04 %     |      45,35 %       |           47 972           |        1 152         |

## Aperçu

Une nouvelle catégorie pour 2021 qui se concentre sur la formulation d'hypothèses relatives aux mises à jour logicielles, aux données critiques et aux pipelines CI/CD sans vérification de l'intégrité. Il s'agit de l'un des impacts pondérés les plus élevés des données CVE/CVSS (Common Vulnerability and Exposures/Common Vulnerability Scoring System). Les *Common Weakness Enumerations* (CWE) notables comprennent *CWE-829 : Inclusion of Functionality from Untrusted Control Sphere*, *CWE-494 : Download of Code Without Integrity Check*, et *CWE-502 : Deserialization of Untrusted Data*.

## Description 

Les défaillances de l'intégrité des logiciels et des données sont liées au code et à l'infrastructure qui ne sont pas protégés contre les violations de l'intégrité. C'est le cas, par exemple, lorsqu'une application s'appuie sur des plugins, des bibliothèques ou des modules provenant de sources, de dépôts et de réseaux de diffusion de contenu (CDN) non fiables. Un pipeline CI/CD non sécurisé peut introduire un risque d'accès non autorisé, de code malveillant ou de compromission du système. Enfin, de nombreuses applications intègrent désormais une fonctionnalité de mise à jour automatique, où les mises à jour sont téléchargées sans vérification d'intégrité suffisante et appliquées à l'application précédemment fiable. Les attaquants pourraient potentiellement télécharger leurs propres mises à jour pour les distribuer et les exécuter sur toutes les installations. Un autre exemple est celui des objets ou des données qui sont codés ou sérialisés dans une structure qu'un attaquant peut voir et modifier et qui sont vulnérables à une désérialisation non sécurisée.

## How to Prevent

-   Use digital signatures or similar mechanisms to verify the software or data is from the expected source and has not been altered.

-   Ensure libraries and dependencies, such as npm or Maven, are
    consuming trusted repositories. If you have a higher risk profile, consider hosting an internal known-good repository that's vetted.

-   Ensure that a software supply chain security tool, such as OWASP
    Dependency Check or OWASP CycloneDX, is used to verify that
    components do not contain known vulnerabilities

-   Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced into your software pipeline.

-   Ensure that your CI/CD pipeline has proper segregation, configuration, and access
    control to ensure the integrity of the code flowing through the
    build and deploy processes.

-   Ensure that unsigned or unencrypted serialized data is not sent to
    untrusted clients without some form of integrity check or digital
    signature to detect tampering or replay of the serialized data

## Example Attack Scenarios

**Scenario #1 Update without signing:** Many home routers, set-top
boxes, device firmware, and others do not verify updates via signed
firmware. Unsigned firmware is a growing target for attackers and is
expected to only get worse. This is a major concern as many times there
is no mechanism to remediate other than to fix in a future version and
wait for previous versions to age out.

**Scenario #2 SolarWinds malicious update**: Nation-states have been
known to attack update mechanisms, with a recent notable attack being
the SolarWinds Orion attack. The company that develops the software had
secure build and update integrity processes. Still, these were able to
be subverted, and for several months, the firm distributed a highly
targeted malicious update to more than 18,000 organizations, of which
around 100 or so were affected. This is one of the most far-reaching and
most significant breaches of this nature in history.

**Scenario #3 Insecure Deserialization:** A React application calls a
set of Spring Boot microservices. Being functional programmers, they
tried to ensure that their code is immutable. The solution they came up
with is serializing the user state and passing it back and forth with
each request. An attacker notices the "rO0" Java object signature (in base64) and
uses the Java Serial Killer tool to gain remote code execution on the
application server.

## References

-   \[OWASP Cheat Sheet: Software Supply Chain Security\](Coming Soon)

-   \[OWASP Cheat Sheet: Secure build and deployment\](Coming Soon)

-    [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) 
 
-   [OWASP Cheat Sheet: Deserialization](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   [SAFECode Software Integrity Controls](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   [A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)

-   [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## List of Mapped CWEs

[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
