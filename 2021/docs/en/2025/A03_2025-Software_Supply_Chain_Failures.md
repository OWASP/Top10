<link rel="stylesheet" href="../../assets/css/RC-stylesheet.css" />

# A03:2025 Software Supply Chain Failures ![icon](../../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Background. 

This was top-ranked in the Top 10 community survey with exactly 50% respondents ranking it #1. Since initially appearing in the 2013 Top 10 as “A9 – Using Components with Known Vulnerabilities”, the risk has grown in scope to include all supply chain failures, not just ones involving known vulnerabilities. Despite this increased scope, supply chain failures continue to be a challenge to identify with only 11 Common Vulnerability and Exposures (CVEs) having the related CWEs. However, when tested and reported in the contributed data, this category has the highest average incidence rate at 5.19%. The relevant CWEs are *CWE-477: Use of Obsolete Function, CWE-1104: Use of Unmaintained Third Party Components*, CWE-1329: *Reliance on Component That is Not Updateable*, and *CWE-1395: Dependency on Vulnerable Third-Party Component*.


## Score table.


<table>
  <tr>
   <td>CWEs Mapped 
   </td>
   <td>Max Incidence Rate
   </td>
   <td>Avg Incidence Rate
   </td>
   <td>Max Coverage
   </td>
   <td>Avg Coverage
   </td>
   <td>Avg Weighted Exploit
   </td>
   <td>Avg Weighted Impact
   </td>
   <td>Total Occurrences
   </td>
   <td>Total CVEs
   </td>
  </tr>
  <tr>
   <td>5
   </td>
   <td>8.81%
   </td>
   <td>5.19%
   </td>
   <td>65.42%
   </td>
   <td>28.93%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>



## Description. 

Software supply chain failures are breakdowns or other compromises in the process of building, distributing, or updating software. They are often caused by vulnerabilities or malicious changes in third-party code, tools, or other dependencies that the system relies on.

You are likely vulnerable if:

* you do not carefully track the versions of all components that you use (both client-side and server-side). This includes components you directly use as well as nested (transitive) dependencies.
* the software is vulnerable, unsupported, or out of date. This includes the OS, web/application server, database management system (DBMS), applications, APIs and all components, runtime environments, and libraries.
* you do not scan for vulnerabilities regularly and subscribe to security bulletins related to the components you use.
* you do not have a change management process or tracking of changes within your supply chain, including tracking IDEs, IDE extensions and updates, changes to your organization’s code repository, sandboxes, image and library repositories, the way artifacts are created and stored, etc. Every part of your supply chain should be documented, especially changes.
* you have not hardened every part of your supply chain, with a special focus on access control and the application of least privilege. 
* your supply chain systems do not have any separation of duty. No single person should be able to write code and  promote it all the way to production without oversight from another human being.
* developers, DevOps, or infrastructure professionals are allowed to download and use components from untrusted sources, for use in production.
* you do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion. This commonly happens in environments when patching is a monthly or quarterly task under change control, leaving organizations open to days or months of unnecessary exposure before fixing vulnerabilities.
* software developers do not test the compatibility of updated, upgraded, or patched libraries.
* you do not secure the configurations of every part of your system (see [A02:2025-Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)).
* your CI/CD pipeline has weaker security than the systems it builds and deploys, especially if it is complex.


## How to prevent. 

There should be a patch management process in place to:



* Centrally generate and manage the Software Bill of Materials (SBOM) of your entire software.
* Track not just your direct dependencies, but their (transitive) dependencies, and so on.
* Reduce attack surface by removing unused dependencies, unnecessary features, components, files, and documentation.
* Continuously inventory the versions of both client-side and server-side components (e.g., frameworks, libraries) and their dependencies using tools like versions, OWASP Dependency Check, retire.js, etc.
* Continuously monitor sources like Common Vulnerability and Exposures (CVE), National Vulnerability Database (NVD), and [Open Source Vulnerabilities (OSV)](https://osv.dev/) for vulnerabilities in the components you use. Use software composition analysis, software supply chain, or security-focused SBOM tools to automate the process. Subscribe to alerts for security vulnerabilities related to components you use.
* Only obtain components from official (trusted) sources over secure links. Prefer signed packages to reduce the chance of including a modified, malicious component (see [A08:2025-Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)).
* Deliberately choose which version of a dependency you use and upgrade only when there is need.
* Monitor for libraries and components that are unmaintained or do not create security patches for older versions. If patching is not possible, consider migrating to an alternative. If that is not possible, consider deploying a virtual patch to monitor, detect, or protect against the discovered issue.
* Update your CI/CD, IDE, and any other developer tooling regularly


There should be a change management process or tracking system in place to track changes to:
* CI/CD settings (all build tools and pipelines)
* Code repositories
* Sandbox areas
* Developer IDEs
* SBOM tooling, and created artifacts
* Logging systems and logs
* Third party integrations, such as SaaS
* Artifact repositories
* Container registries


Harden the following systems, which includes enabling MFA and locking down IAM:
* Your code repository (which includes not checking in secrets, protecting branches, backups)
* Developer workstations (regular patching, MFA, monitoring, and more)
* Your build server & CI/CD (separation of duties, access control, signed builds, environment-scoped secrets, tamper-evident logs, more)
* Your artifacts (ensure integrity via providence, signing, and time stamping, promote artifacts rather than rebuilding for each environment, ensure builds are immutable)
* Infrastructure as code (managed like all code, including use of PRs and version control)

Every organization must ensure an ongoing plan for monitoring, triaging, and applying updates or configuration changes for the lifetime of the application or portfolio.


## Example attack scenarios. 

**Scenario #1:** A trusted vendor is compromised with malware, leading to your computer systems being compromised when you upgrade. The most famous example of this is probably:



* The 2019 SolarWinds compromise that led to ~18,000 organizations being compromised. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Scenario #2:** A trusted vendor is compromised such that it behaves maliciously only under a specific condition. 



* The 2025 Bybit theft of $1.5 billion caused by a supply chain attack in wallet software that only executed when the target wallet was being used. https://thehackernews.com/2025/02/bybit-hack-traced-to-safewallet-supply.html

**Scenario #3:** The GlassWorm supply chain attack in 2025 against the VS Code marketplace has malicious actors implement invisible, self-replicating code into a legitimate extension in the VS Marketplace, as well as several extensions in the OpenVSX Marketplace, which auto-updated onto developer machines. The worm immediately harvested local secrets from the developer machines, attempted to establish command and control, as well as emptied developer’s crypto wallets if possible. This supply chain attack was extremely advanced, fast-spreading, and damaging, and by targeting developer machines it demonstrated developers themselves are now prime targets for supply chain attacks.

**Scenario #4:** Components typically run with the same privileges as the application itself, so flaws in any component can result in serious impact. Such flaws can be accidental (e.g., coding error) or intentional (e.g., a backdoor in a component). Some example exploitable component vulnerabilities discovered are:


* CVE-2017-5638, a Struts 2 remote code execution vulnerability that enables the execution of arbitrary code on the server, has been blamed for significant breaches.
* While the internet of things (IoT) is frequently difficult or impossible to patch, the importance of patching them can be great (e.g., biomedical devices).

There are automated tools to help attackers find unpatched or misconfigured systems. For example, the [Shodan IoT](https://www.shodan.io) search engine can help you find devices that still suffer from Heartbleed vulnerability patched in April 2014.

## References

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## List of Mapped CWEs

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
