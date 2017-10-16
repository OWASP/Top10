# A9 Using Components with Known Vulnerabilities

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| There are off the shelf exploits for certain platforms, but typically this issue requires authentication or access to specific platform functionality. This issue is not easily detectable. due to backported patches or hidden headers. The best place to detect this issue is using dependency checkers in the CI/CD platform. | This issue is widespread, with most applications and APIs containing 200-1000+ dependencies depending on platform.| Some of the largest breaches in history abused this risk, and so depending on the data asset under protection, this might even rise to SEVERE. |

## Am I vulnerable to attack?

You are likely vulnerable:

* If you do not know the versions of all components you use (both client-side and server-side). This includes components you directly use as well as nested dependencies.
* If any of your software out of date? This includes the OS, Web/App Server, DBMS, applications, APIs and all components, runtime environments and libraries.
* If you do not know if they are vulnerable. Either if you don’t research for this information or if you don’t scan them for vulnerabilities on a regular base.
* If you do not fix nor upgrade the software. E.g. if you don’t update your software to work together with this fixes. But also if you fix severe vulnerabilities too slowly.
* If you do not secure the components' configurations (see [A5:2017-TBD]()).

## How do I prevent

Most component projects do not create vulnerability patches for old versions. So the only way to fix the problem is to upgrade to the next version, which can require other code changes. Software projects should have a process in place to:

* Continuously inventory the versions of both client-side and server-side components and their dependencies using tools like [versions](http://www.mojohaus.org/versions-maven-plugin/), [DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/), etc.
* Continuously monitor sources like [CVE](https://cve.mitre.org/) and [NVD](https://nvd.nist.gov/) for vulnerabilities in your components. Use software composition analysis tools to automate the process.
* Analyze libraries to be sure they are actually invoked at runtime before making changes, as many components are never loaded or invoked.
* Only obtain your components from official sources and, when possible, prefer signed packages to reduce the chance of getting a modified, malicious component.
* Most component projects do not create security patches for old versions. So you may need to upgrade to the next version (and rewrite the application to match, if needed). If this is not possible, deploy a [virtual patch](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F) that analyzes HTTP traffic, data flow, or code execution and prevents vulnerabilities from being exploited.

Additionally, you should ensure that there is an ongoing plan for monitoring the security of components for the lifetime of the application.

## Example Scenarios

Components almost always run with the full privilege of the application, so flaws in any component can result in serious impact. Such flaws can be accidental (e.g., coding error) or intentional (e.g., backdoor in component). 

The [2017 Equifax breach](https://arstechnica.com/information-technology/2017/09/massive-equifax-breach-caused-by-failure-to-patch-two-month-old-bug/) was caused by [CVE-2017-5638](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), a Struts 2 remote code execution vulnerability that enables execution of arbitrary code on the server.

While [internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) are frequently difficult to patch, the importance of patching them can be great (eg: [St. Jude pacemakers](http://www.zdnet.com/article/fda-forces-st-jude-pacemaker-recall-to-patch-security-vulnerabilities/)).

There are now tools to help attackers find unpatched systems. For example, the Shodan IoT search engine can help you [find devices](https://www.shodan.io/report/89bnfUyJ) that still suffer from the [Heartbleed vulnerability](https://en.wikipedia.org/wiki/Heartbleed) that was patched in April 2014.

## References

### OWASP

* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### External

* [The Unfortunate Reality of Insecure Libraries](http://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
