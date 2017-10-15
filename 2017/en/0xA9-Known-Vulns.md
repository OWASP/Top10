# A9 Using Compenents with Known Vulnerabilities

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | AVERAGE (2) | There are off the shelf exploits for certain platforms, but typically this issue requires authentication or access to specific platform functionality. |
| Prevalence | WIDESPREAD (3) | This issue is widespread, with most applications and APIs containing 200-1000+ dependencies depending on platform. |
| Detectability | AVERAGE (2) | This issue is not easily detectable. due to backported patches or hidden headers. The best place to detect this issue is using dependency checkers in the CI/CD platform. |
| Impact | MODERATE (2) | Some of the largest breaches in history abused this risk, and so depending on the data asset under protection, this might even rise to SEVERE. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 4.7 | MEDIUM |

## Am I vulnerable to attack?

You are likely vulnerable:

1. If you do not know the versions of all components you use (both client-side and server-side). This includes components you directly use as well as nested dependencies.

* If any of your software out of date? This includes the OS, Web/App Server, DBMS, applications, APIs and all components, runtime environments and libraries.
* If you do not know if they are vulnerable. Either if you don’t research for this information or if you don’t scan them for vulnerabilities on a regular base.
* If you do not fix nor upgrade the software. E.g. if you don’t update your software to work together with this fixes. But also if you fix severe vulnerabilities too slowly.
* If you do not secure the components' configurations (see [A5:2017-TBD]()).

## How do I prevent

Most component projects do not create vulnerability patches for old versions. So the only way to fix the problem is to upgrade to the next version, which can require other code changes. Software projects should have a process in place to:
* Continuously inventory the versions of both client-side and server-side components and their dependencies using tools like [versions](http://www.mojohaus.org/versions-maven-plugin/), [DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/), etc.
* Continuously monitor sources like [CVE](https://cve.mitre.org/) and [NVD](https://nvd.nist.gov/) for vulnerabilities in your components. Use software composition analysis tools to automate the process.
* Analyze libraries to be sure they are actually invoked at runtime before making changes, as many components are never loaded or invoked.
* Most component projects do not create security patches for old versions. So you may need to upgrade to the next version (and rewrite the application to match, if needed). If this is not possible, deploy a [virtual patch](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F) that analyzes HTTP traffic, data flow, or code execution and prevents vulnerabilities from being exploited.

Additionally, you should ensure that there is an ongoing plan for monitoring the security of components for the lifetime of the application.


## Example Scenarios

Components almost always run with the full privilege of the application, so flaws in any component can result in serious impact. Such flaws can be accidental (e.g., coding error) or intentional (e.g., backdoor in component). Some example exploitable component vulnerabilities discovered are:
* Apache CXF Authentication Bypass – By failing to provide an identity token, attackers could invoke any web service with full permission. (Apache CXF is a services framework, not to be confused with the Apache Application Server.)
* Struts 2 Remote Code Execution – Sending an attack in the Content-Type header causes the content of that header to be evaluated as an OGNL expression, which enables execution of arbitrary code on the server.
* Applications using a vulnerable version of either component are susceptible to attack as both components are directly accessible by application users. Other vulnerable libraries, used deeper in an application, may be harder to exploit

## References

### OWASP

* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

External
* [The Unfortunate Reality of Insecure Libraries](http://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
