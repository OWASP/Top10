# A9 Using Components with Known Vulnerabilities

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 3 \| Detectability 2 | Technical 2 \| Business |
| While it is easy to find already-written exploits for many known vulnerabilities, other vulnerabilities require concentrated effort to develop a custom exploit. | Prevalence of this issue is very widespread. Component-heavy development patterns can lead to development teams not even understanding which components they use in their application or API, much less keeping them up to date. This issue is detectable by the use of scanners such as retire.js and header inspection, but verifying if it is exploitable requires an attack of some description. | While some known vulnerabilities lead to only minor impacts, some of the largest breaches to date have relied on exploiting known vulnerabilities in components. Depending on the assets you are protecting, perhaps this risk should be at the top of your list. |

## Am I Vulnerable to Known Vulnerabilities?

You are likely vulnerable:
* If you do not know the versions of all components you use (both client-side and server-side). This includes components you directly use as well as nested dependencies.
* If any of your software out of date? This includes the OS, Web/App Server, DBMS, applications, APIs and all components, runtime environments and libraries.
* If you do not know if they are vulnerable. Either if you don’t research for this information or if you don’t scan them for vulnerabilities on a regular base.
* If you do not fix nor upgrade the underlying platform, frameworks and dependencies in a timely fashion. This commonly happens is environments when patching is a monthly or quarterly task under change control, which leaves organizations open to many days or months of unnecessary exposure to fixed vulnerabilities. This is likely the root cause of one of the largest breaches of all time. 
* If you do not secure the components' configurations (see A6:2017-Security Misconfiguration).

## How Do I Prevent This?

Software projects should have a process in place to:

* Remove unused dependencies, unnecessary features, components, files, and documentation
* Continuously inventory the versions of both client-side and server-side components and their dependencies using tools like versions], [DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/), etc.
* Continuously monitor sources like [CVE](https://cve.mitre.org/) and [NVD](https://cve.mitre.org/) for vulnerabilities in your components. Use software composition analysis tools to automate the process.
* Only obtain your components from official sources and, when possible, prefer signed packages to reduce the chance of getting a modified, malicious component.
* Many libraries and components do not create security patches for out of support or old versions, or it simply be unmaintained. If patching is not possible, consider deploying a [virtual patch](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F) to monitor, detect or protect against the discovered issue.

Every organization must ensure that there is an ongoing plan for monitoring, triaging, and applying updates or configuration changes for the lifetime of the application or portfolio. 

## Example Attack Scenarios

Components typically run with the same privileges as the application itself, so flaws in any component can result in serious impact. Such flaws can be accidental (e.g. coding error) or intentional (e.g. backdoor in component). Some example exploitable component vulnerabilities discovered are:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), a Struts 2 remote code execution vulnerability that enables execution of arbitrary code on the server, has been blamed for significant breaches.
* While [internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things)are frequently difficult or impossible to patch, the importance of patching them can be great (eg: [St. Jude pacemakers]((http://www.zdnet.com/article/fda-forces-st-jude-pacemaker-recall-to-patch-security-vulnerabilities/)).

There are automated tools to help attackers find unpatched or misconfigured systems. For example, the [Shodan IoT search engine](https://www.shodan.io/report/89bnfUyJ) can help you find devices that still suffer from the [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) vulnerability that was patched in April 2014.

## References

### OWASP

* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### External

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
