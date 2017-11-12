# A6:2017 Security Misconfiguration

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 3 | Prevalence 3 \| Detectability 3 | Technical 2 \| Business |
| Attackers will often attempt to access default accounts, unused pages, unpatched flaws, unprotected files and directories, etc. to gain unauthorized access to or knowledge of the system. | Security misconfiguration can happen at any level of an application stack, including the network services, platform, web server, application server, database, frameworks, custom code, and pre-installed virtual machines, containers or storage. Automated scanners are useful for detecting misconfigurations, use of default accounts or configurations, unnecessary services, legacy options etc. | Such flaws frequently give attackers unauthorized access to some system data or functionality. Occasionally, such flaws result in a complete system compromise. The business impact depends on the protection needs of your application and data. |

## Is the Application Vulnerable?

Is your application missing the proper security hardening across any part of the application stack? Including:

* Are any unnecessary features enabled or installed (e.g. ports, services, pages, accounts, privileges)?
* Are default accounts and their passwords still enabled and unchanged?
* Will error handling reveal stack traces or other overly informative error messages to users?
* On upgraded systems, are the latest security features disabled or not configured securely?
* Are the security settings in your application servers, application frameworks (e.g. Struts, Spring, ASP.NET), libraries, databases, etc. not set to secure values?
* For web applications, does the server not send security directives to browsers or are they not set to secure values?
* Is any of your software out of date? (see **A9:2017-Using Components with Known Vulnerabilities**).

Without a concerted, repeatable application security configuration process, systems are at a higher risk.

## How To Prevent

Is your application missing the proper security hardening across any part of the application stack? Including:

* A repeatable hardening process that makes it fast and easy to deploy another environment that is properly locked down. Development, QA, and production environments should all be configured identically, with different credentials used in each environment. This process should be automated to minimize the effort required to setup a new secure environment.
* Remove or do not install any unnecessary features, components, documentation and samples. Remove unused dependencies and frameworks.
* A task to review and update the configurations appropriate to all security notes, updates and patches as part of the patch management process (see **A9:2017-Using Components with Known Vulnerabilities**).
* A strong application architecture that provides effective, secure separation between components, or tenants, with segmentation, containerization, or cloud security groups (ACLs).
* Send security directives to client agents, e.g. [Security Headers](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project).
* An automated process to verify the effectiveness of the configurations and settings in all environments.

## Example Attack Scenarios

**Scenario #1**: The App server comes with sample apps that are not removed from your production server. These sample apps have known security flaws attackers use to compromise your server. If one of these apps is the admin console and default accounts weren’t changed the attacker logs in with default passwords, and takes over.

**Scenario #2**: Directory listing is not disabled on your server. An attacker discovers they can simply list directories. The attacker finds and downloads your compiled Java classes, which they decompile and reverse engineer to view your code. The attacker then finds a serious access control flaw in your application.

**Scenario #3**: The app server’s configuration allows detailed error messages e.g. stack traces to be returned to users. This potentially exposes sensitive information or underlying flaws such as component versions that are known to be vulnerable.

**Scenario #4**: The default configuration or a copied old one activates old vulnerable protocol versions or options that can be misused by an attacker or malware.


## References

### OWASP

* [OWASP Testing Guide: Configuration Management](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [OWASP Testing Guide: Testing for Error Codes](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

For additional requirements in this area, see the [ASVS requirements areas for Security Configuration (V11 and V19)](https://www.owasp.org/index.php/ASVS).

### External

* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
* [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
