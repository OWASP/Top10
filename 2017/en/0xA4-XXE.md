# A4 XML External Entities (XXE)

| Factor | Score | Description |
| -- | -- | -- |
| Threat agent | ? | The threat agent is app specific, and depends on access, motive, and goals against the data asset. |
| Exploitability | AVERAGE (2) | Penetration testers should be capable of exploiting XXE once trained. DAST tools require additional manual steps to exploit this issue. |
| Prevalence | COMMON (2) | XXE was found in a significant number of apps and web services. |
| Detectability | EASY (3) | Automated detection of XXE is possible by DAST tools by inspecting for XML documents or data used, or by setting up a web server or tool to receive connections from the victim XML processor. SAST tools can discover this issue by inspecting dependencies and configuration. |
| Impact | SEVERE (3) | XXE can be used for internal port scanning, internal remote and local file inclusion, and for denial of service. |
| Business impacts | ? | The business impact is application specific, and depends on the classification and protection needs of your application and data. |
| Score | 7.0 | HIGH |

## Am I vulnerable to attack?

If your application accepts XML input, especially from untrusted sources, you may be vulnerable to XXE. You need to identify each XML processor in your application and determine if [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) has been disabled. As the exact mechanism for disabling DTD processing varies by processor, it is recommended that you consult a reference such as the [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).

## How do I prevent

Preventing XXE requires disabling XML DTD processing in all XML parsers in your application. 

## Example Scenarios

Scenario #1: The attacker attempts to extract data from the server:

```
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
 <foo>&xxe;</foo>
```

Scenario #2: An attacker probes the server's private network by changing the above `ENTITY` line to:

```
  <!ENTITY xxe SYSTEM "https://192.168.1.1/private/service" >]>
```

Scenario #3: An attacker attempts a denial-of-service attack by including a potentially endless file:

```
  <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```
## References

### OWASP
* [OWASP Proactive Controls - TBA](https://www.owasp.org/index.php/OWASP_Proactive_Controls#3:_Encode_Data) - is this a good reference? Maybe there's no strong proactive controls reference for XXE?
* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide - Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)

### External

TBA
