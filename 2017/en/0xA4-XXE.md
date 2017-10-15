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

You may be vulnerable to XXE if your application processes XML input without explicitly disabling [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition).

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
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)

### External

TBA
