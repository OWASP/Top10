# A4 XML External Entities (XXE)

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Attackers who can access web pages or web services, particularly SOAP web services, that process XML. Penetration testers should be capable of exploiting XXE once trained. DAST tools require additional manual steps to exploit this issue. SAST tools can discover this issue by inspecting dependencies and configuration. | By default, many older XML processors allow specification of an external entity, a URI that is derefenced and evaluated during XML processing. | These flaws can be used to extract data, execute a remote request from the server, scan internal systems, perform a denial-of-service attack, and other attacks. |

## Am I vulnerable to attack?

If your application accepts XML input, especially from untrusted sources, you may be vulnerable to XXE. You need to identify each XML processor in your application and determine if [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) has been disabled. As the exact mechanism for disabling DTD processing varies by processor, it is recommended that you consult a reference such as the [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).

_This statement seems weak, can we do better?_ If your application is using SOAP prior to version 1.2 it is susceptible to XXE attacks unless you have implemented specific remediations to ensure that XML entities are not being passed to the SOAP framework.

## How do I prevent

Preventing XXE requires:

* Ensure the latest XML processors and libraries are in use. Co
* Ensure the XML processor is configured by default to not parse external entities
* Use SOAP 1.2 or later
* Consider disabling XML DTD processing in all XML parsers in your application.

Protecting against XXE attacks also protects against billion laughs denial-of-service attacks.

_This statement seems weak, can we do better?_ If you are using SOAP, be sure that you are using version 1.2 or better.

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
* [OWASP XML Security Cheat Sheet](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### External

* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
