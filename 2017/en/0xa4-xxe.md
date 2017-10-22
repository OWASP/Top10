# A4:2017 XML External Entities (XXE)

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 2 \| Detectability 3 | Technical 3 \| Business |
| Attackers who can access web pages or web services, particularly SOAP web services, that process XML. Penetration testers should be capable of exploiting XXE once trained. DAST tools require additional manual steps to exploit this issue. | By default, many older XML processors allow specification of an external entity, a URI that is dereferenced and evaluated during XML processing. SAST tools can discover this issue by inspecting dependencies and configuration. | These flaws can be used to extract data, execute a remote request from the server, scan internal systems, perform a denial-of-service attack, and other attacks. The business impact depends on the protection needs of all affected applications and data. |

## Am I Vulnerable to XXE?

Applications and in particular XML-based web services or downstream integrations might be vulnerable to attack if:

* Your application accepts XML directly or XML uploads, especially from untrusted sources, or inserts untrusted data into XML documents, which is then parsed by an XML processor
* Any of the XML processors in the application or SOAP based web services has [document type definitions (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) enabled. As the exact mechanism for disabling DTD processing varies by processor, it is recommended that you consult a reference such as the [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* If your application uses SOAP prior to version 1.2, it is likely susceptible to XXE attacks if XML entities are being passed to the SOAP framework.
* SAST tools can help detect XXE in source code, although manual code review is the best alternative in large, complex apps with many integrations.
* Being vulnerable to XXE attacks likely means that you are vulnerable to other billion laughs denial-of-service attacks.

## How Do I Prevent This?

Developer training is essential to identify and mitigate XXE completely. Besides that, preventing XXE requires:

* Disable XML external entity and DTD processing in all XML parsers in your application, as per the [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Implement positive ("whitelisting") input validation, filtering, or sanitization to prevent hostile data within XML documents, headers, or nodes.
* Verify that XML or XSL file upload functionality validates incoming XML using XSD validation or similar.
* Patch or upgrade all the latest XML processors and libraries in use by the app or on the underlying operating system. The use of dependency checkers is critical in managing the risk from necessary libraries and components in not only your app, but any downstream integrations.
* Upgrade SOAP to the latest version.

If these controls are not possible, consider using virtual patching, API security gateways, or WAFs to detect, monitor, and block XXE attacks. 

## Example Attack Scenarios

Numerous public XXE issues have been discovered, including attacking embedded devices. XXE occurs in a lot of unexpected places, including deeply nested dependencies. The easiest way is to upload a malicious XML file, if accepted:

**Scenario #1**: The attacker  attempts to extract data from the server:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Scenario #2**: An attacker probes the server's private network by changing the above ENTITY line to:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Scenario #3**: An attacker attempts a denial-of-service attack by including a potentially endless file:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## References

### OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide - Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP XXE Prevention Cheat Sheet](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP XML Security Cheat Sheet](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### External

* [CWE-611 Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
