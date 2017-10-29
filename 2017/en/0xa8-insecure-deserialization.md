# A8:2017 Insecure Deserialization

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 1 | Prevalence 2 \| Detectability 2 | Technical 3 \| Business |
| Exploitation of deserialization is somewhat difficult, as off the shelf exploits rarely work without changes or tweaks to the underlying exploit code. | This issue is included in the Top 10 based on an [industry survey](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) and not on quantifiable data. Some tools can discover deserialization flaws, but human assistance is frequently needed to validate the problem. It is expected that prevalence data for deserialization flaws will increase as tooling is developed to help identify and address it. | The impact of deserialization flaws cannot be understated. They can lead to remote code execution attacks, one of the most serious attacks possible. |

## Am I Vulnerable to Insecure Deserialization?

Distributed applications or those that need to store state on clients or the filesystem may be using object serialization. Distributed applications with public listeners or applications that rely on the client maintaining state, are likely to allow for tampering of serialized data. This attack can be possible regardless of the serialization format (binary or text) or the programming language.  Applications and APIs will be vulnerable if the when:
* The serialization mechanism allows for the creation of arbitrary data types, AND
* There are classes available to the application that can be chained together to change application behavior during or after deserialization, or unintended content can be used to influence application behavior, AND
* The application or API accepts and deserializes hostile objects supplied by an attacker, or an application uses serialized opaque client side state without appropriate tamper resistant controls. OR
* Security state sent to an untrusted client without some form of integrity control is likely vulnerable to deserialization.

## How Do I Prevent This?

The only safe architectural pattern is to not accept serialized objects from untrusted sources or to use serialization mediums that only permit primitive data types.

If that is not possible:
* Implement integrity checks or encryption of the serialized objects to prevent hostile object creation or data tampering.
* Enforce strict type constraints during deserialization before object creation; typically code is expecting a definable set of classes. Bypasses to this technique have been demonstrated.
* Isolate code that deserializes, such that it runs in very low privilege environments, such as temporary containers.
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.
* Restrict or monitor incoming and outgoing network connectivity from containers or servers that deserialize.
* Monitor deserialization, alerting if a user deserializes constantly.

## Example Attack Scenarios

**Scenario #1**: A React app calls a set of Spring Boot microservices. Being functional programmers, they tried to ensure that their code is immutable. The solution they came up with is serializing user state and passing it back and forth with each request. An attacker notices the "R00" Java object signature, and uses the Java Serial Killer tool to gain remote code execution on the application server.

**Scenario #2**: A PHP forum uses PHP object serialization to save a "super" cookie, containing the user's user ID, role, password hash, and other state:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

An attacker changes the serialized object to give themselves admin privileges:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## References

### OWASP

* [OWASP Deserialization Cheat Sheet](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls - Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard - TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### External

* [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* https://github.com/mbechler/marshalsec
