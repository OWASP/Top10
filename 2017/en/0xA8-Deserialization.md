# A8 Deserialization

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability | Prevalence \| Detectability | Technical \| Business |
| Exploitation of deserialization is somewhat difficult, as although there are off the shelf exploits, these rarely work without changes or tweaks to the underlying exploit code. This issue can be discovered by tools, but is not easily verifiable due to backported patches or hidden headers. | There is currently little data on deserialization as yet, but if it was tested more frequently, this issue could easily be a future A1:2020 risk. | The impact of deserialization cannot be understated - it is responsible for the Equifax breach affecting the sensitive personal identifying and financial information of over 150 million people. Deserialization typically allows the attacker to run arbitrary code on the server. |

## Am I vulnerable to attack?

Application architecture has changed dramatically over the last few years, with the move to "server-less" API driven mobile and single page applications, with the associated rise of functional programming frameworks and languages. This seismic shift in application architecture were accompanied by the idea of the client maintaining state, to allow theoretical simpler and more scalable functional code. However, the hallmark of application security is the location of trusted state. Security state cannot be sent to the client without some form of integrity promise.

Applications and APIs will be vulnerable if the code:

* The client can create, replay, tamper, or chain existing serialized state (gadgets), AND
* The server or API deserializes hostile objects supplied by an attacker, AND
* The objects contain a constructor, destructor, callbacks, auto-instantiation (such as rehydration calls) OR
* The objects override protected or private member fields that contain sensitive state, such as role or similar

## How do I prevent

* The only safe architectural pattern is to not send or accept serialized objects from untrusted sources

If this not possible

* Implement integrity checks or encryption of the serialized objects to prevent hostile creation, tampering, replay and gadget calls
* Isolate code that deserializes, such that it runs in very low privilege environments, such as temporary containers
* Enforce type constraints over serialized objects; typically code is expecting a particular class
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.

Larger and high performing organizations should also consider:
* Rate limit API or methods that deserialize
* Restrict or monitor incoming and outgoing network connectivity from containers or servers that deserialize
* Monitor deserialization, alerting if a user deserializes constantly.

## References

### OWASP

* [OWASP Proactive Controls - Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard - TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet - Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)

### External

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
