# A7 TBA

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

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
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()

### External

TBA
