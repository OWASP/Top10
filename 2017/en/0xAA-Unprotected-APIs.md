# A10 Underprotected APIs

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |
 

## Am I vulnerable to attack?

Testing your APIs for vulnerabilities should be similar to testing the rest of your application for vulnerabilities. All the different types of injection, authentication, access control, encryption, configuration, and other issues can exist in APIs just as in a traditional application.

However, because APIs are designed for use by programs (not humans) they frequently lack a UI and also use complex protocols and complex data structures. These factors can make security testing difficult. The use of widely-used formats can help, such as Swagger (OpenAPI), REST, JSON, and XML. Some frameworks like GWT and some RPC implementations use custom formats. Some applications and APIs create their own protocol and data formats, like WebSockets. The breadth and complexity of APIs make it difficult to automate effective security testing, possibly leading to a false sense of security.

Ultimately, knowing if your APIs are secure means carefully choosing a strategy to test all defenses that matter.


## How do I prevent this?

The key to protecting APIs is to ensure that you fully understand the threat model and what defenses you have:

* Ensure that you have secured communications between the client and your APIs.
* Ensure that you have a strong authentication scheme for your APIs, and that all credentials, keys, and tokens have been secured.
* Ensure that whatever data format your requests use, that the parser configuration is hardened against attack.
* Implement an access control scheme that protects APIs from being improperly invoked, including unauthorized function and data references.
* Protect against injection of all forms, as these attacks are just as viable through APIs as they are for normal apps.

Be sure your security analysis and testing covers all your APIs and your tools can discover and analyze them all effectively.


## Example Attack Scenarios

Scenario #1: Imagine a mobile banking app that connects to an XML API at the bank for account information and performing transactions. The attacker reverse engineers the app and discovers that the user account number is passed as part of the authentication request to the server along with the username and password. The attacker sends legitimate credentials, but another user’s account number, gaining full access to the other user’s account.

Scenario #2: Imagine a public API offered by an Internet startup for automatically sending text messages. The API accepts JSON messages that contain a “transactionid” field. The API parses out this “transactionid” value as a string and concatenates it into a SQL query, without escaping or parameterizing it. As you can see the API is just as susceptible to SQL injection as any other type of application.

In either of these cases, the vendor may not provide a web UI to use these services, making security testing more difficult.

## References

### OWASP
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()
* [OWASP REST Security Cheat Sheet](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet)
* [OWASP Web Service Security Cheat Sheet](https://www.owasp.org/index.php/Web_Service_Security_Cheat_Sheet)

### External

* [Increasing Importance of APIs in Web Development](https://code.tutsplus.com/articles/the-increasing-importance-of-apis-in-web-development--net-22368)
* [Tracking the Growth of the API Economy](http://nordicapis.com/tracking-the-growth-of-the-api-economy/)
* [The API Centric Future](https://techcrunch.com/2015/09/27/the-future-of-coding-is-here-and-threatens-to-wipe-out-everything-in-its-path/)
* [The Growth of the API](https://www.cronofy.com/blog/the-growth-of-the-api/)
* [What Do You Mean My Security Tools Don’t Work on APIs?!!](http://www.darkreading.com/application-security/what-do-you-mean-my-security-tools-dont-work-on-apis!!/a/d-id/1321050)
* [State of API Security](https://www.soapui.org/testing-dojo/world-of-api-testing/state-of-api-security.html)
