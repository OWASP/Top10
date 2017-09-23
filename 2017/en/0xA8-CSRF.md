# A8 Cross site request forgery

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

## Am I vulnerable to CSRF

To check whether an application is vulnerable, see if any links and forms lack an unpredictable CSRF token. Without such a token, attackers can forge malicious requests.  An alternate defense is to require the user to prove they intended to submit the request, such as through reauthentication.

Focus on the links and forms that invoke state-changing functions, since those are the most important CSRF targets. Multistep transactions are not inherently immune. Also be aware that Server-Side Request Forgery (SSRF) is also possible by tricking apps and APIs into generating arbitrary HTTP requests.

Note that session cookies, source IP addresses, and other information automatically sent by the browser don’t defend against CSRF since they are included in the forged requests.
OWASP’s CSRF Tester tool can help generate test cases to demonstrate the dangers of CSRF flaws.

## How do I prevent

The preferred option is to use an existing CSRF defense. Many frameworks now include built in CSRF defenses, such as Spring, Play, Django, and AngularJS. Some web development languages, such as .NET do so as well. OWASP’s CSRF Guard can automatically add CSRF defenses to Java apps. OWASP’s CSRFProtector does the same for PHP or as an Apache filter.

Otherwise, preventing CSRF usually requires the inclusion of an unpredictable token in each HTTP request. Such tokens should, at a minimum, be unique per user session.

The preferred option is to include the unique token in a hidden field. This includes the value in the body of the HTTP request, avoiding its exposure in the URL.

The unique token can also be included in the URL or a parameter. However, this runs the risk that the token will be exposed to an attacker.
Consider using the “SameSite=strict” flag on all cookies, which is increasingly supported in browsers.


## Example Attack Scenarios

The application allows a user to submit a state changing request that does not include anything secret. For example:

* [http://example.com/app/transferFunds?amount=1500&destinationAccount=4673243243]()

So, the attacker constructs a request that will transfer money from the victim’s account to the attacker’s account, and then embeds this attack in an image request or iframe stored on various sites under the attacker’s control:

<code>
  &lt;img src="http://example.com/app/transferFunds?amount=1500&destinationAccount=attackersAcct#" width="0" height="0" /&gt;
</code>

If the victim visits any of the attacker’s sites while already authenticated to example.com, these forged requests will automatically include the user’s session info, authorizing the attacker’s request.

## References

### OWASP

* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()

### External

* CWE Entry 352 on CSRF
