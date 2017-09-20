# A2 Authentication and Session Management

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

## Am I vulnerable to attack?

Are session management assets like user credentials and session IDs properly protected? You may be vulnerable if:

* User authentication credentials aren’t properly protected when stored using hashing or encryption. See 2017-A6.
* Credentials can be guessed or overwritten through weak account management functions (e.g., account creation, change password, recover password, weak session IDs).
* Session IDs are exposed in the URL (e.g., URL rewriting).
* Session IDs are vulnerable to session fixation attacks.
* Session IDs don’t timeout, or user sessions or authentication tokens (particularly single sign-on (SSO) tokens) aren’t properly invalidated during logout.
* Session IDs aren’t rotated after successful login.
* Passwords, session IDs, and other credentials are sent over unencrypted connections. See 2017-A6.

See the ASVS requirement areas V2 and V3 for more details.

## How do I prevent

The primary recommendation for an organization is to make available to developers:

* A single set of strong authentication and session management controls. Such controls should strive to:
* meet all the authentication and session management requirements defined in OWASP’s Application Security Verification Standard (ASVS) areas V2 (Authentication) and V3 (Session Management).
* have a simple interface for developers. 

## Example Scenarios

Scenario #1: A travel reservations application supports URL rewriting, putting session IDs in the URL:

<code>
  http://example.com/sale/saleitems;jsessionid=2P0OC2JSNDLPSKHCJUN2JV&amp;dest=Hawaii
</code>

An authenticated user of the site wants to let their friends know about the sale. User e-mails the above link without knowing they are also giving away their session ID. When the friends use the link they use user’s session and credit card.

Scenario #2: Application’s timeouts aren’t set properly. User uses a public computer to access site. Instead of selecting “logout” the user simply closes the browser tab and walks away. An attacker uses the same browser an hour later, and that browser is still authenticated.

Scenario #3: An insider or external attacker gains access to the system’s password database. User passwords are not properly hashed and salted, exposing every users’ password.

## References

### OWASP 
* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide: Authentication]()
* [OWASP Authentication Cheat Sheet]()
* [OWASP Forgot Password Cheat Sheet]()
* [OWASP Password Storage Cheat Sheet]()
* [OWASP Session Management Cheat Sheet]()

### External
* [CWE Entry 287 on Improper Authentication]()
* [CWE Entry 384 on Session Fixation]()
