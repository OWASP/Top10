# A5:2017 Broken Access Control

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 2 \| Detectability 2 | Technical 3 \| Business |
| Exploitation of access control is a core skill of penetration testers. SAST and DAST tools can detect the absence of access control, but not verify if it is functional. Access control is detectable using manual means, or possibly through automation for the absence of access controls in certain frameworks. | Access control weaknesses are common due to the lack of automated detection, and lack of effective functional testing by application developers. Access control detection is not typically amenable to automated static or dynamic testing. | The technical impact is anonymous attackers acting as users or administrators, users using privileged functions, or creating, accessing, updating or deleting every record. |

## Is the Application Vulnerable?

Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside of the limits of the user. Common access control vulnerabilities include:

* Bypassing access control checks by modifying the URL, internal app state, or the HTML page, or simply using a custom API attack tool.
* Allowing the primary key to be changed to another's users record, such as viewing or editing someone else's account.
* Elevation of privilege. Acting as a user without being logged in, or acting as an admin when logged in as a user.
* Metadata manipulation, such as replaying or tampering with a JWT access control token or a cookie or hidden field manipulated to elevate privileges.
* CORS misconfiguration allows unauthorized API access
* Force browsing to authenticated pages as an unauthenticated user, or to privileged pages as a standard user or API not enforcing access controls for POST, PUT and DELETE

## How To Prevent?

Access control is only effective if enforced in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata.

* With the exception of public resources, deny by default.
Implement access control mechanisms once and re-use them throughout the application.
* Model access controls should enforce record ownership, rather than accepting that the user can create, read, update or delete any record.
* Domain access controls are unique to each application, but business limit requirements should be enforced by domain models
* Disable web server directory listing, and ensure file metadata such (e.g. .git) is not present within web roots
* Log access control failures, alert admins when appropriate (e.g. repeated failures)
* Rate limiting API and controller access to minimize the harm from automated attack tooling
* Developers and QA staff should include functional access control unit and integration tests.

## Example Attack Scenarios

**Scenario #1**: The application uses unverified data in a SQL call that is accessing account information:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery( );
```

An attacker simply modifies the 'acct' parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user's account.

* `http://example.com/app/accountInfo?acct=notmyacct`

**Scenario #2**:  An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.

* `http://example.com/app/getappInfo`
* `http://example.com/app/admin_getappInfo`

If an unauthenticated user can access either page, it's a flaw. If a non-admin can access the admin page, this is a flaw.

## References

### OWASP

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Access Control](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### External

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')]()
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [Portswigger: Exploiting CORS misconfiguration](http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
