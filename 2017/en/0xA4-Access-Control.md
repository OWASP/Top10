# A3 Access Control

| Threat agents | Exploitability | Prevalance | Detectability | Technical Impact | Business Impacts |
| --- | --- | --- | --- | --- | --- |
| App Specific |  EASY | COMMON | AVERAGE | SEVERE | App Specific | 
| TBA | TBA | TBA | TBA. | TBA |

## Am I vulnerable to attack?

The best way to find out if an application is vulnerable to access control vulnerabilities is to verify that all data and function references have appropriate defenses. To determine if you are vulnerable, consider:
For data references, does the application ensure the user is authorized by using a reference map or access control check to ensure the user is authorized for that data?

For non-public function requests, does the application ensure the user is authenticated, and has the required roles or privileges to use that function?

Code review of the application can verify whether these controls are implemented correctly and are present everywhere they are required. Manual testing is also effective for identifying access control flaws. Automated tools typically do not look for such flaws because they cannot recognize what requires protection or what is safe or unsafe.

## How do I prevent

Preventing access control flaws requires selecting an approach for protecting each function and each type of data (e.g., object number, filename).

Check access. Each use of a direct reference from an untrusted source must include an access control check to ensure the user is authorized for the requested resource.

Use per user or session indirect object references. This coding pattern prevents attackers from directly targeting unauthorized resources. For example, instead of using the resource’s database key, a drop down list of six resources authorized for the current user could use the numbers 1 to 6 to indicate which value the user selected. 

Automated verification. Leverage automation to verify proper authorization deployment. This is often custom.

## Example Scenarios

Scenario #1: The application uses unverified data in a SQL call that is accessing account information:

<code>
  pstmt.setString( 1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery( );
</code>

An attacker simply modifies the ‘acct’ parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user’s account.

* [http://example.com/app/accountInfo?acct=notmyacct]()

Scenario #2: An attacker simply force browses to target URLs. Admin rights are also required for access to the admin page.

* [http://example.com/app/getappInfo](http://example.com/app/getappInfo)  
* [http://example.com/app/admin_getappInfo](http://example.com/app/admin_getappInfo)

If an unauthenticated user can access either page, it’s a flaw. If a non-admin can access the admin page, this is also a flaw.

## References

### OWASP

* [OWASP Proactive Controls - TBA]()
* [OWASP Application Security Verification Standard - TBA]()
* [OWASP Testing Guide - TBA]()
* [OWASP Cheat Sheet - TBA]()

### External

* CWE Entry 285 on Improper Access Control (Authorization)
* CWE Entry 639 on Insecure Direct Object References
* CWE Entry 22 on Path Traversal (an example of a Direct Object Reference weakness)
