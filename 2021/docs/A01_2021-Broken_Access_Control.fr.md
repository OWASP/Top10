# A01 2021 contrôle d'accès cassé

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 94.55%       | 47.72%       | 6.92                 | 5.93                | 318,487           | 19,013     |

## Overview

Moving up from the fifth position, 94% of applications were tested for
some form of broken access control. Notable CWEs included are *CWE-200:
Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201:
Exposure of Sensitive Information Through Sent Data*, and *CWE-352:
Cross-Site Request Forgery*.

## Description

Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data or
performing a business function outside the user's limits. Common access
control vulnerabilities include:

-   Bypassing access control checks by modifying the URL, internal
    application state, or the HTML page, or simply using a custom API
    attack tool.

-   Allowing the primary key to be changed to another user's record,
    permitting viewing or editing someone else's account.

-   Elevation of privilege. Acting as a user without being logged in or
    acting as an admin when logged in as a user.

-   Metadata manipulation, such as replaying or tampering with a JSON
    Web Token (JWT) access control token, or a cookie or hidden field
    manipulated to elevate privileges or abusing JWT invalidation.

-   CORS misconfiguration allows unauthorized API access.

-   Force browsing to authenticated pages as an unauthenticated user or
    to privileged pages as a standard user. Accessing API with missing
    access controls for POST, PUT and DELETE.

## How to Prevent

Access control is only effective in trusted server-side code or
server-less API, where the attacker cannot modify the access control
check or metadata.

-   Except for public resources, deny by default.

-   Implement access control mechanisms once and re-use them throughout
    the application, including minimizing CORS usage.

-   Model access controls should enforce record ownership rather than
    accepting that the user can create, read, update, or delete any
    record.

-   Unique application business limit requirements should be enforced by
    domain models.

-   Disable web server directory listing and ensure file metadata (e.g.,
    .git) and backup files are not present within web roots.

-   Log access control failures, alert admins when appropriate (e.g.,
    repeated failures).

-   Rate limit API and controller access to minimize the harm from
    automated attack tooling.

-   JWT tokens should be invalidated on the server after logout.

Developers and QA staff should include functional access control unit
and integration tests.

## Example Attack Scenarios

**Scenario #1:** The application uses unverified data in a SQL call that
is accessing account information:

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

An attacker simply modifies the browser's 'acct' parameter to send
whatever account number they want. If not correctly verified, the
attacker can access any user's account.

https://example.com/app/accountInfo?acct=notmyacct

**Scenario #2:** An attacker simply forces browses to target URLs. Admin
rights are required for access to the admin page.

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

If an unauthenticated user can access either page, it's a flaw. If a
non-admin can access the admin page, this is a flaw.

## References

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control]()

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## List of Mapped CWEs

CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')

CWE-23 Relative Path Traversal

CWE-35 Path Traversal: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

CWE-201 Exposure of Sensitive Information Through Sent Data

CWE-219 Storage of File with Sensitive Data Under Web Root

CWE-264 Permissions, Privileges, and Access Controls (should no longer
be used)

CWE-275 Permission Issues

CWE-276 Incorrect Default Permissions

CWE-284 Improper Access Control

CWE-285 Improper Authorization

CWE-352 Cross-Site Request Forgery (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized
Actor

CWE-377 Insecure Temporary File

CWE-402 Transmission of Private Resources into a New Sphere ('Resource
Leak')

CWE-425 Direct Request ('Forced Browsing')

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

CWE-497 Exposure of Sensitive System Information to an Unauthorized
Control Sphere

CWE-538 Insertion of Sensitive Information into Externally-Accessible
File or Directory

CWE-540 Inclusion of Sensitive Information in Source Code

CWE-548 Exposure of Information Through Directory Listing

CWE-552 Files or Directories Accessible to External Parties

CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key

CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

CWE-639 Authorization Bypass Through User-Controlled Key

CWE-651 Exposure of WSDL File Containing Sensitive Information

CWE-668 Exposure of Resource to Wrong Sphere

CWE-706 Use of Incorrectly-Resolved Name or Reference

CWE-862 Missing Authorization

CWE-863 Incorrect Authorization

CWE-913 Improper Control of Dynamically-Managed Code Resources

CWE-922 Insecure Storage of Sensitive Information

CWE-1275 Sensitive Cookie with Improper SameSite Attribute
