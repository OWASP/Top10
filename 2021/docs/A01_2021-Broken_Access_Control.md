---
source:  "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
title:   "A01:2021 – Broken Access Control"
id:      "A01:2021"
lang:    "en"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".1" -%}
#A01:2021 – Broken Access Control     ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Broken Access Control", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.5" ) }}


## Factors {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## Overview {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Overview", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Moving up from the fifth position, 94% of applications were tested for
some form of broken access control with the average incidence rate of 3.81%, and has the most occurrences in the contributed dataset with over 318k. Notable Common Weakness Enumerations (CWEs) included are *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201:
Insertion of Sensitive Information Into Sent Data*, and *CWE-352:
Cross-Site Request Forgery*.

## Description {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Description", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data or
performing a business function outside the user's limits. Common access
control vulnerabilities include:

-   Violation of the principle of least privilege or deny by default,
    where access should only be granted for particular capabilities,
    roles, or users, but is available to anyone.

-   Bypassing access control checks by modifying the URL (parameter
    tampering or force browsing), internal application state, or the
    HTML page, or by using an attack tool modifying API requests.

-   Permitting viewing or editing someone else's account, by providing
    its unique identifier (insecure direct object references)

-   Accessing API with missing access controls for POST, PUT and DELETE.

-   Elevation of privilege. Acting as a user without being logged in or
    acting as an admin when logged in as a user.

-   Metadata manipulation, such as replaying or tampering with a JSON
    Web Token (JWT) access control token, or a cookie or hidden field
    manipulated to elevate privileges or abusing JWT invalidation.

-   CORS misconfiguration allows API access from unauthorized/untrusted
    origins.

-   Force browsing to authenticated pages as an unauthenticated user or
    to privileged pages as a standard user.

## How to Prevent {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Access control is only effective in trusted server-side code or
server-less API, where the attacker cannot modify the access control
check or metadata.

-   Except for public resources, deny by default.

-   Implement access control mechanisms once and re-use them throughout
    the application, including minimizing Cross-Origin Resource Sharing (CORS) usage.

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

-   Stateful session identifiers should be invalidated on the server after logout.
    Stateless JWT tokens should rather be short-lived so that the window of 
    opportunity for an attacker is minimized. For longer lived JWTs it's highly recommended to
    follow the OAuth standards to revoke access.

Developers and QA staff should include functional access control unit
and integration tests.

## Example Attack Scenarios {{ osib_anchor(osib=osib ~ ".example attack scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Example Attack Scenarios", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

**Scenario #1:** The application uses unverified data in a SQL call that
is accessing account information:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

An attacker simply modifies the browser's 'acct' parameter to send
whatever account number they want. If not correctly verified, the
attacker can access any user's account.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Scenario #2:** An attacker simply forces browses to target URLs. Admin
rights are required for access to the admin page.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```
If an unauthenticated user can access either page, it's a flaw. If a
non-admin can access the admin page, this is a flaw.

## References {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.owasp.opc.3." ~ "7", osib=osib) }} <!-- [OWASP Proactive Controls: Enforce Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls) --> 
-   {{ osib_link(link="osib.owasp.asvs.4-0." ~ "4", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V4 Access Control](https://owasp.org/www-project-application-security-verification-standard) --> 
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.5", osib=osib) }} <!-- [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README) --> 
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Authorization", osib=osib) }} <!-- [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.portswigger.research.articles.exploiting cors misconfigurations for bitcoins and bounties", osib=osib) }} <!--- [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) --->
-   {{ osib_link(link="osib.oauth.oauth2 servers.listing authorizations.revoking access", osib=osib) }} <!--- [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/) --->

## List of Mapped CWEs {{ osib_anchor(osib=osib ~ ".mapped cwes", id=id ~ "-mapped_cwes", name=title ~ ": List of Mapped CWEs", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.22", doc="", osib=osib) }} <!-- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html) --> 
-   {{ osib_link(link="osib.mitre.cwe.0.23", doc="", osib=osib) }} <!-- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.35", doc="", osib=osib) }} <!-- [CWE-35: Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.59", doc="", osib=osib) }} <!-- [CWE-59: Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.200", doc="", osib=osib) }} <!-- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.201", doc="", osib=osib) }} <!-- [CWE-201: Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.219", doc="", osib=osib) }} <!-- [CWE-219: Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.264", doc="", osib=osib) }} <!-- [CWE-264: Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.275", doc="", osib=osib) }} <!-- [CWE-275: Permission Issues](https://cwe.mitre.org/data/definitions/275.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.276", doc="", osib=osib) }} <!-- [CWE-276: Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.284", doc="", osib=osib) }} <!-- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.285", doc="", osib=osib) }} <!-- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.352", doc="", osib=osib) }} <!-- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.359", doc="", osib=osib) }} <!-- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.377", doc="", osib=osib) }} <!-- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.402", doc="", osib=osib) }} <!-- [CWE-402: Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.425", doc="", osib=osib) }} <!-- [CWE-425: Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.441", doc="", osib=osib) }} <!-- [CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.497", doc="", osib=osib) }} <!-- [CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.538", doc="", osib=osib) }} <!-- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.540", doc="", osib=osib) }} <!-- [CWE-540: Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.548", doc="", osib=osib) }} <!-- [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.552", doc="", osib=osib) }} <!-- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.566", doc="", osib=osib) }} <!-- [CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.601", doc="", osib=osib) }} <!-- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.639", doc="", osib=osib) }} <!-- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.651", doc="", osib=osib) }} <!-- [CWE-651: Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.668", doc="", osib=osib) }} <!-- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.706", doc="", osib=osib) }} <!-- [CWE-706: Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.862", doc="", osib=osib) }} <!-- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.863", doc="", osib=osib) }} <!-- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.913", doc="", osib=osib) }} <!-- [CWE-913: Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.922", doc="", osib=osib) }} <!-- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1275", doc="", osib=osib) }} <!-- [CWE-1275: Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html) -->
