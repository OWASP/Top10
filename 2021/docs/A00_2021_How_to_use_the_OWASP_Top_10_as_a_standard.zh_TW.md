# 如何將 OWASP Top 10 2021 做為標準使用

OWASP Top 10 最主要是一個提升意識形態的文件。但是，從 2003 年開始，這並沒有讓任何的企業或組織停止使用它當作預設的 AppSec 標準。如果你想要用使用 OWASP Top 10 當作程式設計或是驗證測試的一個標準，要先知道這只是一個最低指標並且也只是一個開始。
The OWASP Top 10 is primarily an awareness document. However, this has
not stopped organizations using it as a de facto industry AppSec
standard since its inception in 2003. If you want to use the OWASP Top
10 as a coding or testing standard, know that it is the bare minimum and
just a starting point.

One of the difficulties of using the OWASP Top 10 as a standard is that
we document appsec risks, and not necessarily easily testable issues.
For example, A04:2021-Insecure Design is beyond the scope of most forms
of testing. Another example is testing in place, in use, and effective
logging and monitoring can only be done with interviews and requesting a
sampling of effective incident responses. A static code analysis tool
can look for the absence of logging, but it might be impossible to
determine if business logic or access control is logging critical
security breaches. Penetration testers may only be able to determine
that they have invoked incident response in a test environment, which
are rarely monitored in the same way as production.

Here are our recommendations for when it is appropriate to use the OWASP
Top 10:

| Use Case                | OWASP Top 10 2021 | OWASP Application Security Verification Standard |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| Awareness               | Yes               |                                                  |
| Training                | Entry level       | Comprehensive                                    |
| Design and architecture | Occasionally      | Yes                                              |
| Coding standard         | Bare minimum      | Yes                                              |
| Secure Code review      | Bare minimum      | Yes                                              |
| Peer review checklist   | Bare minimum      | Yes                                              |
| Unit testing            | Occasionally      | Yes                                              |
| Integration testing     | Occasionally      | Yes                                              |
| Penetration testing     | Bare minimum      | Yes                                              |
| Tool support            | Bare minimum      | Yes                                              |
| Secure Supply Chain     | Occasionally      | Yes                                              |

We would encourage anyone wanting to adopt an application security
standard to use the OWASP Application Security Verification Standard
(ASVS), as it’s designed to be verifiable and tested, and can be used in
all parts of a secure development lifecycle.

The ASVS is the only acceptable choice for tool vendors. Tools cannot
comprehensively detect, test, or protect against the OWASP Top 10 due to
the nature of several of the OWASP Top 10 risks, with reference to
A04:2021-Insecure Design. OWASP discourages any claims of full coverage
of the OWASP Top 10, because it’s simply untrue.
