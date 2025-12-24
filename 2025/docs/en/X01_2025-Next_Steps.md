<link rel="stylesheet" href="../assets/css/RC-stylesheet.css" />

# Next Steps

By design, the OWASP Top 10 is innately limited to the ten most significant risks. Every OWASP Top 10 has “on the cusp” risks considered at length for inclusion, but in the end, didn't make the cut. The other risks were more prevalent and impactful.

The following two issues are well worth the effort to identify and remediate, organizations working towards a mature appsec program, security consultancies, or tool vendors wishing to expand coverage for their offerings.


## X01:2025 Lack of Application Resilience

### Background. 

This is a renaming of 2021’s Denial of Service. That was renamed as it described a symptom rather than a root cause. This category focuses on CWEs that describe weaknesses that are related to resilience issues. The scoring of this category was very close with A10:2025-Mishandling of Exceptional Conditions. Relevant CWEs include: *CWE-400 Uncontrolled Resource Consumption, CWE-409 Improper Handling of Highly Compressed Data (Data Amplification), CWE-674 Uncontrolled Recursion*, and *CWE-835 Loop with Unreachable Exit Condition ('Infinite Loop').*


### Score table.


<table>
  <tr>
   <td>CWEs Mapped 
   </td>
   <td>Max Incidence Rate
   </td>
   <td>Avg Incidence Rate
   </td>
   <td>Max Coverage
   </td>
   <td>Avg Coverage
   </td>
   <td>Avg Weighted Exploit
   </td>
   <td>Avg Weighted Impact
   </td>
   <td>Total Occurrences
   </td>
   <td>Total CVEs
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>20.05%
   </td>
   <td>4.55%
   </td>
   <td>86.01%
   </td>
   <td>41.47%
   </td>
   <td>7.92
   </td>
   <td>3.49
   </td>
   <td>865,066
   </td>
   <td>4,423
   </td>
  </tr>
</table>



### Description. 

This category represents a systemic weakness in how applications respond to stress, failures, and edge cases that it is unable to recover from failure. When an application does not gracefully handle, withstand, or recover from unexpected conditions, resource constraints, and other adverse events it can easily result in availability issues (most commonly), but also data corruption, sensitive data disclosure, cascading failures, and/or bypasses of security controls.

Furthermore [X02:2025 Memory Management Failures](#x022025-memory-management-failures) can also lead to failure of the application or even the entire system.

### How to prevent 

In order to prevent this type of vulnerability you must design for failure and recovery of your systems.

* Add limits, quotas, and failover functionality, paying special attention to the most resource consuming operations
* Identify resource intensive pages and plan ahead: Reduce attack surface especially not exposing unneeded ‘gadgets’ and functions that require a lot of resources (e.g. CPU, memory) to unknown or untrusted users
* Perform strict input validation with allow-lists and size limitations, then test thoroughly
* Limit response sizes, and never send raw responses back to the client (process on the server side)
* Default to safe/closed (never open), deny by default and roll back if there’s an error
* Avoid blocking synchronous calls in request threads (use asynchronous/non-blocking, have timeouts, have concurrency limits, etc.)
* Carefully test your error handling functionality
* Implement resilience patterns such as circuit breakers, bulkheads, retry logic, and graceful degradation
* Do performance and load testing; add chaos engineering if you have the risk appetite for it
* Implement and architect for redundancy where reasonable and affordable
* Implement monitoring, observability, and alerting
* Filter invalid sender addresses in accordance with RFC 2267
* Block known botnets by finger prints, IPs, or dynamically by behavior
* Proof-of-Work: initiate resource consuming operations at the *attackers* side that does not have big impacts on normal users but impacts bots trying to send a huge amount of requests. Make the Proof-of-Work more difficult if the general load of the system raises, especially for systems that are less trustworthy or appear to be bots
* Limit server side session time based on inactivity and a final timeout
* Limit session bound information storage


### Example attack scenarios. 

**Scenario #1:** Attackers intentionally consume application resources to trigger failures within the system, resulting in denial of service. This could be memory exhaustion, filling up disk space, CPU saturation, or opening endless connections.

**Scenario #2:** Input fuzzing that leads to crafted responses that break application business logic.

**Scenario #3:** Attackers focus on the application’s dependencies, taking down APIs or other external services, and the application is unable to continue.


### References.

* [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### List of Mapped CWEs
* [CWE-73  External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)
* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)
* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)
* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)
* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)
* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)
* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)
* [CWE-653 Improper Isolation or Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)
* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)
* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)


## X02:2025 Memory Management Failures

### Background. 

Languagess like Java, C#, JavaScript/TypeScript (node.js), Go, and "safe" Rust are memory safe. Memory management problems tend to happen in non-memory safe languages such as C and C++. This category scored the lowest on the community survey and low in the data despite having the third most related CVEs. We believe this is due to the predominance of web applications over more traditional desktop applications. Memory management vulnerabilities frequently have the highest CVSS scores. 


### Score table.


<table>
  <tr>
   <td>CWEs Mapped 
   </td>
   <td>Max Incidence Rate
   </td>
   <td>Avg Incidence Rate
   </td>
   <td>Max Coverage
   </td>
   <td>Avg Coverage
   </td>
   <td>Avg Weighted Exploit
   </td>
   <td>Avg Weighted Impact
   </td>
   <td>Total Occurrences
   </td>
   <td>Total CVEs
   </td>
  </tr>
  <tr>
   <td>24
   </td>
   <td>2.96%
   </td>
   <td>1.13%
   </td>
   <td>55.62%
   </td>
   <td>28.45%
   </td>
   <td>6.75
   </td>
   <td>4.82
   </td>
   <td>220,414
   </td>
   <td>30,978
   </td>
  </tr>
</table>



### Description. 

When an application is forced to manage memory itself, it is very easy to make mistakes. Memory safe languages are being used more often, but there are still many legacy systems in production worldwide, new low-level systems that require the use of non-memory safe languages, and web applications that interact with mainframes, IoT devices, firmware, and other systems that may be forced to manage their own memory. Representative CWEs are *CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')* and *CWE-121 Stack-based Buffer Overflow*.

Memory management failures can happen when:

* You do not allocate enough memory for a variable
* You do not validate input, causing an overflow of the heap, the stack, a buffer
* You store a data value that is larger than the type of the variable can hold 
* You attempt to use unallocated memory or address spaces
* You create off-by-one errors (counting from 1 instead of zero)
* You try to access an object after its been freed
* You use uninitialized variables
* You leak memory or otherwise use up all available memory in error until our application fails

Memory management failures can lead to failure of the application or even the entire system, see also [X01:2025 Lack of Application Resilience](#x012025-lack-of-application-resilience)


### How to prevent. 

The best way to prevent memory management failures is to use a memory-safe language. Examples include Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript, etc. When creating new applications, try hard to convince your organization that it is worth the learning curve to switch to a memory-safe language. If performing a full refactor, push for a rewrite in a memory-safe language when it is possible and feasible.

If you are unable to use a memory-safe language, perform the following:

* Enable the following server features that make memory management errors harder to exploit: address space layout randomization (ASLR), Data Execution Protection (DEP), and Structured Exception Handling Overwrite Protection (SEHOP).
* Monitor your application for memory leaks.
* Validate all input to your system very carefully, and reject all input that does not meet expectations.
* Study the language you are using and make a list of unsafe and more-safe functions, then share that list with your entire team. If possible, add it to your secure coding guideline or standard. For example, in C, prefer strncpy() over strcpy() and strncat() over strcat().
* If your language or framework offers memory safety libraries, use them. For example: Safestringlib or SafeStr.
* Use managed buffers and strings rather than raw arrays and pointers whenever possible.
* Take secure coding training that focuses on memory issues and/or your language of choice. Inform your trainer that you are concerned about memory management failures.
* Perform code reviews and/or static analyses.
* Use compiler tools that help with memory management such as StackShield, StackGuard, and Libsafe.
* Perform fuzzing on every input to your system.
* If you have a penetration test performed, inform your tester that you are concerned about memory management failures and that you would like them to pay special attention to this while testing.
*  Fix all compiler errors *and* warnings. Do not ignore warnings because your program compiles.
* Ensure your underlying infrastructure is regularly patched, scanned, and hardened.
* Monitor your underlying infrastructure specifically for potential memory vulnerabilities and other failures.
* Consider using [canaries](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) to protect your address stack from overflow attacks.

### Example attack scenarios. 

**Scenario #1:** Buffer overflows are the most famous memory vulnerability, a situation where an attacker submits more information into a field than it can accept, such that it overflows the buffer created for the underlying variable. In a successful attack, the overflow characters overwrite the stack pointer, allowing the attacker to insert malicious instructions into your program.

**Scenario #2:** Use-After-Free (UAF) happens often enough that it’s a semi-common browser bug bounty submission. Imagine a web browser processing JavaScript that manipulates DOM elements. The attacker crafts a JavaScript payload that creates an object (such as a DOM element) and obtains references to it. Through careful manipulation, they trigger the browser to free the object's memory while keeping a dangling pointer to it. Before the browser realizes the memory has been freed, the attacker allocates a new object that occupies the *same* memory space. When the browser tries to use the original pointer, it now points to attacker-controlled data. If this pointer was for a virtual function table, the attacker can redirect code execution to their payload. 

**Scenario #3:** A network service that accepts user input, doesn’t properly validate or sanitize it, then passes it directly to the logging function. The input from the user is passed to the logging function as syslog(user_input) instead of syslog("%s", user_input), which doesn’t specify the format. The attacker sends malicious payloads containing format specifiers such as %x to read stack memory (sensitive data disclosure) or %n to write to memory addresses. By chaining together multiple format specifiers they could map out the stack, locate important addresses, and then overwrite them. This would be a Format string vulnerability (uncontrolled string format). 

Note: modern browsers use many levels of defenses to defend against such attacks, including [browser sandboxing](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing) ASLR, DEP/NX, RELRO, and PIE. A memory management failure attack on a browser is not a simple attack to carry out.

### References.

* [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### List of Mapped CWEs
* [CWE-14 Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
* [CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-124 Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html)
* [CWE-125 Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-126 Buffer Over-read](https://cwe.mitre.org/data/definitions/126.html)
* [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-191 Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
* [CWE-196 Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html)
* [CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
* [CWE-415 Double Free](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-457 Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
* [CWE-459 Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
* [CWE-467 Use of sizeof() on a Pointer Type](https://cwe.mitre.org/data/definitions/467.html)
* [CWE-787 Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
* [CWE-788 Access of Memory Location After End of Buffer](https://cwe.mitre.org/data/definitions/788.html)
* [CWE-824 Access of Uninitialized Pointer](https://cwe.mitre.org/data/definitions/824.html)



## X03:2025 Inappropriate Trust in AI Generated Code ('Vibe Coding')

### Background.

Currently the entire world is talking about and using AI, and this includes software developers. Although there are currently no CVEs or CWEs related to AI generated code, it is well known and documented that AI generated code often contains more vulnerabilities than code written by human beings.


### Description.

We are seeing software development practices change to include not only code written with the assistance of AI, but code written and committed almost entirely without human oversight (often referred to as vibe coding). Just as it was never a good idea to copy code snippets from blogs or websites without thinking twice, the problem is exacerbated in this case. Good, secure code snippets were and are rare and might be statistically neglected by AI due to system constraints.


### How to prevent.
We urge all people who write code to consider the following when using AI:

* You should be able to read and fully understand all code you submit, even if it is written by an AI or copied from an online forum. You are responsible for all code that you commit.
* You should review all AI-assisted code thoroughly for vulnerabilities, ideally with your own eyes and also with security tooling made for this purpose (such as static analysis). Consider using classic code review techniques as described in [OWASP Cheat Sheet Series: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
* Ideally, write your own code, let the AI suggest improvements, check the AI's code, and let the AI make corrections until you are satisfied with the result.
* Consider using a Retrieval Augmented Generation (RAG) server with your own collected  and reviewed secure code samples and documentation, such as your organization’s security coding guideline, standard, or policy, and have the RAG server enforce any policies or standards.
* Consider purchasing tooling that implements guardrails for privacy and security for use with your AI(s) of choice.
* Consider purchasing a private AI, ideally with a contract agreement (including a privacy agreement) that the AI is not to be trained on your organization’s data, queries, code or any other sensitive information.
* Consider implementing an Model Context Protocol (MCP) server in-between your IDE and AI, then set it up to enforce the use of your security tooling of choice.
* Implement policies and processes as part of your SDLC to inform developers (and all employees) of how they should and should not use AI within your organization.
* Create a list of good and effective prompts, that take IT security best practices into account. Ideally they should also consider your internal secure coding guidelines. Developers can use this prompts as a starting point for their programs.
* AI is likely to become part of each phase of your system development life cycle, both how to use it effectively and safely. Use it wisely.
* Actually it is **<u>not</u>** recommended to use vibe coding for complex functions, business critical programs, or programs that are used for a long time.
* Implement technical checks and safeguards against the use of Shadow AI.
* Train your developers on your policies, as well as safe AI usage and best practices for using AI in software development.


### References.

* [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


### List of Mapped CWEs
-none-
