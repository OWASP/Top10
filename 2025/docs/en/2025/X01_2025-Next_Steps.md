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

Furthermore [X2:2025 Memory Management Errors](2025/X1_2025-Next_Steps#X2:2025 Memory Management Failures) can also lead to failure of the application or even the entire system. 

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

* [Denial of Service - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) \
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [Awesome Fuzzing](https://github.com/secfigo/Awesome-Fuzzing) - an excellent resource on all things fuzzing
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Divlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

## X02:2025 Memory Management Failures

### Background. 

Web applications tend to be written in managed memory languages, such as Java, .NET, or node.js (JavaScript or TypeScript). However, these languages are written in systems languages that have memory management issues, such as buffer or heap overflows, use after free, integer overflows, and more. There have been many sandbox escapes over the years that prove that just because the web application language is nominally memory “safe,” the foundations are not. This category scored the lowest on the community survey and low in the data despite having the third most related CVEs. We believe this is due to the predominance of web applications over more traditional desktop applications, and explains why it is treated differently than in the MITRE Top 25.


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

When an application is forced to manage memory itself, it is very easy to make mistakes. Memory safe languages are being used more often, but there are still many legacy systems in production worldwide, new low-level systems that require the use of non-memory safe languages, and web applications that interact with mainframes, IoT devices, firmware, and other systems that may be forced to manage their own memory.

 

Memory management failures can happen when:



* We do not allocate enough memory for a variable
*  We overflow the heap, stack, buffer or a string, integer, floats or arrays by putting more into them than they can accommodate (variable types have limits) or more than has been allocated (heap, stack, buffers)
* We attempt to use unallocated memory or address spaces
* We create off-by-one errors (counting from 1 instead of zero)
*  We try to access an object after we’ve freed it (deleted it’s address in memory)
* We use uninitialized variables
* We leak memory or otherwise use up all available memory in error until our application fails

Memory management failures can lead to failure of the application or even the entire system, see also [‘XL01:2025 Lack of Application Resilience’](?tab=t.q1uzy1q9mmu)


### How to prevent. 

The best way to prevent memory management failures is to use a memory-safe language. Examples include Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript, etc. If creating net-new applications, try hard to convince your organization that it is worth the learning curve to switch to a memory-safe language. If performing a full refactor, push for a rewrite in a memory-safe language if possible or reasonable.

If you are unable to use a memory-safe language, perform the following:



* Enable the following server features: address space layout randomization (ASLR), Data Execution Protection (DEP), and Structured Exception Handling Overwrite Protection (SEHOP)
* Monitor your application for memory leaks
* Validate all input to your system very carefully, and reject all input that does not meet expectations
* Study the language you are using and make a list of unsafe and more-safe functions, then share that list with your entire team. If possible, add it to your secure coding guideline or standard. For example, in C, prefer strncpy() over strcpy() and strncat() over strcat().
* If your language or framework offers memory safety libraries, use them. For example: Safestringlib or SafeStr
* Use managed buffers and strings rather than raw arrays and pointers if possible
* Take secure coding training that focuses on memory issues and/or your language of choice. Inform your trainer that you are concerned about memory management failures
* Perform code review and/or static analysis
* Use compiler tools that help with memory management such as StackShield, StackGuard, and Libsafe
* Perform fuzzing on every input to your system
* If you have a penetration test performed, inform your tester that you are concerned about memory management failures and that you would like them to pay special attention to this while testing
*  Fix all compiler errors *and* warnings. Do not ignore warnings because your program compiles.
* Ensure your underlying infrastructure is regularly patched, scanned, and hardened
* Monitor your underlying infrastructure specifically for potential memory vulnerabilities and other failures

         Consider using canaries to protect your address stack from overflow attacks



### Example attack scenarios. 

**Scenario #1:** Buffer overflows are the most famous memory vulnerability, a situation where an attacker submits more information into a field than it can accept, such that it overflows the buffer created for the underlying variable. In a successful attack, the overflow characters overwrite the stack pointer, giving the program new instructions, which are malicious. The overflow characters include shellcode, which contains the attack.

**Scenario #2:** Use-After-Free (UAF) is another attack scenario that happens often enough that it’s a semi-common browser bug bounty submission. Imagine a web browser processing JavaScript that manipulates DOM elements. The attacker crafts a JavaScript payload that creates an object (such as a DOM element) and obtains references to it. Through careful manipulation, they trigger the browser to free the object's memory while keeping a dangling pointer to it. Before the browser realizes the memory has been freed, the attacker allocates a new object of the *same* size to occupy that *same* memory space. When the browser tries to use the original pointer, it now points to attacker-controlled data. If this pointer was for a virtual function table, the attacker can redirect code execution to their payload. 

**Scenario #3:** A network service that accepts user input, doesn’t properly validate or sanitize it, then passes it directly to the logging function. The input from the user is passed to the logging function as syslog(user_input) instead of syslog("%s", user_input), which doesn’t specify the format. The attacker sends malicious payloads containing format specifiers such as %x to read stack memory (sensitive data disclosure) or %n to write to memory addresses. By chaining together multiple format specifiers they could map out the stack, locate important addresses, and then overwrite them. This would be a Format string vulnerability (uncontrolled string format). 

Note: modern browsers use many levels of defenses to defend against such attacks, including ASLR, DEP/NX, RELRO and PIE. These are not simple attacks to carry out.


### References.

OWASP: Memory leak, Doubly freeing memory, & Buffer Overflow community pages

Alice and Bob Learn Secure Coding

Project Zero Blog

Microsoft MSRC Blog
