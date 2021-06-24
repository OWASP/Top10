As organizations and people work toward submitting data for the Top 10 project, one of the pieces that can be difficult is mapping our findings to the CWE list.   While many HAT systems do this automatically, TAH groups may not have this information prebuilt.   The list below is an attempt to gather sample lists of CWEs related to Top 10-like vulnerabilities to ease the collation of data.   While not comprehensive, and we encourage submissions to build this better, it is hopefully a start to our work.

One source of a easier to follow list of CWEs is at https://cwe.mitre.org/data/definitions/2000.html		
		

CWE ID	| CWE Name
------------ | -------------
20 | Improper Input Validation
22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
77 | Improper Neutralization of Special Elements used in a Command ('Command Injection')
78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
88 | Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
90 | Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
91 | XML Injection (aka Blind XPath Injection)
94 | Improper Control of Generation of Code ('Code Injection')
119 | Improper Restriction of Operations within the Bounds of a Memory Buffer
125	| Out-of-bounds Read
190	| Integer Overflow or Wraparound
200	| Exposure of Sensitive Information to an Unauthorized Actor
209	| Generation of Error Message Containing Sensitive Information
220	| Storage of File With Sensitive Data Under FTP Root
223	| Omission of Security-relevant Information
256	| Unprotected Storage of Credentials
269	| Improper Privilege Management
284	| Improper Access Control
285	| Improper Authorization
287	| Improper Authentication
295	| Improper Certificate Validation
308	| Use of Single-factor Authentication
311	| Missing Encryption of Sensitive Data
312	| Cleartext Storage of Sensitive Information
319	| Cleartext Transmission of Sensitive Information
325	| Missing Required Cryptographic Step
326	| Inadequate Encryption Strength
327	| Use of a Broken or Risky Cryptographic Algorithm
328	| Reversible One-Way Hash
346	| Origin Validation Error
352	| Cross-Site Request Forgery (CSRF)
359	| Exposure of Private Personal Information to an Unauthorized Actor
384	| Session Fixation
400	| Uncontrolled Resource Consumption
416	| Use After Free
425	| Direct Request ('Forced Browsing')
426	| Untrusted Search Path
434	| Unrestricted Upload of File with Dangerous Type
476	| NULL Pointer Dereference
502	| Deserialization of Untrusted Data
521	| Weak Password Requirements
522	| Insufficiently Protected Credentials
523	| Unprotected Transport of Credentials
548	| Exposure of Information Through Directory Listing
564	| SQL Injection: Hibernate
601	| URL Redirection to Untrusted Site ('Open Redirect')
611	| Improper Restriction of XML External Entity Reference
613	| Insufficient Session Expiration
614	| Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
620	| Unverified Password Change
639	| Authorization Bypass Through User-Controlled Key
640	| Weak Password Recovery Mechanism for Forgotten Password
650	| Trusting HTTP Permission Methods on the Server Side
732	| Incorrect Permission Assignment for Critical Resource
772	| Missing Release of Resource after Effective Lifetime
776	| Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
778	| Insufficient Logging
787	| Out-of-bounds Write
798	| Use of Hard-coded Credentials
917	| Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')
943	| Improper Neutralization of Special Elements in Data Query Logic
1021	| Improper Restriction of Rendered UI Layers or Frames
1216	| Lockout Mechanism Errors
