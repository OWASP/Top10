# Nächste Schritte

Die OWASP Top 10 sind von Natur aus auf die zehn bedeutendsten Risiken beschränkt. Jede OWASP Top 10 hat Risiken, die an der Schwelle zur Aufnahme in die Top 10 stehen,  es letztendlich jedoch nicht in die Liste geschafft haben. Die anderen Risiken waren weiter verbreitet und hatten größere Auswirkungen.

Die folgenden drei Themen sind es wert, identifiziert und behoben zu werden – insbesondere für Organisationen, die ein ausgereiftes Anwendungssicherheitsprogramm aufbauen möchten, sowie für Sicherheitsberatungsunternehmen oder Werkzeughersteller, die 
ihre Abdeckung erweitern möchten.


## X01:2025 Mangelnde Resilienz der Anwendung

### Hintergrund. 

Dies ist eine Umbenennung des Themas „Denial of Service" aus dem Jahr 2021. Die Umbenennung erfolgte, da der frühere Begriff ein Symptom beschrieb und nicht die eigentliche Ursache. Diese Kategorie konzentriert sich auf CWEs (Common Weakness Enumerations – Auflistungen häufiger Schwachstellen), die Schwächen im Zusammenhang mit Resilienzproblemen beschreiben. Die Bewertung dieser Kategorie lag sehr nahe an A10:2025 – Fehlerhafte Behandlung von Ausnahmezuständen. Relevante CWEs umfassen: *CWE-400 Unkontrollierter Ressourcenverbrauch, CWE-409 Unsachgemäße Behandlung von stark komprimierten Daten (Datenverstärkung), CWE-674 Unkontrollierte Rekursion* und *CWE-835 Schleife mit unerreichbarer Abbruchbedingung ('Endlosschleife')*.


### Punktetabelle.

<table>
  <tr>
   <td>Zugeordnete CWEs 
   </td>
   <td>Max. Häufigkeit
   </td>
   <td>Durchschn. Häufigkeit
   </td>
   <td>Max. Abdeckung
   </td>
   <td>Durchschn. Abdeckung
   </td>
   <td>Durchschn. gewichtete Ausnutzbarkeit
   </td>
   <td>Durchschn. gewichtete Auswirkung
   </td>
   <td>Gesamtanzahl 
   </td>
   <td>Summe CVEs
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



### Beschreibung. 

Diese Kategorie stellt eine systemische Schwäche darin dar, wie Anwendungen auf Belastungen, Ausfälle und Grenzfälle reagieren, von denen sie sich nicht erholen können. Wenn eine Anwendung unerwartete Zustände, Ressourcenengpässe und andere ungünstige Ereignisse nicht ordnungsgemäß behandelt, übersteht oder sich davon erholt, kann dies leicht zu Verfügbarkeitsproblemen führen (tritt am häufigsten auf), aber auch zu Datenschädigung, Offenlegung sensibler Daten, Kaskadenausfällen und/oder der Umgehung von Sicherheitskontrollen.

Darüber hinaus können [X02:2025 Speicherverwaltungsfehler](#x022025-speicherverwaltungsfehler) ebenfalls zum Ausfall der Anwendung oder sogar des gesamten Systems führen.


### Prävention und Gegenmaßnahmen.
Um diese Art von Schwachstelle zu verhindern, müssen Sie Ihre Systeme auf Fehlertoleranz und Wiederherstellung auslegen.

* Fügen Sie Begrenzungen, Kontingente und Failover-Funktionalität hinzu, und achten Sie dabei besonders auf die ressourcenintensivsten Vorgänge.
* Identifizieren Sie ressourcenintensive Seiten und planen Sie voraus: Reduzieren Sie die Angriffsfläche, indem Sie insbesondere keine unnötigen Funktionen und Komponenten, die viele Ressourcen (z. B. Prozessor, Arbeitsspeicher) benötigen, gegenüber unbekannten oder nicht vertrauenswürdigen Benutzer:innen exponieren.
* Führen Sie eine strikte Eingabevalidierung mit Positivlisten und Größenbeschränkungen durch und testen Sie diese gründlich.
* Begrenzen Sie die Größe von Antworten und senden Sie niemals unverarbeitete Rohantworten an den Client zurück (Verarbeitung auf der Serverseite).
* Standardmäßig sicher/geschlossen konfigurieren (niemals offen), standardmäßig ablehnen und bei einem Fehler zurücksetzen.
* Vermeiden Sie blockierende synchrone Aufrufe in Anfrage-Threads (verwenden Sie asynchrone/nicht-blockierende Verarbeitung, setzen Sie Zeitüberschreitungen und Parallelitätsbeschränkungen ein usw.).
* Testen Sie Ihre Fehlerbehandlungsfunktionalität sorgfältig.
* Implementieren Sie Resilienzmuster wie Schutzschalter (Circuit Breaker), Schotten (Bulkheads), Wiederholungslogik (Retry Logic) und schrittweisen Leistungsabbau (Graceful Degradation).
* Führen Sie Leistungs- und Lasttests durch; setzen Sie bei ausreichender Risikobereitschaft auch Chaos-Engineering ein.
* Implementieren Sie Redundanz, wo dies sinnvoll und wirtschaftlich vertretbar ist, und berücksichtigen Sie diese bei der Systemarchitektur.
* Implementieren Sie Überwachung, Beobachtbarkeit und Alarmierung.
* Filtern Sie ungültige Absenderadressen gemäß RFC 2267.
* Blockieren Sie bekannte Botnetze anhand von Fingerabdrücken, IP-Adressen oder dynamisch anhand ihres Verhaltens.
* Arbeitsnachweis (Proof-of-Work): Initiieren Sie ressourcenintensive Vorgänge auf der Seite der Angreifer:innen, die normale Benutzer:innen kaum beeinträchtigen, jedoch Bots behindern, die versuchen, eine große Anzahl von Anfragen zu senden. Erhöhen Sie den Schwierigkeitsgrad des Arbeitsnachweises, wenn die allgemeine Systemlast steigt, insbesondere für Systeme, die weniger vertrauenswürdig erscheinen oder sich wie Bots verhalten.
* Begrenzen Sie die serverseitige Sitzungsdauer basierend auf Inaktivität und einer maximalen Gesamtdauer.
* Begrenzen Sie die sitzungsgebundene Informationsspeicherung.


### Beispielhafte Angriffsszenarien.

**Szenario Nr. 1:** Angreifer:innen verbrauchen gezielt Anwendungsressourcen, um Ausfälle im System auszulösen und so einen Denial-of-Service zu verursachen. Dies kann durch Arbeitsspeichererschöpfung, Auffüllen des Festplattenspeichers, Prozessorüberlastung oder das Öffnen endloser Verbindungen geschehen.

**Szenario Nr. 2:** Eingabe-Fuzzing, das zu manipulierten Antworten führt, die die Geschäftslogik der Anwendung außer Kraft setzt.

**Szenario Nr. 3:** Angreifer:innen konzentrieren sich auf die Abhängigkeiten der Anwendung, indem sie Schnittstellen (APIs) oder andere externe Dienste zum Ausfall bringen, sodass die Anwendung nicht mehr weiterarbeiten kann.



### Referenzen.

* [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### Liste der zugeordneten CWEs
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


## X02:2025 Speicherverwaltungsfehler

### Hintergrund. 
Sprachen wie Java, C#, JavaScript/TypeScript (node.js), Go und „sicheres" Rust sind speichersicher. Speicherverwaltungsprobleme treten typischerweise in nicht speichersicheren Sprachen wie C und C++ auf. Diese Kategorie erzielte in der Umfrage in der Gemeinschaft (Community) die niedrigste Bewertung und war auch in den Daten gering vertreten, obwohl sie die drittmeisten zugehörigen CVEs aufweist. Wir führen dies auf die Dominanz von Webanwendungen gegenüber traditionellen Desktop-Anwendungen zurück. Speicherverwaltungsschwachstellen weisen häufig die höchsten CVSS-Bewertungen auf.

### Punktetabelle.

<table>
  <tr>
   <td>Zugeordnete CWEs 
   </td>
   <td>Max. Häufigkeit
   </td>
   <td>Durchschn. Häufigkeit
   </td>
   <td>Max. Abdeckung
   </td>
   <td>Durchschn. Abdeckung
   </td>
   <td>Durchschn. gewichtete Ausnutzbarkeit
   </td>
   <td>Durchschn. gewichtete Auswirkung
   </td>
   <td>Gesamtanzahl 
   </td>
   <td>Summe CVEs
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



### Beschreibung. 

Wenn eine Anwendung gezwungen ist, den Arbeitsspeicher selbst zu verwalten, können leicht Fehler entstehen. Speichersichere Sprachen werden zwar zunehmend eingesetzt, jedoch gibt es weltweit noch viele veraltete Systeme im produktiven Betrieb, neue systemnahe Anwendungen, die den Einsatz nicht speichersicherer Sprachen erfordern, sowie Webanwendungen, die mit Großrechnern, IoT-Geräten, Firmware und anderen Systemen interagieren, die möglicherweise ihren eigenen Arbeitsspeicher verwalten müssen. Repräsentative CWEs sind *CWE-120 Pufferkopie ohne Überprüfung der Eingabegröße (‚Klassischer Pufferüberlauf')* und *CWE-121 Stapelbasierter Pufferüberlauf. Speicherverwaltungsfehler* können auftreten, wenn:

* Sie nicht genügend Arbeitsspeicher für eine Variable reservieren
* Sie Eingaben nicht validieren und dadurch einen Überlauf des Heaps, des Stapelspeichers oder eines Puffers verursachen
* Sie einen Datenwert speichern, der größer ist als der Datentyp der Variable aufnehmen kann
* Sie versuchen, nicht reservierten Arbeitsspeicher oder Adressbereiche zu verwenden
* Sie Einzel-Versatz-Fehler erzeugen (Zählung ab 1 statt ab 0)
* Sie versuchen, auf ein Objekt zuzugreifen, nachdem dessen Speicher bereits freigegeben wurde
* Sie nicht initialisierte Variablen verwenden
* Sie Arbeitsspeicher verlieren oder anderweitig den gesamten verfügbaren Arbeitsspeicher verbrauchen, bis Ihre Anwendung abstürzt

Speicherverwaltungsfehler können zum Ausfall der Anwendung oder sogar des gesamten Systems führen; siehe auch [X01:2025 Mangelnde Resilienz der Anwendung](#x012025-mangelnde-resilienz-der-anwendung).


### Prävention und Gegenmaßnahmen.

Der beste Weg zur Vermeidung von Speicherverwaltungsfehlern ist die Verwendung einer speichersicheren Sprache. Beispiele hierfür sind Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript usw. Versuchen Sie bei der Entwicklung neuer Anwendungen, Ihre Organisation davon zu überzeugen, dass der Aufwand für den Umstieg auf eine speichersichere Sprache gerechtfertigt ist. Wenn eine vollständige Überarbeitung durchgeführt wird, setzen Sie sich dafür ein, den Code in einer speichersicheren Sprache neu zu schreiben, sofern dies möglich und machbar ist.

Falls die Verwendung einer speichersicheren Sprache nicht möglich ist, führen Sie folgende Maßnahmen durch:

* Aktivieren Sie die folgenden Serverfunktionen, die die Ausnutzung von Speicherverwaltungsfehlern erschweren: Adressraumanordnungs-Zufälligkeit (address space layout randomization / ASLR), Datenausführungsschutz (Data Execution Protection / DEP) und Strukturierter-Ausnahmebehandlungs-Überschreibungsschutz (Structured Exception Handling Overwrite Protection / SEHOP).
* Überwachen Sie Ihre Anwendung auf Arbeitsspeicherlecks.
* Validieren Sie alle Eingaben in Ihrem System sehr sorgfältig und weisen Sie alle Eingaben zurück, die nicht den Erwartungen entsprechen.
* Analysieren Sie die von Ihnen verwendete Programmiersprache und erstellen Sie eine Liste unsicherer und sichererer Funktionen. Teilen Sie diese Liste mit Ihrem gesamten Team. Fügen Sie sie, wenn möglich in Ihre Richtlinien oder Standards für sicheres Programmieren ein. Bevorzugen Sie beispielsweise in C die Funktion strncpy() gegenüber strcpy() und strncat() gegenüber strcat().
* Wenn Ihre Programmiersprache oder Ihr Framework Bibliotheken für Arbeitsspeichersicherheit anbietet, verwenden Sie diese. Beispiele hierfür sind Safestringlib oder SafeStr.
* Verwenden Sie nach Möglichkeit verwaltete Puffer und Zeichenketten anstelle von unbearbeiteten (raw) Feldern und Zeigern.
* Nehmen Sie an Schulungen für sicheres Programmieren teil, die sich auf Speicherprobleme und/oder Ihre bevorzugte Programmiersprache konzentrieren. Teilen Sie Ihrem Schulungsanbieter mit, dass Sie Speicherverwaltungsfehler als besonderes Risiko betrachten.
* Führen Sie Quellcode-Überprüfungen und/oder statische Analysen durch.
* Verwenden Sie Compiler-Werkzeuge, die bei der Speicherverwaltung helfen, wie StackShield, StackGuard und Libsafe.
* Führen Sie Fuzzing für alle Eingaben in Ihrem System durch.
* Wenn ein Penetrationstest durchgeführt wird, informieren Sie die Tester:innen, dass Sie Speicherverwaltungsfehler als besonderes Risiko betrachten und dass sie diesen Aspekt beim Testen besonders berücksichtigen soll.
* Beheben Sie alle Compiler-Fehler und Warnungen. Ignorieren Sie Warnungen nicht, nur weil Ihr Programm erfolgreich kompiliert.
* Stellen Sie sicher, dass Ihre zugrundeliegende Infrastruktur regelmäßig mit Sicherheitsaktualisierungen versorgt, überprüft und gehärtet wird.
* Überwachen Sie Ihre zugrundeliegende Infrastruktur gezielt auf potenzielle Speicherschwachstellen und andere Ausfälle.
* Erwägen Sie den Einsatz von [Canary-Werten (Prüfwerte)](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries), um Ihren Adressstapel vor Überlaufangriffen zu schützen.

### Beispielhafte Angriffsszenarien. 

**Szenario Nr. 1:** Pufferüberläufe sind die bekannteste Speicherschwachstelle – eine Situation, in der Angreifer:innen mehr Daten in ein Eingabefeld eingeben, als dieses aufnehmen kann, sodass der für die zugrundeliegende Variable angelegte Puffer überläuft. Bei einem erfolgreichen Angriff überschreiben die überlaufenden Zeichen den Stapelzeiger, was es ihnen ermöglicht, schadhaften Programmcode in Ihre Anwendung einzuschleusen.

**Szenario Nr. 2:** Use-After-Free (UAF) – Zugriff auf bereits freigegebenen Speicher – tritt häufig genug auf, um eine gängige Einsendung in Browser-Fehlerprämienprogrammen (bug bounty) zu sein. Stellen Sie sich einen Webbrowser vor, der JavaScript verarbeitet, das DOM-Elemente manipuliert. Die/Der Angreifer:in erstellt eine JavaScript-Nutzlast, die ein Objekt (z. B. ein DOM-Element) erzeugt und Verweise darauf erhält. Durch gezielte Manipulation veranlasst sie/er den Browser, den Speicher des Objekts freizugeben, während ein hängender Zeiger darauf bestehen bleibt. Bevor der Browser erkennt, dass der Speicher freigegeben wurde, reserviert die/der Angreifer:in ein neues Objekt, das denselben Speicherbereich belegt. Wenn der Browser versucht, den ursprünglichen Zeiger zu verwenden, verweist dieser nun auf von der/dem Angreifer:in kontrollierte Daten. Falls dieser Zeiger auf eine virtuelle Funktionstabelle zeigte, kann die/der Angreifer:in die Programmausführung auf ihre/seine Nutzlast umleiten.
 

**Szenario Nr. 3:** Hierbei handelt es sich um einen Netzwerkdienst, der Benutzereingaben entgegennimmt, diese nicht ordnungsgemäß validiert oder bereinigt und sie dann direkt an die Protokollierungsfunktion weitergibt. Die Benutzereingabe wird als syslog(user_input) statt als syslog("%s", user_input) an die Protokollierungsfunktion übergeben, ohne dass ein Formatbezeichner angegeben wird. Angreifer:innen senden schadhafte Nutzlasten mit Formatbezeichnern wie %x, um Stapelspeicherinhalte auszulesen (Offenlegung sensibler Daten), oder %n, um in Speicheradressen zu schreiben. Durch die Verkettung mehrerer Formatbezeichner können sie den Stapelspeicher kartieren, wichtige Adressen lokalisieren und diese anschließend überschreiben. Dies wäre eine Formatzeichenketten-Schwachstelle (unkontrolliertes Zeichenkettenformat).

Hinweis: Moderne Browser verwenden viele Schutzebenen, um sich gegen solche Angriffe zu verteidigen, darunter [Browser-Sandboxing](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing), ASLR, DEP/NX, RELRO und PIE. Ein Speicherverwaltungsangriff auf einen Browser ist kein einfach durchzuführender Angriff.

### Referenzen.

* [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### Liste der zugeordneten CWEs 
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



## X03:2025 Unangebrachtes Vertrauen in KI-generierten Code (‚Vibe Coding') 

### Hintergrund.

Derzeit spricht und nutzt die gesamte Welt Künstliche Intelligenz (KI), das schließt Softwareentwickler:innen ein. Obwohl es derzeit keine CVEs oder CWEs im Zusammenhang mit KI-generiertem Code gibt, ist allgemein bekannt und dokumentiert, dass KI-generierter Code häufig mehr Schwachstellen enthält als von Menschen geschriebener Code.

### Beschreibung.

Wir beobachten, dass sich die Softwareentwicklungspraxis dahingehend verändert, dass nicht nur Code mit Unterstützung von KI geschrieben wird, sondern Code nahezu vollständig ohne menschliche Aufsicht erstellt und eingereicht wird (oft als „Vibe Coding" bezeichnet). So wie es noch nie eine gute Idee war, Codeausschnitte aus Blogs oder Webseiten gedankenlos zu kopieren, wird das Problem in diesem Fall noch verschärft. Gute, sichere Codeausschnitte waren und sind selten und werden von KI aufgrund systemischer Einschränkungen möglicherweise statistisch vernachlässigt.


### Prävention und Gegenmaßnahmen.
Wir fordern alle Personen, die Code schreiben, auf, beim Einsatz von KI Folgendes zu berücksichtigen: 

* Sie sollten in der Lage sein, den gesamten von Ihnen eingereichten Code zu lesen und vollständig zu verstehen, auch wenn er von einer KI geschrieben oder aus einem Online-Forum kopiert wurde. Sie sind für jeden Code verantwortlich, den Sie einreichen.
* Sie sollten jeden KI-unterstützten Code gründlich auf Schwachstellen überprüfen, idealerweise mit eigenen Augen und zusätzlich mit Sicherheitswerkzeugen, die für diesen Zweck entwickelt wurden (z. B. statische Analyse). Ziehen Sie klassische Quellcode-Überprüfungstechniken in Betracht, wie sie in der [OWASP-Spickzettel-Reihe: Sichere Quellcode-Überprüfung](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html) beschrieben werden.
* Im Idealfall schreiben Sie Ihren eigenen Code, lassen die KI Verbesserungen vorschlagen, überprüfen den KI-Code und lassen die KI Korrekturen vornehmen, bis Sie mit dem Ergebnis zufrieden sind.
* Erwägen Sie den Einsatz eines Retrieval Augmented Generation (RAG)-Servers mit Ihren eigenen gesammelten und geprüften sicheren Codebeispielen und Dokumentationen, wie z. B. den Richtlinien, Standards oder Vorgaben Ihrer Organisation für sicheres Programmieren, und lassen Sie den RAG-Server die Einhaltung dieser Richtlinien und Standards durchsetzen.
* Erwägen Sie den Erwerb von Werkzeugen, die Schutzmaßnahmen für Datenschutz und Sicherheit für die Verwendung mit Ihrer/Ihren KI-Lösung(en) implementieren.
* Erwägen Sie den Erwerb einer privaten KI-Lösung, idealerweise mit einer Vertragsvereinbarung (einschließlich einer Datenschutzvereinbarung), dass die KI nicht mit den Daten, Anfragen, dem Code oder anderen sensiblen Informationen Ihrer Organisation trainiert wird.
* Erwägen Sie die Implementierung eines Model Context Protocol (MCP)-Servers zwischen Ihrer Entwicklungsumgebung und der KI und konfigurieren Sie diesen so, dass er den Einsatz Ihrer bevorzugten Sicherheitswerkzeuge erzwingt.
* Implementieren Sie Richtlinien und Prozesse als Teil Ihres Softwareentwicklungslebenszyklus (SDLC), um Entwickler:innen (und alle Mitarbeiter:innen) darüber zu informieren, wie KI innerhalb Ihrer Organisation verwendet werden soll und wie nicht.
* Erstellen Sie eine Liste guter und wirksamer Eingabeaufforderungen (Prompts), die bewährte IT-Sicherheitspraktiken berücksichtigen. Idealerweise sollten diese auch Ihre internen Richtlinien für sicheres Programmieren einbeziehen. Entwickler:innen können diese Eingabeaufforderungen als Ausgangspunkt für ihre Programme verwenden.
* KI wird voraussichtlich Teil jeder Phase Ihres Softwareentwicklungslebenszyklus werden – sowohl hinsichtlich des effektiven als auch des sicheren Einsatzes. Verwenden Sie KI mit Bedacht.
* Es wird ausdrücklich **<u>nicht</u>** empfohlen, Vibe Coding für komplexe Funktionen, geschäftskritische Programme oder Programme, die über einen langen Zeitraum genutzt werden, einzusetzen.
* Implementieren Sie technische Prüfungen und Schutzmaßnahmen gegen die Verwendung von Schatten-KI (Shadow AI).
* Schulen Sie Ihre Entwickler:innen in Bezug auf Ihre Richtlinien sowie den sicheren KI-Einsatz und bewährte Praktiken für die Verwendung von KI in der Softwareentwicklung.

### Referenzen.

* [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


### Liste der zugeordneten CWEs 
- keine
