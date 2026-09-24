# A10:2025 – Fehlerhafte Behandlung von Ausnahmezuständen ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## Hintergrund.

Fehlerhafte Behandlung von Ausnahmezuständen ist eine neue Kategorie für 2025. Diese Kategorie enthält 24 CWEs und konzentriert sich auf unsachgemäße Fehlerbehandlung, logische Fehler, „Failing Open" sowie andere verwandte Szenarien, die aus abnormalen Zuständen resultieren, mit denen Systeme konfrontiert werden können. Einige der enthaltenen CWEs waren zuvor der schlechten Codequalität zugeordnet. Das war uns zu allgemein; nach unserer Einschätzung bietet diese spezifischere Kategorie eine bessere Orientierung.

Bemerkenswerte CWEs in dieser Kategorie: *CWE-209 Generation of Error Message Containing Sensitive Information, CWE-234 Failure to Handle Missing Parameter, CWE-274 Improper Handling of Insufficient Privileges, CWE-476 NULL Pointer Dereference* und *CWE-636 Not Failing Securely ('Failing Open')*.


## Beurteilungskriterien.


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
   <td>20.67%
   </td>
   <td>2.95%
   </td>
   <td>100.00%
   </td>
   <td>37.95%
   </td>
   <td>7.11
   </td>
   <td>3.81
   </td>
   <td>769,581
   </td>
   <td>3,416
   </td>
  </tr>
</table>



## Beschreibung.

Fehlerhafte Behandlung von Ausnahmezuständen in Software tritt auf, wenn Programme außergewöhnliche und unvorhersehbare Situationen weder verhindern, erkennen noch darauf reagieren – was zu Abstürzen, unerwartetem Verhalten und mitunter zu Schwachstellen führt. Dies kann einen oder mehrere der folgenden drei Mängel umfassen: Die Anwendung verhindert eine ungewöhnliche Situation nicht, sie erkennt sie nicht, während sie eintritt, und/oder sie reagiert anschließend unzureichend oder gar nicht darauf.

 

Ausnahmezustände können durch fehlende, mangelhafte oder unvollständige Eingabevalidierung entstehen, durch späte oder übergeordnete Fehlerbehandlung anstatt dort, wo die Fehler auftreten, durch unerwartete Umgebungszustände wie Speicher-, Berechtigungs- oder Netzwerkprobleme, inkonsistente Ausnahmebehandlung oder vollständig unbehandelte Ausnahmen, die das System in einen unbekannten und unvorhersehbaren Zustand versetzen. Jedes Mal, wenn eine Anwendung über ihre nächste Anweisung unsicher ist, wurde ein Ausnahmezustand fehlerhaft behandelt. Schwer auffindbare Fehler und Ausnahmen können die Sicherheit der gesamten Anwendung über lange Zeit gefährden.

 

Bei fehlerhafter Behandlung von Ausnahmezuständen können vielfältige Schwachstellen entstehen, wie logische Fehler, Überläufe, Race Conditions, betrügerische Transaktionen oder Probleme mit Speicher, Zustand, Ressourcen, Timing, Authentifizierung und Autorisierung. Diese Schwachstellen können die Vertraulichkeit, Verfügbarkeit und/oder Integrität eines Systems oder seiner Daten beeinträchtigen. Angreifer:innen nutzen die fehlerhafte Fehlerbehandlung einer Anwendung aus, um diese Schwachstelle auszunutzen.


## Prävention und Gegenmaßnahmen.

Um Ausnahmezustände korrekt zu behandeln, müssen wir solche Situationen einplanen (vom Schlimmsten ausgehen). Wir müssen jeden möglichen Systemfehler direkt an der Stelle abfangen, an der er auftritt, und ihn dann behandeln (d. h. etwas Sinnvolles tun, um das Problem zu lösen und die Wiederherstellung sicherzustellen). Als Teil der Behandlung sollten wir einen Fehler werfen (um die/den Benutzer:in verständlich zu informieren), das Ereignis protokollieren sowie bei Bedarf einen Alarm auslösen. Wir sollten außerdem einen globalen Exception-Handler einrichten, für den Fall, dass uns etwas entgangen ist. Idealerweise verfügen wir zusätzlich über Monitoring- und/oder Observability-Werkzeuge, die auf wiederholte Fehler oder Muster hinweisen, die auf einen laufenden Angriff hindeuten, und eine Reaktion, Abwehr oder Blockierung auslösen können. Dies hilft uns, Skripte und Bots zu blockieren und darauf zu reagieren, die unsere Schwachstellen in der Fehlerbehandlung ausnutzen.

 

Das Abfangen und Behandeln von Ausnahmezuständen stellt sicher, dass die zugrunde liegende Infrastruktur unserer Programme nicht mit unvorhersehbaren Situationen allein gelassen wird. Befindet man sich mitten in einer Transaktion jeglicher Art, ist es äußerst wichtig, die gesamte Transaktion zurückzusetzen und neu zu beginnen (auch bekannt als „Failing Closed"). Der Versuch, eine Transaktion mittendrin wiederherzustellen, ist oft der Punkt, an dem unbehebbare Fehler entstehen.

 

Wo immer möglich sollten Rate Limiting, Ressourcenkontingente, Throttling und andere Begrenzungen eingesetzt werden, um Ausnahmezustände von vornherein zu verhindern. Nichts in der Informationstechnologie sollte unbegrenzt sein, da dies zu mangelnder Anwendungsresilienz, Denial-of-Service, erfolgreichen Brute-Force-Angriffen und enormen Cloud-Kosten führt.

Es sollte überlegt werden, ob identische, sich wiederholende Fehler ab einer bestimmten Rate nur noch als Statistik ausgegeben werden sollten, die anzeigt, wie oft und in welchem Zeitraum sie aufgetreten sind. Diese Information sollte an die ursprüngliche Meldung angehängt werden, um automatisiertes Logging und Monitoring nicht zu beeinträchtigen, siehe [A09:2025 Unzureichendes Sicherheitslogging und Alarmierung](A09_2025-Security_Logging_and_Alerting_Failures.md).

Darüber hinaus sollten wir strikte Eingabevalidierung (mit Bereinigung oder Escaping potenziell gefährlicher Zeichen, die wir akzeptieren müssen) sowie *zentralisierte* Fehlerbehandlung, Logging, Monitoring und Alerting mit einem globalen Exception-Handler einsetzen. Eine Anwendung sollte nicht mehrere Funktionen zur Behandlung von Ausnahmezuständen haben – dies sollte einheitlich an einer Stelle erfolgen. Wir sollten zudem Sicherheitsanforderungen für alle Empfehlungen dieses Abschnitts definieren, Bedrohungsmodellierung und/oder sichere Design-Reviews in der Entwurfsphase durchführen, Code-Reviews oder statische Analysen vornehmen sowie Stress-, Performance- und Penetrationstests am fertigen System ausführen.

 

Wenn möglich, sollte die gesamte Organisation Ausnahmezustände einheitlich behandeln, da dies die Überprüfung und Auditierung des Codes auf Fehler in dieser wichtigen Sicherheitsmaßnahme erleichtert.


## Beispielhafte Angriffsszenarien.

**Szenario Nr. 1:** Ressourcenerschöpfung durch fehlerhafte Behandlung von Ausnahmezuständen (Denial of Service) kann auftreten, wenn die Anwendung beim Datei-Upload Ausnahmen abfängt, die Ressourcen danach jedoch nicht ordnungsgemäß freigibt. Jede neue Ausnahme hinterlässt gesperrte oder anderweitig nicht verfügbare Ressourcen, bis alle Ressourcen verbraucht sind.

**Szenario Nr. 2:** Offenlegung sensibler Daten durch fehlerhafte Behandlung von Datenbankfehlern, die den vollständigen Systemfehler an die/den Benutzer:in weitergeben. Die/Der Angreifer:in erzwingt weiterhin Fehler, um die sensiblen Systeminformationen für einen gezielteren SQL-Injection-Angriff zu nutzen. Die sensiblen Daten in den Fehlermeldungen dienen dabei als Aufklärung.

**Szenario Nr. 3:** Zustandskorruption bei Finanztransaktionen kann durch ein:e Angreifer:in verursacht werden, der eine mehrstufige Transaktion durch Netzwerkunterbrechungen stört. Angenommen, die Transaktionsreihenfolge lautet: Nutzerkonto belasten, Zielkonto gutschreiben, Transaktion protokollieren. Wenn das System bei einem Fehler mittendrin die gesamte Transaktion nicht ordnungsgemäß zurücksetzt (Failing Closed), könnte die/der Angreifer:in das Konto der/des Nutzer:in leeren oder über eine Race Condition Geld mehrfach an das Zielkonto senden.


## Referenzen.

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/) 

## Liste der zugeordneten CWEs
* [CWE-209	Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215	Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234	Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235	Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248	Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252	Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274	Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280	Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369	Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390	Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391	Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394	Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396	Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397	Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460	Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476	NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478	Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484	Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550	Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636	Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703	Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754	Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755	Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756	Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)
