#  A01:2025 Broken Access Control <img src="../assets/TOP_10_Icons_Final_Broken_Access_Control.png" style="height:80px;width:80px; float:right;" alt="icon">



## Hintergrund. 

100 % der getesteten Anwendungen wiesen irgendeine Form fehlerhafter Zugriffskontrolle auf.
An der Spitze der Top Ten verbleibend, weist diese Kategorie die höchste Anzahl an Vorkommnissen im vorliegenden Datensatz sowie die zweithöchste Anzahl zugehöriger CVEs auf.
Bemerkenswerte Common Weakness Enumerations (CWEs) sind *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201: Insertion of Sensitive Information Into Sent Data*, *CWE-918: Server-Side Request Forgery (SSRF)* und *CWE-352: Cross-Site Request Forgery (CSRF)*.

## Punktetabelle.


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
   <td>40
   </td>
   <td>20.15%
   </td>
   <td>3.74%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.04
   </td>
   <td>3.84
   </td>
   <td>1,839,701
   </td>
   <td>32,654
   </td>
  </tr>
</table>



## Beschreibung. 

Die Zugriffskontrolle erzwingt Richtlinien, sodass Nutzende nicht außerhalb ihrer vorgesehenen Berechtigungen handeln können. Fehler führen in der Regel zur unbefugten Offenlegung, Änderung oder Zerstörung aller Daten oder zur Ausführung einer Geschäftsfunktion außerhalb der Verfügungen der anwendenden Person. Zu den häufigsten Schwachstellen bei der Zugriffskontrolle gehören:



* Verstoß gegen die Prinzipien der geringsten Rechte oder der standardmäßigen Verweigerung, bei dem der Zugriff nur für bestimmte Fähigkeiten, Rollen oder Nutzende gewährt werden sollte, aber für jedermann verfügbar ist.
* Umgehen von Zugriffskontrollprüfungen durch Ändern der URL (Parametermanipulation oder erzwungenes Durchsuchen), des internen Anwendungsstatus oder der HTML-Seite oder durch Verwendung eines Angriffstools zur Änderung von API-Anfragen.
* Ermöglichen, das Konto einer anderen Person anzuzeigen oder zu bearbeiten, indem dessen eindeutige Kennung angegeben wird (unsichere direkte Objektreferenzen).
* Eine zugängliche API mit fehlenden Zugriffskontrollen für POST, PUT und DELETE.
* Erhöhung der Privilegien. Als Nutzerin/Nutzer fungieren, ohne angemeldet zu sein oder als Administrator fungieren, wenn man als Standard-Nutzerin/Nutzer angemeldet ist.
* Manipulation von Metadaten, wie z. B. das Abfangen oder Manipulieren eines JSON Web Token (JWT)-Zugriffskontrolltokens oder die Manipulation eines Cookies oder eines versteckten Felds, um Berechtigungen zu erhöhen oder die Ungültigerklärung von JWTs zu missbrauchen.
* CORS-Fehlkonfiguration ermöglicht API-Zugriff von nicht autorisierten/nicht vertrauenswürdigen Quellen.
* Erzwingen des Zugriffs auf authentifizierte Seiten als nicht authentifizierte Person oder zu privilegierten Seiten als Standard-Nutzerin/Nutzer.


## Prävention und Gegenmaßnahmen.

Die Zugriffskontrolle ist nur wirksam bei vertrauenswürdigem serverseitigem Code oder serverlosen APIs, bei denen Angreifende die Zugriffskontrollprüfung oder Metadaten nicht ändern können.



* Verweigern Sie standardmäßig den Zugriff, mit Ausnahme öffentlicher Ressourcen.
* Implementieren Sie Zugriffskontrollmechanismen einmalig und verwenden Sie diese in der gesamten Anwendung wieder, einschließlich der Minimierung der Nutzung von Cross-Origin Resource Sharing (CORS).
* Modellzugriffskontrollen sollten die Datensatzeigentümerschaft erzwingen, anstatt zu akzeptieren, dass Nutzerinnen/Nutzer Datensätze erstellen, lesen, aktualisieren oder löschen können.
* Durch Domänenmodelle sollten eindeutige Geschäftslimitanforderungen für Anwendungen durchgesetzt werden.
* Deaktivieren Sie die Verzeichnisliste des Webservers und stellen Sie sicher, dass Dateimetadaten (z. B. .git) und Sicherungsdateien nicht in Web-Roots vorhanden sind.
* Protokollieren Sie Fehler bei der Zugriffskontrolle und benachrichtigen Sie Administratoren bei Bedarf (z. B. wiederholte Fehler).
* Setzen Sie Ratenbegrenzung für API- und Controller-Zugriff, um den Schaden durch automatisierte Angriffstools zu minimieren.
* Statusbehaftete Sitzungskennungen sollten nach dem Abmelden auf dem Server ungültig gemacht werden. Zustandslose JWT-Token sollten eher kurzlebig sein, damit das Zeitfenster für Angreifende minimiert wird. Für langlebigere JWTs wird dringend empfohlen, die OAuth-Standards zu befolgen, um den Zugriff zu widerrufen.
* Verwenden Sie bewährte Toolkits oder Muster, die einfache, deklarative Zugriffskontrollen bieten.

Entwickler und QA-Mitarbeiter sollten funktionale Zugriffskontrolleinheiten und Integrationstests durchführen.


## Beispielhafte Angriffsszenarien. 

**Szenario Nr. 1:** Die Anwendung verwendet nicht überprüfte Daten in einem SQL-Aufruf, der auf Kontoinformationen zugreift:


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```


Angreifende ändern einfach den „acct“-Parameter des Browsers, um die gewünschte Kontonummer zu senden. Bei nicht korrekter Überprüfung kann die angreifende Person auf das Konto einer beliebigen Nutzerin/Nutzers zugreifen.


```
https://example.com/app/accountInfo?acct=notmyacct
```


**Szenario Nr. 2:** Eine angreifende Person erzwingt einfach die Suche nach Ziel-URLs. Für den Zugriff auf die Admin-Seite sind Admin-Rechte erforderlich.


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


Wenn eine nicht authentifizierte Benutzerin/Benutzer auf eine der Seiten zugreifen kann, liegt ein Fehler vor. Wenn ein Benutzerin/Benutzer ohne Administrationsrechte auf die Admin-Seite zugreifen kann, handelt es sich um einen Fehler.

**Szneraio Nr. 3:** Eine Anwendung verwaltet ihre gesamte Zugriffskontrolle im Frontend. Während der Angreifer aufgrund von im Browser ausgeführtem JavaScript-Code nicht auf `https://example.com/app/admin_getappInfo` zugreifen kann, kann er einfach Folgendes ausführen:


```
$ curl https://example.com/app/admin_getappInfo
```


von der Kommandozeile aus.


## Referenzen.

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## Liste der zugeordneten CWEs

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)

* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)

* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)

* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)

* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)

* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)

* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)

* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)

* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
