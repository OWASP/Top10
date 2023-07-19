# A01:2021 – Fehler in der Zugriffskontrolle ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## Überblick

Vom fünften Platz aufgestiegen, wurden in 94 % der Anwendungen eine Form fehlerhafter Zugangskontrolle festgestellt. Mit einer durchschnittlichen Inzidenzrate von 3,81 % und weist mit über 318.000 die meisten Vorkommnisse im bereitgestellten Datensatz auf. Relevante Common Weakness Enumerations (CWEs) sind *CWE-200: Offenlegung sensibler Informationen gegenüber einem nicht autorisierten Akteur*, *CWE-201: Einfügen sensibler Informationen in gesendete Daten* und *CWE-352: Cross-Site Request Forgery* .

## Beschreibung

Zugriffskontrollmechanismen setzen Richtlinien um, so dass Benutzer nur innerhalb ihrer beabsichtigten Berechtigungen handeln können. Fehlerfälle führen hier in der Regel zu unbefugter Offenlegung, Änderung oder Löschung von Daten oder zu einer Geschäftshandlung außerhalb der Befugnisse des Benutzers. Zu den häufigsten Schwachstellen gehören:

- Verstoß gegen das Least-Priviledge-Prinzip oder Deny-by-Default an Stellen bei denen der Zugriff nur für bestimmte Rollen oder Benutzer gewährt werden sollte, aber für jedermann verfügbar ist.

- Umgehen von Zugriffskontrollprüfungen durch Ändern der URL (Verändern der Parameter oder force browsing), des internen Anwendungsstatus oder der HTML-Seite oder einfach durch Verwendung eines API-Angriffswerkzeugs.

- Anzeigen oder Bearbeiten eines Benutzerkontos durch verändern des Primärschlüssels (Unsichere, direkte Objekt-Referenzen).

- Zugriff auf die API mit fehlenden Zugriffskontrollen für POST, PUT und DELETE.

- Rechteausweitung: Als Benutzer handeln, ohne angemeldet zu sein oder als Administrator handeln, wenn man als Benutzer angemeldet ist.

- Metadatenmanipulationen, wie z.B. das erneute Verwenden/Manipulieren eines JSON Web Tokens (JWT), Zugriffskontroll-Tokens, Cookies oder versteckten Feldes, um Berechtigungen auszuweiten oder der Missbrauch der JWT-Invalidierung.

- Fehlkonfigurationen von CORS ermöglichen einen API-Zugriff aus nicht vertrauenswürdigen Quellen.

- Aufrufen authentifizierter Seiten als nicht authentifizierter Benutzer oder privilegierter Seiten als Standardbenutzer.

## Gegenmaßnahmen

Eine Zugriffskontrolle ist nur wirksam, wenn sie im vertrauenswürdigen serverseitigen Code oder über eine Serverless API betrieben wird, so dass der Angreifer die Zugriffskontrollprüfung oder die verwendeten Metadaten nicht manipulieren kann.

- Mit Ausnahme von Zugriffen auf öffentliche Ressourcen sollten Anfragen standardmäßig verweigert werden.

- Zugriffskontrollmechanismen sollten einmalig implementiert und in der gesamten Anwendung wiederverwendet werden. Cross-Origin Resource Sharing (CORS) sollte ebenfalls minimiert werden.

- Zugriffskontrollmechanismen müssen die Berechtigung für Datensätze anhand des Besitzers kontrollieren anstatt zuzulassen, dass Benutzer beliebige Datensätze erstellen, lesen, aktualisieren oder löschen können. In Zugriffskontrollen müssen Subjekt, Aktion und Objekt geprüft werden.

- (Sich gegenseitig ausschließende Rechte sollten durch Berechtigungskonzepte durchgesetzt werden.) ???

- Verzeichnisauflistungen bei Webservern müssen deaktiviert werden und es muss sichergestellt werden, dass keine Meta- und Backupdateien (z.B. .git) in Web-Roots abgelegt werden.

- Zugriffsfehler müssen protokolliert und ggf. Administratoren alarmiert werden (z.B. bei wiederholten Fehlern).

- API- und Controller-Zugriffe sollten über Quotas beschränkt werden, um den Schaden durch automatisierte Angriffs-Tools zu minimieren.

– Stateful session sollten nach dem Abmelden auf dem Server ungültig gemacht werden. Zustandslose JWT-Token sollten kurzlebig sein, damit das Zeitfenster für einen Angreifer minimiert wird. Für langlebigere JWTs wird dringend empfohlen, die OAuth-Standards zu befolgen, um den Zugriff zu widerrufen.

Entwickler und QA-Mitarbeiter sollten funktionale Unit- und Integrationstests der Zugriffskontrolle durchführen.

## Mögliche Angriffsszenarien

**Szenario 1:** Eine Anwendung verarbeitet nicht verifizierte Daten in einem SQL-Aufruf, der auf Kontoinformationen zugreift:

```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```

Ein Angreifer ändert nun den Parameter “acct” im Browser in eine beliebige Kontonummer. Werden Eingangsdaten nicht ordnungsgemäß verifiziert, kann ein Angreifer auf das Konto eines beliebigen Benutzers zugreifen.

```
https://example.com/app/accountInfo?acct=notmyacct
```

**Szenario 2:** Ein Angreifer erzwingt einfach die Suche nach Ziel-URLs. Für den Zugriff auf die Admin-Seite sind Admin-Rechte erforderlich.

```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```
Wenn ein nicht authentifizierter Benutzer auf eine der Seiten zugreifen kann, liegt ein Fehler vor. Wenn ein Nicht-Administrator auf die Admin-Seite zugreifen kann, handelt es sich um einen Fehler.

## Referenzen

- [OWASP Proactive Controls: Zugriffskontrollen erzwingen](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

- [OWASP Application Security Verification Standard: V4 Access Control](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP-Testleitfaden: Autorisierungstests](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

- [OWASP-Cheat sheet: Autorisierung](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

- [PortSwigger: CORS-Fehlkonfiguration ausnutzen](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

- [OAuth: Zugriff widerrufen](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## Liste der zugeordneten CWEs

[CWE-22 Unsachgemäße Beschränkung eines Pfadnamens auf ein eingeschränktes Verzeichnis („Path Traversal“)](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Unsachgemäße Linkauflösung vor Dateizugriff („Linkfolge“)](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Offenlegung sensibler Informationen gegenüber einem nicht autorisierten Akteur](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Offenlegung sensibler Informationen durch gesendete Daten](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Speicherung von Dateien mit sensiblen Daten im Web-Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264-Berechtigungen, Privilegien und Zugriffskontrollen (sollten nicht mehr verwendet werden)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275-Berechtigungsprobleme](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Falsche Standardberechtigungen](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Unsachgemäße Zugriffskontrolle](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Unsachgemäße Autorisierung](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Offenlegung privater personenbezogener Daten gegenüber einem nicht autorisierten Akteur](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Unsichere temporäre Datei](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Übertragung privater Ressourcen in einen neuen Bereich („Ressourcenleck“)](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425-Direktanfrage („Forced Browsing“)](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unbeabsichtigter Stellvertreter oder Vermittler („Verwirrter Stellvertreter“)](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Offenlegung sensibler Systeminformationen gegenüber einer unbefugten Kontrollsphäre](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Einfügen vertraulicher Informationen in extern zugängliche Dateien oder Verzeichnisse](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Einbeziehung sensibler Informationen in den Quellcode](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Offenlegung von Informationen durch Verzeichniseintrag](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552-Dateien oder -Verzeichnisse, auf die externe Parteien zugreifen können](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566-Autorisierungsumgehung durch benutzergesteuerten SQL-Primärschlüssel](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL-Umleitung auf nicht vertrauenswürdige Site („Open Redirect“)](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639-Autorisierungsumgehung durch benutzergesteuerten Schlüssel](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Offenlegung einer WSDL-Datei mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposition der Ressource gegenüber der falschen Sphäre](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Verwendung eines falsch aufgelösten Namens oder einer Referenz](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Fehlende Autorisierung](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Falsche Autorisierung](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Unsachgemäße Kontrolle dynamisch verwalteter Coderessourcen](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Unsichere Speicherung sensibler Informationen](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensibles Cookie mit falschem SameSite-Attribut](https://cwe.mitre.org/data/definitions/1275.html)
