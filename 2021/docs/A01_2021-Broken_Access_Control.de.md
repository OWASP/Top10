---
source: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
title:  "A01:2021 – Mangelhafte Zugriffskontrolle"
id:     "A01:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib   = parent ~ ".1" -%}
#A01:2021 – Mangelhafte Zugriffskontrolle ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name="Broken Access Control", lang=lang, source=source, parent=parent, predecessor=extra.osib.document ~ ".2017.5" ) }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

94 % der Anwendungen wurden auf irgendeine Form fehlerhafter Zugriffskontrolle getestet.
Vom fünften Platz aufgestiegen, weist die fehlerhafte Zugriffskontrolle mit einer durchschnittlichen Inzidenzrate von 3,81 % und mit über 318.000 die meisten Vorkommnisse im vorliegenden Datensatz auf. Bemerkenswerte Common Weakness Enumerations (CWEs) sind *CWE-200: Offenlegung sensibler Informationen gegenüber einem nicht autorisierten Akteur*, *CWE-201: Einfügen sensibler Informationen in gesendete Daten* und *CWE-352: Cross-Site Request Forgery* .

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Die Zugriffskontrolle erzwingt Richtlinien, sodass Benutzer nicht außerhalb ihrer vorgesehenen Berechtigungen handeln können. Fehler führen in der Regel zur unbefugten Offenlegung, Änderung oder Zerstörung aller Daten oder zur Ausführung einer Geschäftsfunktion außerhalb der Verfügungen des Benutzers. Zu den häufigsten Schwachstellen bei der Zugriffskontrolle gehören:

- Verstoß gegen die Prinzipien der geringsten Rechte oder der standardmäßigen Verweigerung, bei dem der Zugriff nur für bestimmte Fähigkeiten, Rollen oder Benutzer gewährt werden sollte, aber für jedermann verfügbar ist

- Umgehen von Zugriffskontrollprüfungen durch Ändern der URL (Parametermanipulation oder erzwungenes Durchsuchen), des internen Anwendungsstatus oder der HTML-Seite oder durch Verwendung eines Angriffstools zur Änderung von API-Anfragen

- Ermöglichen, das Konto einer anderen Person anzuzeigen oder zu bearbeiten, indem dessen eindeutige Kennung angegeben wird (unsichere direkte Objektreferenzen)

- Zugriff auf die API mit fehlenden Zugriffskontrollen für POST, PUT und DELETE

- Erhöhung der Privilegien. Als Benutzer fungieren, ohne angemeldet zu sein, oder als Administrator fungieren, wenn man als Benutzer angemeldet ist

- Metadatenmanipulation, wie z. B. das Wiedergeben oder Manipulieren eines JSON Web Token (JWT)-Zugriffskontrolltokens oder die Manipulation eines Cookies oder versteckten Felds, um Berechtigungen zu erhöhen oder die JWT-Ungültigmachung zu missbrauchen

- CORS-Fehlkonfiguration ermöglicht API-Zugriff von nicht autorisierten/nicht vertrauenswürdigen Quellen.

- Erzwingen des Navigierens zu authentifizierten Seiten als nicht authentifizierter Benutzer oder zu privilegierten Seiten als Standardbenutzer

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

Die Zugriffskontrolle ist nur wirksam bei vertrauenswürdigem serverseitigem Code oder serverlosen APIs, bei denen der Angreifer die Zugriffskontrollprüfung oder Metadaten nicht ändern kann.

- Verweigern Sie standardmäßig den Zugriff, mit Ausnahme öffentlicher Ressourcen.

- Implementieren Sie Zugriffskontrollmechanismen einmalig und verwenden Sie diese in der gesamten Anwendung wieder, einschließlich der Minimierung der Nutzung von Cross-Origin Resource Sharing (CORS).

- Modellzugriffskontrollen sollten die Datensatzeigentümerschaft erzwingen, anstatt zu akzeptieren, dass der Benutzer Datensätze erstellen, lesen, aktualisieren oder löschen kann.

- Durch Domänenmodelle sollten eindeutige Geschäftslimitanforderungen für Anwendungen durchgesetzt werden.

- Deaktivieren Sie die Verzeichnisliste des Webservers und stellen Sie sicher, dass Dateimetadaten (z. B. .git) und Sicherungsdateien nicht in Web-Roots vorhanden sind.

- Protokollieren Sie Fehler bei der Zugriffskontrolle und benachrichtigen Sie Administratoren bei Bedarf (z. B. wiederholte Fehler).

- Setzen Sie Ratenbegrenzung für API- und Controller-Zugriff, um den Schaden durch automatisierte Angriffstools zu minimieren.

- Statusbehaftete Sitzungskennungen sollten nach dem Abmelden auf dem Server ungültig gemacht werden. Zustandslose JWT-Token sollten eher kurzlebig sein, damit das Zeitfenster für einen Angreifer minimiert wird. Für langlebigere JWTs wird dringend empfohlen, die OAuth-Standards zu befolgen, um den Zugriff zu widerrufen.

Entwickler und QA-Mitarbeiter sollten funktionale Zugriffskontrolleinheiten und Integrationstests durchführen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Die Anwendung verwendet nicht überprüfte Daten in einem SQL-Aufruf, der auf Kontoinformationen zugreift:

```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```

Ein Angreifer ändert einfach den „acct“-Parameter des Browsers, um die gewünschte Kontonummer zu senden. Bei nicht korrekter Überprüfung kann der Angreifer auf das Konto eines beliebigen Benutzers zugreifen.

```
https://example.com/app/accountInfo?acct=notmyacct
```

**Szenario Nr. 2:** Ein Angreifer erzwingt einfach die Suche nach Ziel-URLs. Für den Zugriff auf die Admin-Seite sind Admin-Rechte erforderlich.

```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```
Wenn ein nicht authentifizierter Benutzer auf eine der Seiten zugreifen kann, liegt ein Fehler vor. Wenn ein Nicht-Administrator auf die Admin-Seite zugreifen kann, handelt es sich um einen Fehler.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3." ~ "7", osib=osib) }} <!-- [OWASP Proaktive Kontrollen: Zugriffskontrollen erzwingen](https://owasp.org/ www-project-proactive-controls/v3/en/c7-enforce-access-controls) -->
- {{ osib_link(link="osib.owasp.asvs.4-0." ~ "4", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V4 Access Control](https:// owasp.org/www-project-application-security-verification-standard) -->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.5", osib=osib) }} <!-- [OWASP-Testleitfaden: Autorisierungstests](https://owasp.org/www- project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Authorization", osib=osib) }} <!-- [OWASP Spickzettel: Autorisierung](https://cheatsheetseries.owasp.org/ cheatsheets/Authorization_Cheat_Sheet.html) -->
- {{ osib_link(link="osib.portswigger.research.articles.exploiting cors misconfigurations for bitcoins and bounties", osib=osib) }} <!--- [PortSwigger: Exploiting CORS misconfiguration](https://portswigger. net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) -->
- {{ osib_link(link="osib.oauth.oauth2 Servers.listing Authorizations.Revoking Access", osib=osib) }} <!--- [OAuth: Zugriff widerrufen](https://www.oauth.com/ oauth2-servers/listing-authorizations/revoking-access/) -->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.22", doc="", osib=osib) }} <!-- [CWE-22: Unsachgemäße Beschränkung eines Pfadnamens auf ein eingeschränktes Verzeichnis (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.23", doc="", osib=osib) }} <!-- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.35", doc="", osib=osib) }} <!-- [CWE-35: Path Traversal: '.../...// '](https://cwe.mitre.org/data/definitions/35.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.59", doc="", osib=osib) }} <!-- [CWE-59: Falsche Linkauflösung vor dem Dateizugriff ('Link Following')] (https://cwe.mitre.org/data/definitions/59.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.200", doc="", osib=osib) }} <!-- [CWE-200: Offenlegung sensibler Informationen gegenüber einem nicht autorisierten Akteur](https://cwe.mitre.org/data/definitions/200.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.201", doc="", osib=osib) }} <!-- [CWE-201: Offenlegung sensibler Informationen durch gesendete Daten](https://cwe.mitre.org/data/definitions/201.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.219", doc="", osib=osib) }} <!-- [CWE-219: Speicherung von Dateien mit sensiblen Daten im Web-Root](https://cwe.mitre.org/data/definitions/219.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.264", doc="", osib=osib) }} <!-- [CWE-264: Berechtigungen, Privilegien und Zugriffskontrollen (sollten nicht mehr verwendet werden )](https://cwe.mitre.org/data/definitions/264.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.275", doc="", osib=osib) }} <!-- [CWE-275: Berechtigungsprobleme](https://cwe.mitre.org/data/definitions/275.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.276", doc="", osib=osib) }} <!-- [CWE-276: Falsche Standardberechtigungen](https://cwe.mitre.org/data/definitions/276.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.284", doc="", osib=osib) }} <!-- [CWE-284: Unsachgemäße Zugriffskontrolle](https://cwe.mitre.org/data/definitions/284.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.285", doc="", osib=osib) }} <!-- [CWE-285: Unsachgemäße Autorisierung](https://cwe.mitre.org/data/definitions/285.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.352", doc="", osib=osib) }} <!-- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.359", doc="", osib=osib) }} <!-- [CWE-359: Offenlegung privater personenbezogener Daten gegenüber einem nicht autorisierten Akteur](https://cwe.mitre.org/data/definitions/359.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.377", doc="", osib=osib) }} <!-- [CWE-377: Unsichere temporäre Datei](https://cwe.mitre.org/data/definitions/377.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.402", doc="", osib=osib) }} <!-- [CWE-402: Übertragung privater Ressourcen in eine neue Sphäre („Resource Leak“ )](https://cwe.mitre.org/data/definitions/402.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.425", doc="", osib=osib) }} <!-- [CWE-425: Direkte Anfrage ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.441", doc="", osib=osib) }} <!-- [CWE-441: Unbeabsichtigter Proxy oder Vermittler („Confused Deputy“)](https://cwe.mitre.org/data/definitions/441.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.497", doc="", osib=osib) }} <!-- [CWE-497: Offenlegung sensibler Systeminformationen gegenüber einer nicht autorisierten Kontrollsphäre](https://cwe.mitre.org/data/definitions/497.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.538", doc="", osib=osib) }} <!-- [CWE-538: Einfügen vertraulicher Informationen in extern zugängliche Dateien oder Verzeichnisse]( https://cwe.mitre.org/data/definitions/538.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.540", doc="", osib=osib) }} <!-- [CWE-540: Aufnahme sensibler Informationen in Quellcode](https://cwe.mitre.org/data/definitions/540.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.548", doc="", osib=osib) }} <!-- [CWE-548: Offenlegung von Informationen durch Verzeichniseintrag](https://cwe.mitre.org/data/definitions/548.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.552", doc="", osib=osib) }} <!-- [CWE-552: Dateien oder Verzeichnisse, auf die externe Parteien zugreifen können](https://cwe.mitre.org/data/definitions/552.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.566", doc="", osib=osib) }} <!-- [CWE-566: Autorisierungsumgehung durch benutzergesteuerten SQL-Primärschlüssel](https://cwe.mitre.org/data/definitions/566.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.601", doc="", osib=osib) }} <!-- [CWE-601: URL-Umleitung zu nicht vertrauenswürdiger Site („Open Redirect“)](https://cwe.mitre.org/data/definitions/601.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.639", doc="", osib=osib) }} <!-- [CWE-639: Autorisierungsumgehung durch benutzergesteuerten Schlüssel](https://cwe.mitre.org/data/definitions/639.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.651", doc="", osib=osib) }} <!-- [CWE-651: Offenlegung einer WSDL-Datei mit vertraulichen Informationen](https://cwe.mitre.org/data/definitions/651.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.668", doc="", osib=osib) }} <!-- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.706", doc="", osib=osib) }} <!-- [CWE-706: Verwendung eines falsch aufgelösten Namens oder einer Referenz](https://cwe.mitre.org/data/definitions/706.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.862", doc="", osib=osib) }} <!-- [CWE-862: Fehlende Autorisierung](https://cwe.mitre.org/data/definitions/862.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.863", doc="", osib=osib) }} <!-- [CWE-863: Falsche Autorisierung](https://cwe.mitre.org/data/definitions/863.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.913", doc="", osib=osib) }} <!-- [CWE-913: Unsachgemäße Kontrolle dynamisch verwalteter Coderessourcen](https://cwe.mitre.org/data/definitions/913.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.922", doc="", osib=osib) }} <!-- [CWE-922: Unsichere Speicherung sensibler Informationen](https://cwe.mitre.org/data/definitions/922.html) -->
- {{ osib_link(link="osib.mitre.cwe.0.1275", doc="", osib=osib) }} <!-- [CWE-1275: Sensibles Cookie mit falschem SameSite-Attribut](https://cwe.mitre.org/data/definitions/1275.html) -->
