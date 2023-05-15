# A10:2021 – Serverseitige Anforderungsfälschung (SSRF) ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 8.28                 | 6.72                | 67.72%       | 67.72%       | 9,503             | 385        |

## Überblick

Diese Kategorie wurde aus der Top-10-Community-Umfrage (Nr. 1) hinzugefügt. Die Daten zeigen eine relativ niedrige Inzidenzrate mit überdurchschnittlicher Testabdeckung und überdurchschnittlichen Bewertungen des Exploit- und Impact-Potenzials. Da es sich bei neuen Einträgen wahrscheinlich um eine einzelne oder kleine Gruppe von Common Weakness Enumerations (CWEs) handelt, um Aufmerksamkeit und Aufmerksamkeit zu erregen, besteht die Hoffnung, dass sie einer Fokussierung unterliegen und in einer zukünftigen Ausgabe in eine größere Kategorie zusammengefasst werden können.

## Beschreibung

SSRF-Fehler treten immer dann auf, wenn eine Webanwendung eine Remote-Ressource abruft, ohne die vom Benutzer angegebene URL zu überprüfen. Dadurch kann ein Angreifer die Anwendung dazu zwingen, eine manipulierte Anfrage an ein unerwartetes Ziel zu senden, selbst wenn sie durch eine Firewall, ein VPN oder eine andere Art von Netzwerkzugriffskontrollliste (ACL) geschützt ist.

Da moderne Webanwendungen Endbenutzern praktische Funktionen bieten, wird das Abrufen einer URL zu einem häufigen Szenario. Infolgedessen nimmt die Inzidenz von SSRF zu. Außerdem nimmt der Schweregrad von SSRF aufgrund von Cloud-Diensten und der Komplexität der Architekturen zu.

## Wie man etwas vorbeugt

Entwickler können SSRF verhindern, indem sie einige oder alle der folgenden Tiefenverteidigungskontrollen implementieren:

### **Von der Netzwerkebene**

- Segmentieren Sie die Remote-Ressourcenzugriffsfunktionalität in separate Netzwerke, um die Auswirkungen von SSRF zu reduzieren

- Erzwingen Sie „standardmäßig verweigern“-Firewall-Richtlinien oder Netzwerkzugriffskontrollregeln, um den gesamten Intranetverkehr außer dem Wesentlichen zu blockieren.<br/>
*Hinweise:*<br>
~ Richten Sie einen Besitz und einen Lebenszyklus für Firewall-Regeln basierend auf Anwendungen ein.<br/>
~ Protokollieren Sie alle akzeptierten *und* blockierten Netzwerkflüsse auf Firewalls
(siehe [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)).

### **Von der Anwendungsebene:**

- Bereinigen und validieren Sie alle vom Kunden bereitgestellten Eingabedaten

– Erzwingen Sie das URL-Schema, den Port und das Ziel mit einer positiven Zulassungsliste

- Senden Sie keine Rohantworten an Kunden

- Deaktivieren Sie HTTP-Umleitungen

- Achten Sie auf die URL-Konsistenz, um Angriffe wie DNS-Rebinding und „Time of Check, Time of Use“ (TOCTOU)-Race-Conditions zu vermeiden

Entschärfen Sie SSRF nicht durch die Verwendung einer Ablehnungsliste oder eines regulären Ausdrucks.
Angreifer verfügen über Payload-Listen, Tools und Fähigkeiten, um Deny-Listen zu umgehen.

### **Zusätzliche zu berücksichtigende Maßnahmen:**

- Stellen Sie keine anderen sicherheitsrelevanten Dienste auf Frontsystemen bereit (z. B. OpenID).
Kontrollieren Sie den lokalen Verkehr auf diesen Systemen (z. B. localhost).

- Für Frontends mit dedizierten und verwaltbaren Benutzergruppen nutzen Sie Netzwerkverschlüsselung (z. B. VPNs) auf unabhängigen Systemen, um sehr hohen Schutzbedarf zu berücksichtigen

## Beispielangriffsszenarien

Angreifer können SSRF verwenden, um Systeme anzugreifen, die hinter Webanwendungs-Firewalls, Firewalls oder Netzwerk-ACLs geschützt sind, und dabei Szenarien wie z
als:

**Szenario Nr. 1:** Port-Scan interner Server – Wenn die Netzwerkarchitektur nicht segmentiert ist, können Angreifer interne Netzwerke abbilden und anhand der Verbindungsergebnisse oder der verstrichenen Zeit für die Verbindung oder Ablehnung von SSRF-Nutzlastverbindungen feststellen, ob Ports auf internen Servern offen oder geschlossen sind .

**Szenario Nr. 2:** Offenlegung sensibler Daten – Angreifer können auf lokale Dateien oder interne Dienste zugreifen, um vertrauliche Informationen wie „file:///etc/passwd“ und „http://localhost:28017/“ zu erhalten.

**Szenario Nr. 3:** Zugriff auf Metadatenspeicher von Cloud-Diensten – Die meisten Cloud-Anbieter verfügen über Metadatenspeicher wie „http://169.254.169.254/“. Ein Angreifer kann die Metadaten lesen, um an vertrauliche Informationen zu gelangen.

**Szenario Nr. 4:** Kompromittierung interner Dienste – Der Angreifer kann interne Dienste missbrauchen, um weitere Angriffe wie Remote Code Execution (RCE) oder Denial of Service (DoS) durchzuführen.

## Verweise

- [OWASP – Spickzettel zur Verhinderung von Fälschungen auf Serverseite](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

- [PortSwigger – Serverseitige Anforderungsfälschung (SSRF)](https://portswigger.net/web-security/ssrf)

- [Acunetix – Was ist Server-Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

- [SSRF-Bibel](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

- [Eine neue Ära von SSRF – Nutzung des URL-Parsers in trendigen Programmiersprachen!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of- SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## Liste der zugeordneten CWEs

[CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
