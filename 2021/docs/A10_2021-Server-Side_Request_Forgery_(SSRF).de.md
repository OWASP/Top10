---
source: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/"
title:  "A10:2021 – Server-Side Request Forgery (SSRF)"
id:     "A10:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".10" -%}
#A10:2021 – Server-Side Request Forgery (SSRF) ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib , id=id, name="Server-Side Request Forgery (SSRF)", lang=lang, source=source, parent=parent) }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 8.28                 | 6.72                | 67.72%       | 67.72%       | 9,503             | 385        |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ":Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Diese Kategorie stammt aus der Top-10-Community-Umfrage (Nr. 1). Die Daten zeigen eine relativ niedrige Häufigkeit bei überdurchschnittlicher Abdeckung und überdurchschnittlichen Bewertungen der Ausnutzbarkeit und Auswirkungen.
Um Aufmerksamkeit und Awareness zu erzeugen,
handelt es sich bei neuen Einträgen in die Top 10 oft um einzelne oder kleine Gruppen von Common Weakness Enumerations (CWEs) handelt.
Es besteht die Hoffnung, dass sie unter genauerer Betrachtung in einer zukünftigen Ausgabe in eine größere Kategorie zusammengefasst werden können.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ":Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

SSRF-Schwachstellen treten immer dann auf, wenn eine Webanwendung eine Remote-Ressource abruft, ohne die vom Benutzer angegebene URL zu überprüfen. Dadurch kann ein Angreifer die Anwendung dazu zwingen, eine manipulierte Anfrage an ein unerwartetes Ziel zu senden, selbst wenn sie durch eine Firewall, ein VPN oder eine andere Art von Netzwerkzugriffskontrollliste (ACL) geschützt ist.

Da moderne Webanwendungen Endbenutzern komfortable Funktionen bieten, wird das Abrufen einer URL zu einem gängigen Szenario. 
Infolgedessen nimmt die Häufigkeit von SSRF zu. 
Außerdem nimmt der Schweregrad von SSRF aufgrund von der Verbreitung von Cloud-Diensten und der Komplexität der Architekturen zu.

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ":Prävention und Gegenmaßnahmen", lang=lang, source=source ~ "#" ~id, parent=osib) }}

Entwickler können SSRF verhindern, indem sie folgende Defense-in-Depth-Controls implementieren:

### **Auf der Netzwerk-Ebene**

- Segmentieren Sie die Remote-Ressourcenzugriffsfunktionalität in separate Netzwerke, um die Auswirkungen von SSRF zu reduzieren.

- Erzwingen Sie „deny-by-default“-Firewall-Regeln oder Netzwerkzugriffskontrollregeln, um den gesamten Intranetverkehr jenseits des Wesentlichen zu blockieren.
<br/> *Hinweise:*<br> 
~ Etablieren Sie Ownership und einen Lebenszyklus für Firewall-Regeln passenend zu den Anwendungen.<br/ > 
~ Protokollieren Sie alle zugelassenen *und* blockierten Netzwerkflüsse auf den Firewalls 
(siehe [A09:2021 – Fehler beim Logging und Monitoring](A09_2021-Security_Logging_and_Monitoring_Failures.de.md)).

### **Auf der Anwendungsebene:**

- Bereinigen und validieren Sie alle vom Client bereitgestellten Eingabedaten.

- Erzwingen Sie das URL-Schema, den Port und das Ziel mit einer Positivliste.

- Senden Sie keine Rohantworten an Clients.

- Deaktivieren Sie HTTP-Redirects.

- Achten Sie auf die Konsistenz von URLs, um Angriffe wie DNS-Rebinding und „Time of Check, Time of Use“ (TOCTOU)-Race-Conditions zu vermeiden.

Versuchen Sie nicht, SSRF durch die Verwendung einer Negativliste oder eines regulären Ausdrucks zu mitigieren. 
Angreifer verfügen über Payload-Listen, Werkzeuge und Fähigkeiten, um Negativlisten zu umgehen.

### **Zusätzliche zu berücksichtigende Maßnahmen:**

- Bieten Sie keine anderen sicherheitsrelevanten Dienste auf Frontend-Systemen an (z. B. OpenID). 
Kontrollieren Sie den lokalen Verkehr auf diesen Systemen (z. B. localhost).

- Für Frontends mit dedizierten und verwaltbaren Benutzergruppen nutzen Sie Netzwerkverschlüsselung (z. B. VPNs) auf unabhängigen Systemen um sehr hohen Schutzbedarf zu berücksichtigen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ":Beispielhafte Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

Angreifer können SSRF verwenden, um Systeme anzugreifen, die durch Webanwendungs-Firewalls (WAFs), Firewalls oder Netzwerk-ACLs geschützt sind, mithilfe von Szenarios wie:

**Szenario Nr. 1:** Port-Scan interner Server – Wenn die Netzwerkarchitektur nicht segmentiert ist, können Angreifer interne Netzwerke abbilden und anhand der Verbindungsergebnisse oder der verstrichenen Zeit für die Verbindung oder Ablehnung von SSRF-Nutzlast-Verbindungen feststellen, ob Ports auf internen Servern offen oder geschlossen sind.

**Szenario Nr. 2:** Offenlegung sensibler Daten – Angreifer können auf lokale Dateien oder interne Dienste zugreifen, um vertrauliche Informationen wie „file:///etc/passwd“ und „http://localhost:28017/“ zu erhalten.

**Szenario Nr. 3:** Zugriff auf Metadatenspeicher von Cloud-Diensten – Die meisten Cloud-Anbieter verfügen über Metadatenspeicher wie „http://169.254.169.254/“. Ein Angreifer kann die Metadaten lesen, um an vertrauliche Informationen zu gelangen.

**Szenario Nr. 4:** Kompromittierung interner Dienste – Der Angreifer kann interne Dienste missbrauchen, um weitere Angriffe wie Remote Code Execution (RCE) oder Denial of Service (DoS) durchzuführen.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ":Referenzen", lang=lang, source=source ~ "#" ~ id, parent= osib) }}
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.server side request forgery prevention", osib=osib) }} <!--- [OWASP - Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) --->
-   {{ osib_link(link="osib.portswigger.web security.ssrf", osib=osib) }} <!--- [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf) --->
-   {{ osib_link(link="osib.acunetix.blog.ssrf", osib=osib) }} <!--- [Acunetix - What is Server-Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)  --->
-   {{ osib_link(link="osib.wallarm.ssrf bible.pdf", doc="osib.wallarm", osib=osib) }} <!--- [SSRF bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf) --->
-   {{ osib_link(link="osib.blackhat.us-17.ssrf.pdf", osib=osib) }} <!--- [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) --->


## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":Liste der zugeordneten CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}
- {{ osib_link(link="osib.mitre.cwe.0.918", doc="", osib=osib) }} <!-- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) -->
