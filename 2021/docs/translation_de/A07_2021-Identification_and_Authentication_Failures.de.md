---
source: "https://owasp.org/Top10/A07_2021-identification_and_Authentication_Failures/“
title: "A07:2021 – Fehler in der Identifikation und Authentifizierung“
id: "A07:2021“
lang:	"de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".7" -%}
#A07:2021 – Fehler in der Authentifizierung ![icon](assets/TOP_10_Icons_Final_identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id , name="identifizierungs- und Authentifizierungsfehler", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.2") }}


## Faktoren {{ osib_anchor(osib=osib~".factors", id=id~"-factors", name=title~":Factors", aussehen=appearance, source=source~"#"~id, parent= osib) }}

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 7.40                 | 6.50                | 79.51%       | 45.72%       | 132,195           | 3,897      |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Früher bekannt als *Fehler in der Authentifizierung*, ist diese Kategorie von der zweiten Position abgerutscht und umfasst nun Common Weakness Enumerations (CWEs) im Zusammenhang mit identifikationsfehlern. Bemerkenswerte CWEs sind *CWE-297: Unsachgemäße Validierung des Zertifikats mit Host-Nichtübereinstimmung*, *CWE-287: Unsachgemäße Authentifizierung* und *CWE-384: Sitzungsfixierung*.

## Ist die Anwendung verwundbar {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Die Bestätigung der identität des Benutzers, die Authentifizierung und die Sitzungsverwaltung sind für den Schutz vor authentifizierungsbezogenen Angriffen von entscheidender Bedeutung. Es kann zu Authentifizierungsschwächen kommen, wenn die Anwendung:

– Ermöglicht automatisierte Angriffe wie Credential Stuffing, bei denen der Angreifer über eine Liste gültiger Benutzernamen und Passwörter verfügt.

- Ermöglicht Brute-Force- oder andere automatisierte Angriffe.

– Ermöglicht standardmäßige, schwache oder bekannte Passwörter wie „Passwort1“ oder „admin/admin“.

- Verwendet schwache oder ineffektive Verfahren zur Wiederherstellung von Anmeldeinformationen und zum Vergessen von Passwörtern, wie z. B. „wissensbasierte Antworten“, die nicht sicher gemacht werden können.

– Verwendet reine Text-, verschlüsselte oder schwach gehashte Passwort-Datenspeicher (siehe [A02:2021-Fehlkonfiguration der Sicherheit](A02_2021-Cryptographic_Failures.md)).

- Fehlende oder ineffektive Multi-Faktor-Authentifizierung.

– Legt die Sitzungskennung in der URL offen.

- Sitzungskennung nach erfolgreicher Anmeldung wiederverwenden.

– Sitzungs-ids werden nicht korrekt ungültig gemacht. Benutzersitzungen oder Authentifizierungstoken (hauptsächlich Single-Sign-On-Tokens (SSO)) werden beim Abmelden oder während eines Zeitraums der Inaktivität nicht ordnungsgemäß ungültig gemacht.

## Wie kann ich das verhindern {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": How to Prevent", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

- Implementieren Sie nach Möglichkeit eine Multi-Faktor-Authentifizierung, um automatisiertes Credential Stuffing, Brute Force und Angriffe auf die Wiederverwendung gestohlener Credentials zu verhindern.

– Nicht mit Standardanmeldeinformationen versenden oder bereitstellen, insbesondere nicht für Administratorbenutzer.

- Implementieren Sie schwache Passwortprüfungen, z. B. das Testen neuer oder geänderter Passwörter anhand der Liste der 10.000 schlechtesten Passwörter.

- Passen Sie die Richtlinien für Passwortlänge, -komplexität und -rotation an die Richtlinien des National Institute of Standards and Technology (NIST) 800-63b in Abschnitt 5.1.1 für gespeicherte Geheimnisse oder andere moderne, evidenzbasierte Passwortrichtlinien an.

– Stellen Sie sicher, dass die Registrierung, die Wiederherstellung von Anmeldeinformationen und die API-Pfade gegen Kontoaufzählungsangriffe geschützt sind, indem Sie für alle Ergebnisse dieselben Nachrichten verwenden.

- Begrenzen oder verzögern Sie fehlgeschlagene Anmeldeversuche zunehmend, achten Sie jedoch darauf, kein Denial-of-Service-Szenario zu schaffen. Protokollieren Sie alle Fehler und benachrichtigen Sie Administratoren, wenn Credential Stuffing, Brute Force oder andere Angriffe erkannt werden.

- Verwenden Sie einen serverseitigen, sicheren, integrierten Sitzungsmanager, der nach der Anmeldung eine neue zufällige Sitzungs-id mit hoher Entropie generiert. Die Sitzungskennung sollte nicht in der URL enthalten sein, sicher gespeichert und nach Abmeldung, Leerlauf und absoluten Zeitüberschreitungen ungültig gemacht werden.

## Beispiel-Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Credential Stuffing, die Verwendung von Listen bekannter Passwörter, ist ein häufiger Angriff. Angenommen, eine Anwendung implementiert keinen automatisierten Bedrohungs- oder Credential-Stuffing-Schutz. In diesem Fall kann die Anwendung als Passwort-Orakel verwendet werden, um festzustellen, ob die Anmeldeinformationen gültig sind.

**Szenario Nr. 2:** Die meisten Authentifizierungsangriffe erfolgen aufgrund der fortgesetzten Verwendung von Passwörtern als einzigem Faktor. Einmal als Best Practices betrachtet, ermutigen Anforderungen an die Passwortrotation und -komplexität Benutzer dazu, schwache Passwörter zu verwenden und wiederzuverwenden. Organisationen wird empfohlen, diese Praktiken gemäß NIST 800-63 zu stoppen und die Multi-Faktor-Authentifizierung zu verwenden.

**Szenario Nr. 3:** Zeitüberschreitungen für Anwendungssitzungen sind nicht richtig eingestellt. Ein Benutzer verwendet einen öffentlichen Computer, um auf eine Anwendung zuzugreifen. Anstatt „Abmelden“ auszuwählen, schließt der Benutzer einfach den Browser-Tab und geht weg. Eine Stunde später verwendet ein Angreifer denselben Browser und der Benutzer ist immer noch authentifiziert.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3.6", osib=osib) }} <!-- [OWASP Proaktive Kontrollen: Digitale identität implementieren](https://owasp.org/www-project-proactive -controls/v3/en/c6-digital-identity) ->
- {{ osib_link(link="osib.owasp.asvs.4-0.2", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V2-Authentifizierung](https://owasp.org/www- project-application-security-verification-standard) ->
- {{ osib_link(link="osib.owasp.asvs.4-0.3", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V3 Session Management](https://owasp.org/www -project-application-security-verification-standard) ->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.3", osib=osib) }}, <!-- [OWASP-Testleitfaden: identität](https://owasp.org/www- project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-identity_Management_Testing/README) --> {{ osib_link(link= "osib.owasp.wstg.4-2.4.4", doc="", osib=osib) }} <!-- [Authentifizierung ](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) -->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.Authentication", osib=osib) }} <!-- [OWASP Cheat Sheet: Authentifizierung](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet .html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.Credential Stuffing Prevention", osib=osib) }} <!-- [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/ (Cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.Forgot Password", osib=osib) }} <!-- [OWASP Cheat Sheet: Passwort vergessen](https://cheatsheetseries.owasp.org/cheatsheets /Forgot_Password_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0.Session Management", osib=osib) }} <!-- [OWASP Cheat Sheet: Sitzungsverwaltung](https://cheatsheetseries.owasp.org/cheatsheets /Session_Management_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.oat", osib=osib) }} <!--- OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to- Webanwendungen/)a --->
- {{ osib_link(link="osib.nist.csrc.sp.800-63b.5.1.1", doc="osib.nist.csrc.sp.800-63b", osib=osib) }} <!- -- [NIST 800-63b: 5.1.1 Auswendig gelernte Geheimnisse](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) --->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.255", doc="", osib=osib) }} <!-- [CWE-255: Fehler bei der Verwaltung von Anmeldeinformationen](https://cwe.mitre. org/data/definitions/255.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.259", doc="", osib=osib) }} <!-- [CWE-259: Verwendung eines hartcodierten Passworts](https://cwe .mitre.org/data/definitions/259.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.287", doc="", osib=osib) }} <!-- [CWE-287: Unsachgemäße Authentifizierung](https://cwe.mitre.org /data/definitions/287.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.288", doc="", osib=osib) }} <!-- [CWE-288: Authentifizierungsumgehung mithilfe eines alternativen Pfads oder Kanals](https:/ /cwe.mitre.org/data/definitions/288.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.290", doc="", osib=osib) }} <!-- [CWE-290: Authentifizierungsumgehung durch Spoofing](https://cwe.mitre .org/data/definitions/290.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.294", doc="", osib=osib) }} <!-- [CWE-294: Authentifizierungsumgehung durch Capture-Replay](https://cwe .mitre.org/data/definitions/294.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.295", doc="", osib=osib) }} <!-- [CWE-295: Unsachgemäße Zertifikatsvalidierung](https://cwe.mitre. org/data/definitions/295.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.297", doc="", osib=osib) }} <!-- [CWE-297: Unsachgemäße Validierung des Zertifikats mit Host-Konflikt](https:// cwe.mitre.org/data/definitions/297.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.300", doc="", osib=osib) }} <!-- [CWE-300: Kanal, auf den kein Endpunkt zugreifen kann](https://cwe .mitre.org/data/definitions/300.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.302", doc="", osib=osib) }} <!-- [CWE-302: Authentifizierungsumgehung durch angenommene unveränderliche Daten](https:// cwe.mitre.org/data/definitions/302.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.304", doc="", osib=osib) }} <!-- [CWE-304: Kritischer Schritt bei der Authentifizierung fehlt](https://cwe. mitre.org/data/definitions/304.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.306", doc="", osib=osib) }} <!-- [CWE-306: Fehlende Authentifizierung für kritische Funktion](https://cwe. mitre.org/data/definitions/306.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.307", doc="", osib=osib) }} <!-- [CWE-307: Unsachgemäße Einschränkung übermäßiger Authentifizierungsversuche](https://cwe .mitre.org/data/definitions/307.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.346", doc="", osib=osib) }} <!-- [CWE-346: Ursprungsvalidierungsfehler](https://cwe.mitre. org/data/definitions/346.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.384", doc="", osib=osib) }} <!-- [CWE-384: Sitzungsfixierung](https://cwe.mitre.org /data/definitions/384.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.521", doc="", osib=osib) }} <!-- [CWE-521: Schwache Passwortanforderungen](https://cwe.mitre. org/data/definitions/521.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.613", doc="", osib=osib) }} <!-- [CWE-613: Unzureichender Sitzungsablauf](https://cwe.mitre. org/data/definitions/613.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.620", doc="", osib=osib) }} <!-- [CWE-620: Nicht bestätigte Passwortänderung](https://cwe.mitre. org/data/definitions/620.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.640", doc="", osib=osib) }} <!-- [CWE-640: Schwacher Passwort-Wiederherstellungsmechanismus für vergessenes Passwort](https:// cwe.mitre.org/data/definitions/640.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.798", doc="", osib=osib) }} <!-- [CWE-798: Verwendung von hartcodierten Anmeldeinformationen](https://cwe .mitre.org/data/definitions/798.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.940", doc="", osib=osib) }} <!-- [CWE-940: Unsachgemäße Überprüfung der source eines Kommunikationskanals](https:/ /cwe.mitre.org/data/definitions/940.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.1216", doc="", osib=osib) }} <!-- [CWE-1216: Fehler beim Sperrmechanismus](https://cwe.mitre. org/data/definitions/1216.html) ->
