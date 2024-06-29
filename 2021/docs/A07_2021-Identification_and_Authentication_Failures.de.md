---
source: "https://owasp.org/Top10/A07_2021-identification_and_Authentication_Failures/"
title:  "A07:2021 – Fehlerhafte Authentifizierung"
id:     "A07:2021"
lang:   "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".7" -%}
#A07:2021 – Fehlerhafte Authentifizierung ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id , name="Fehlerhafte Authentifizierung", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.2") }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84 %             | 2.55 %              | 7.40                 | 6.50                | 79.51 %       | 45.72 %       | 132,195           | 3,897      |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ":Bezug / Kontext / Auswertung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Diese Kategorie, die früher als *Broken Authentication* bekannt war, rutschte von der zweiten Position nach unten und umfasst nun Common Weakness Enumerations (CWEs) im Zusammenhang mit Identifikationsfehlern. Die bedeutendsten CWEs sind
-   *{{ osib_link(link="osib.mitre.cwe.0.297", doc="", osib=osib) }}* <!-- *CWE-297: Improper Validation of Certificate with Host Mismatch*, -->
-   *{{ osib_link(link="osib.mitre.cwe.0.287", doc="", osib=osib) }}* und <!-- *CWE-287: Improper Authentication* und -->
-   *{{ osib_link(link="osib.mitre.cwe.0.384", doc="", osib=osib) }}* <!-- *CWE-384: Session Fixation*. -->

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Die Überprüfung der Identität des Benutzers, die Authentifizierung und die Sitzungsverwaltung sind entscheidend für den Schutz vor authentifizierungsbezogenen Angriffen. Schwachstellen bei der Authentifizierung können auftreten, falls die Anwendung:

- automatisierte Angriffe wie Credential Stuffing zulässt, bei dem der Angreifer über eine Liste gültiger Benutzernamen und Passwörter verfügt.

- Brute-Force- oder andere automatisierte Angriffe ermöglicht.

- Standard-, schwache oder gängige Passwörter zulässt, wie z. B. "Passwort1" oder "admin/admin".

- schwache oder ineffektive Verfahren zur Wiederherstellung von Anmeldeinformationen  und   Verfahren für vergessene Passwörtern, wie z. B. „wissensbasierte Antworten“, die nicht sicher gemacht werden können, 
verwendet werden.

-  Klartext-, verschlüsselte oder schwach gehashte Kennwortdatenspeicher (siehe
    [A02:2021-Cryptographic Failures](A02_2021-Cryptographic_Failures.md)) verwendet.

- Fehlende oder unwirksame Multi-Faktor-Authentifizierung.

- Die Session-ID wird in der URL angezeigt.

- Session-IDs nach erfolgreichem Login wieder verwendet werden.

- Session-IDs werden nicht korrekt ungültig gemacht. Benutzersitzungen oder Authentifizierungs-Tokens (hauptsächlich Single Sign-On (SSO) Tokens) werden beim  Abmelden oder bei Inaktivität nicht ordnungsgemäß invalidiert.

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": Prävention und Gegenmaßnahmen", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

- Wenn möglich, sollte eine Multi-Faktor-Authentifizierung implementiert werden, um automatisiertes Credential Stuffing, Brute Force-Angriffe und die Wiederverwendung gestohlener Zugangsdaten zu verhindern.

- Liefern Sie die Anwendung nicht mit Standard Login-Daten aus, insbesondere nicht für Administrator-Benutzer.

- Implementieren Sie Prüfungen auf schwache Passwörter, wie z. B. durch den Vergleich von neuen oder geänderten Passwörtern mit der Liste der 10.000 schlechtesten Passwörter.

- Angleichung der Passwortlänge, -komplexität und -rotation an die Richtlinien des National Institute of Standards and Technology (NIST) 800-63b in Abschnitt 5.1.1 "Memorized Secrets" oder andere modernen, bewährten Passwortrichtlinien.

- Sicherstellen, dass die Registrierung, die Wiederherstellung von Zugangsdaten und die API-Pfade gegen Angriffe zur Ermittlung von Benutzerkonten gehärtet sind, indem für alle Resultate die gleiche Nachricht ausgegeben wird.

- Begrenzen oder bremsen Sie fehlgeschlagene Anmeldeversuche immer weiter aus, aber achten Sie darauf, dass hierbei kein Denial-of-Service-Szenario entsteht. Loggen Sie alle Fehlversuche und alarmieren Sie die Administratoren, wenn Credential Stuffing, Brute Force oder andere Angriffe erkannt werden.

- Verwenden Sie einen serverseitigen, sicheren, integrierten Sitzungsmanager, der für jede Sitzung eine neue zufällige Sitzungs-ID mit hoher Entropie erzeugt. Die Sitzungs-ID sollte nicht in der URL enthalten sein, sicher gespeichert werden und nach Abmeldung, Inaktivität und Absoluten Timeouts entwertet werden.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1:** Credential Stuffing, die Verwendung von Listen mit bekannten Kennwörtern, ist ein gängiger Angriff. Angenommen, eine Anwendung verfügt keinen automatischen Schutz vor Bedrohungen oder Credential Stuffing. In diesem Fall kann die Anwendung als Passwort-Orakel verwendet werden, um festzustellen, ob die Anmeldeinformationen gültig sind.

**Szenario #2:** Die meisten Authentifizierungsangriffe erfolgen aufgrund der andauernden Verwendung von Kennwörtern als einzigem Zugangsmerkmal. Die früher als Best Practices geltenden Anforderungen an den Wechsel und die Komplexität von Passwörtern verleiten die Benutzer zur Verwendung und Wiederverwendung schwacher Passwörter. Organisationen wird empfohlen, diese Praktiken gemäß NIST 800-63 einzustellen und eine Mehrfaktor-Authentifizierung zu verwenden.

**Szenario #3:** Die Session-Timeouts von Anwendungen sind nicht korrekt gesetzt. Ein Benutzer verwendet einen öffentlichen Computer, um auf eine Anwendung zuzugreifen. Anstatt sich abzumelden, schließt der Benutzer einfach die Browser-Registerkarte und geht weg. Ein Angreifer verwendet denselben Browser eine Stunde später, und der Benutzer ist noch immer authentifiziert.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": Referenzen", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

-   {{ osib_link(link="osib.owasp.opc.3.6", osib=osib) }} <!-- [OWASP Proactive Controls: Implement Digital Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.2", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V2 authentication](https://owasp.org/www-project-application-security-verification-standard) -->
-   {{ osib_link(link="osib.owasp.asvs.4-0.3", osib=osib) }} <!-- [OWASP Application Security Verification Standard: V3 Session Management](https://owasp.org/www-project-application-security-verification-standard) -->
-   {{ osib_link(link="osib.owasp.wstg.4-2.4.3", osib=osib) }}, <!-- [OWASP Testing Guide: Identity ](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README) --> {{ osib_link(link= "osib.owasp.wstg.4-2.4.4", doc="", osib=osib) }} <!-- [Authentication ](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Authentication", osib=osib) }} <!-- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Credential Stuffing Prevention", osib=osib) }} <!-- [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Forgot Password", osib=osib) }} <!-- [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.cheatsheetseries.0.Session Management", osib=osib) }} <!-- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) -->
-   {{ osib_link(link="osib.owasp.oat", osib=osib) }} <!-- OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/) -->
-   {{ osib_link(link="osib.nist.csrc.sp.800-63b.5.1.1", doc="osib.nist.csrc.sp.800-63b", osib=osib) }} <!-- [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) -->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":Liste der zugeordneten CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

-   {{ osib_link(link="osib.mitre.cwe.0.255", doc="", osib=osib) }} <!-- [CWE-255: Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.259", doc="", osib=osib) }} <!-- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.287", doc="", osib=osib) }} <!-- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.288", doc="", osib=osib) }} <!-- [CWE-288: Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.290", doc="", osib=osib) }} <!-- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.294", doc="", osib=osib) }} <!-- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.295", doc="", osib=osib) }} <!-- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.297", doc="", osib=osib) }} <!-- [CWE-297: Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.300", doc="", osib=osib) }} <!-- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.302", doc="", osib=osib) }} <!-- [CWE-302: Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.304", doc="", osib=osib) }} <!-- [CWE-304: Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.306", doc="", osib=osib) }} <!-- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.307", doc="", osib=osib) }} <!-- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.346", doc="", osib=osib) }} <!-- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.384", doc="", osib=osib) }} <!-- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.521", doc="", osib=osib) }} <!-- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.613", doc="", osib=osib) }} <!-- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.620", doc="", osib=osib) }} <!-- [CWE-620: Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.640", doc="", osib=osib) }} <!-- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.798", doc="", osib=osib) }} <!-- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.940", doc="", osib=osib) }} <!-- [CWE-940: Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html) -->
-   {{ osib_link(link="osib.mitre.cwe.0.1216", doc="", osib=osib) }} <!-- [CWE-1216: Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html) -->
