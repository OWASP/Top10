# A07:2021 – Identifikations- und Authentifizierungsfehler ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 7.40                 | 6.50                | 79.51%       | 45.72%       | 132,195           | 3,897      |

## Überblick

Früher bekannt als *Broken Authentication*, ist diese Kategorie von der zweiten Position abgerutscht und umfasst nun Common Weakness Enumerations (CWEs) im Zusammenhang mit Identifikationsfehlern. Bemerkenswerte CWEs sind *CWE-297: Unsachgemäße Validierung des Zertifikats mit Host-Nichtübereinstimmung*, *CWE-287: Unsachgemäße Authentifizierung* und *CWE-384: Sitzungsfixierung*.

## Beschreibung

Die Bestätigung der Identität des Benutzers, die Authentifizierung und die Sitzungsverwaltung sind für den Schutz vor authentifizierungsbezogenen Angriffen von entscheidender Bedeutung. Es kann zu Authentifizierungsschwächen kommen, wenn die Anwendung:

– Automatisierte Angriffe wie Credential Stuffing ermöglicht, bei denen der Angreifer über eine Liste gültiger Benutzernamen und Passwörter verfügt.

- Brute-Force- oder andere automatisierte Angriffe ermöglicht.

– Standardmäßige, schwache oder bekannte Passwörter wie „Passwort1“ oder „admin/admin“ verwendet werden.

- Schwache oder ineffektive Verfahren zur Wiederherstellung von Anmeldeinformationen und zum Vergessen von Passwörtern, wie z. B. „wissensbasierte Antworten“, die nicht sicher gemacht werden können, verwendet werden.

– Reine Text-, verschlüsselte oder schwach gehashte Passwort-Datenspeicher (siehe [A02:2021-Cryptographic Failures](A02_2021-Cryptographic_Failures.md)) verwendet werden.

- Eine Multi-Faktor-Authentifizierung fehlt oder nur ineffektiv implementiert wurde.

– Die Sitzungskennung in der URL dargestellt wird.

- Die Sitzungskennung nach erfolgreicher Anmeldung wiederverwendet werden kann.

– Die Sitzungs-IDs nicht korrekt ungültig gemacht werden. Benutzersitzungen oder Authentifizierungstoken (hauptsächlich Single-Sign-On-Tokens (SSO)) werden beim Abmelden oder während eines Zeitraums der Inaktivität nicht ordnungsgemäß ungültig gemacht.

## Gegenmaßnahmen

- Implementieren Sie nach Möglichkeit eine Multi-Faktor-Authentifizierung, um automatisiertes Credential Stuffing, Brute Force und Angriffe auf die Wiederverwendung gestohlener Credentials zu verhindern.

– Setzen Sie keine Software ein, in der noch die Standardanmeldeinformationen verwendet werden, insbesondere nicht für Administratorbenutzer.

- Implementieren Sie schwache Passwortprüfungen, z. B. das Testen neuer oder geänderter Passwörter anhand der Liste der 10.000 schlechtesten Passwörter.

- Passen Sie die Richtlinien für Passwortlänge, -komplexität und -rotation an die Richtlinien des National Institute of Standards and Technology (NIST) 800-63b in Abschnitt 5.1.1 für gespeicherte Geheimnisse oder andere moderne, evidenzbasierte Passwortrichtlinien an.

– Stellen Sie sicher, dass die Registrierung, die Wiederherstellung von Anmeldeinformationen und die API-Pfade gegen "Account Enumeration"-Angriffe geschützt sind, indem Sie für alle Prüfungsergebnisse dieselbe Nachricht verwenden.

- Begrenzen sie die Anzahl oder verlängern Sie die Wartezeit Sie fehlgeschlagene Anmeldeversuche zunehmend, achten Sie jedoch darauf, kein Denial-of-Service-Szenario zu schaffen. Protokollieren Sie alle Fehler und benachrichtigen Sie Administratoren, wenn Credential Stuffing, Brute Force oder andere Angriffe erkannt werden.

- Verwenden Sie einen serverseitigen, sicheren, integrierten Sitzungsmanager, der nach der Anmeldung eine neue zufällige Sitzungs-ID mit hoher Entropie generiert. Die Sitzungskennung sollte nicht in der URL enthalten sein, sicher gespeichert und nach Abmeldung, Leerlauf und nach Überschreiten einer Gültigkeitsdauer ungültig gemacht werden.

## Beispielangriffsszenarien

**Szenario Nr. 1:** Credential Stuffing, die Verwendung von Listen bekannter Passwörter, ist ein häufiger Angriff. Angenommen, eine Anwendung implementiert keinen automatisierten Bedrohungs- oder Credential-Stuffing-Schutz. In diesem Fall kann die Anwendung als Passwort-Orakel verwendet werden, um festzustellen, ob die Anmeldeinformationen gültig sind.

**Szenario Nr. 2:** Die meisten Authentifizierungsangriffe erfolgen aufgrund der kontinuierlichen Verwendung von Passwörtern als einzigem Faktor. Einmal als Best Practices betrachtet, ermutigen Anforderungen an die Passwortänderungen und -komplexität Benutzer dazu, schwache Passwörter zu verwenden und wiederzuverwenden. Organisationen wird empfohlen, diese Praktiken gemäß NIST 800-63 zu stoppen und eine Multi-Faktor-Authentifizierung zu verwenden.

**Szenario Nr. 3:** Die Maximaldauer für Anwendungssitzungen ist nicht richtig eingestellt. Ein Benutzer verwendet einen öffentlichen Computer, um auf eine Anwendung zuzugreifen. Anstatt „Abmelden“ auszuwählen, schließt der Benutzer einfach den Browser-Tab und geht weg. Eine Stunde später verwendet ein Angreifer denselben Browser und der Benutzer ist immer noch authentifiziert.

## Referenzen

- [OWASP Proactive Controls: Digitale Identität implementieren](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

- [OWASP Application Security Verification Standard: V2-Authentifizierung](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Application Security Verification Standard: V3 Session Management](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP-Testleitfaden: Identität](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Authentifizierung](https:// owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

- [OWASP-Spickzettel: Authentifizierung](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

- [OWASP-Spickzettel: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

- [OWASP-Spickzettel: Passwort vergessen](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

- [OWASP-Spickzettel: Sitzungsverwaltung](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

- [OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)

## Liste der zugeordneten CWEs

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Verwendung eines hartcodierten Passworts](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Unsachgemäße Authentifizierung](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288-Authentifizierungsumgehung mithilfe eines alternativen Pfads oder Kanals](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290-Authentifizierungsumgehung durch Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294-Authentifizierungsumgehung durch Capture-Replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Unsachgemäße Zertifikatsvalidierung](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Unsachgemäße Validierung des Zertifikats mit Host-Nichtübereinstimmung](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300-Kanal, auf den Nicht-Endpunkte zugreifen können](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302-Authentifizierungsumgehung durch angenommene unveränderliche Daten](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Fehlender kritischer Schritt bei der Authentifizierung](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Fehlende Authentifizierung für kritische Funktion](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Unsachgemäße Beschränkung übermäßiger Authentifizierungsversuche](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Ursprungsvalidierungsfehler](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384-Sitzungsfixierung](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521-Anforderungen für schwache Passwörter](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Unzureichender Sitzungsablauf](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 nicht bestätigte Passwortänderung](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Schwacher Passwort-Wiederherstellungsmechanismus für vergessenes Passwort](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Verwendung von hartcodierten Anmeldeinformationen](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Unsachgemäße Überprüfung der Quelle eines Kommunikationskanals](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216-Sperrmechanismusfehler](https://cwe.mitre.org/data/definitions/1216.html)
