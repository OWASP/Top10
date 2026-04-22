# A07:2025 – Fehlerhafte Authentifizierung ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## Hintergrund.

Fehlerhafte Authentifizierung behält mit einer leichten Namensänderung seinen Rang #7 bei, um die 36 CWEs dieser Kategorie präziser widerzuspiegeln. Trotz der Vorteile standardisierter Frameworks hat diese Kategorie ihren Rang #7 aus 2021 gehalten. Zu den relevanten CWEs zählen *CWE-259: Use of Hard-coded Password*, *CWE-297: Improper Validation of Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, *CWE-384: Session Fixation* sowie *CWE-798: Use of Hard-coded Credentials*.


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
   <td>36
   </td>
   <td>15.80%
   </td>
   <td>2.92%
   </td>
   <td>100.00%
   </td>
   <td>37.14%
   </td>
   <td>7.69
   </td>
   <td>4.44
   </td>
   <td>1,120,673
   </td>
   <td>7,147
   </td>
  </tr>
</table>



## Beschreibung.

Wenn ein Angreifer ein System dazu bringen kann, einen ungültigen oder nicht autorisierten Nutzer als legitim anzuerkennen, liegt diese Schwachstelle vor. Schwachstellen bei der Authentifizierung können auftreten, falls die Anwendung:

* automatisierte Angriffe wie Credential Stuffing ermöglicht, bei denen Angreifende über eine Liste bekannter Benutzernamen und Passwörter verfügen. Jüngst wurde diese Angriffsmethode um hybride Passwort-Angriffe erweitert (auch als Password-Spray-Angriffe bekannt), bei denen Angreifende Variationen kompromittierter Zugangsdaten verwenden, z. B. Password1!, Password2!, Password3! usw.

* Brute-Force- oder andere automatisierte, skriptbasierte Angriffe ermöglicht, die nicht schnell genug unterbunden werden.

* Standard-, schwache oder gängige Passwörter zulässt, wie z. B. „Password1" oder „admin/admin".

* die Erstellung neuer Konten mit bereits als kompromittiert bekannten Zugangsdaten zulässt.

* schwache oder ineffektive Verfahren zur Wiederherstellung von Anmeldeinformationen und Verfahren für vergessene Passwörter, wie z. B. „wissensbasierte Antworten", die nicht sicher gestaltet werden können.

* Klartext-, verschlüsselte oder schwach gehashte Kennwortdatenspeicher (siehe [A04:2025 – Fehlerhafter Einsatz von Kryptographie](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)) verwendet.

* fehlende oder unwirksame Multi-Faktor-Authentifizierung aufweist.

* schwache oder ineffektive Ausweichmechanismen zulässt, falls keine Multi-Faktor-Authentifizierung verfügbar ist.

* die Session-ID in der URL, einem versteckten Feld oder einer anderen unsicheren, für den Client zugänglichen Stelle offenlegt.

* dieselbe Session-ID nach erfolgreichem Login wiederverwendet.

* Benutzersitzungen oder Authentifizierungs-Tokens (hauptsächlich SSO-Tokens) beim Abmelden oder bei Inaktivität nicht korrekt invalidiert.

* den Scope und die vorgesehene Audience der bereitgestellten Zugangsdaten nicht korrekt prüft.

## Prävention und Gegenmaßnahmen.

* Wenn möglich, sollte eine Multi-Faktor-Authentifizierung implementiert und deren Nutzung durchgesetzt werden, um automatisiertes Credential Stuffing, Brute-Force-Angriffe und die Wiederverwendung gestohlener Zugangsdaten zu verhindern.

* Wenn möglich, die Nutzung von Passwort-Managern fördern und ermöglichen, um Nutzenden bessere Entscheidungen bei der Passwortwahl zu erleichtern.

* Liefern Sie die Anwendung nicht mit Standard Login-Daten aus, insbesondere nicht für Administrator-Konten.

* Implementieren Sie Prüfungen auf schwache Passwörter, wie z. B. durch den Vergleich von neuen oder geänderten Passwörtern mit der Liste der 10.000 schlechtesten Passwörter.

* Bei der Erstellung neuer Konten und Passwortänderungen Zugangsdaten gegen Listen bekannter kompromittierter Passwörter prüfen (z. B. mit [haveibeenpwned.com](https://haveibeenpwned.com)).

* Angleichung der Passwortlänge, -komplexität und -rotation an die Richtlinien des National Institute of Standards and Technology (NIST) 800-63b in [Abschnitt 5.1.1 „Memorized Secrets"](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) oder andere modernen, bewährten Passwortrichtlinien.

* Passwortrotation nicht erzwingen, es sei denn, es besteht ein Verdacht auf eine Kompromittierung. Bei Verdacht sofortige Passwort-Resets durchsetzen.

* Sicherstellen, dass die Registrierung, die Wiederherstellung von Zugangsdaten und die API-Pfade gegen Angriffe zur Ermittlung von Konten gehärtet sind, indem für alle Resultate die gleiche Nachricht ausgegeben wird („Ungültiger Benutzername oder Passwort.”).

* Begrenzen oder bremsen Sie fehlgeschlagene Anmeldeversuche immer weiter aus, aber achten Sie darauf, dass hierbei kein Denial-of-Service-Szenario entsteht. Loggen Sie alle Fehlversuche und alarmieren Sie die Administratoren, wenn Credential Stuffing, Brute Force oder andere Angriffe erkannt oder vermutet werden.

* Verwenden Sie einen serverseitigen, sicheren, integrierten Sitzungsmanager, der für jede Sitzung eine neue zufällige Sitzungs-ID mit hoher Entropie erzeugt. Die Sitzungs-ID sollte nicht in der URL enthalten sein, sicher in einem sicheren Cookie gespeichert und nach Abmeldung, Inaktivität und absoluten Timeouts invalidiert werden.

* Idealerweise ein bewährtes, vertrauenswürdiges System für Authentifizierung, Identitätsverwaltung und Session-Management verwenden. Dieses Risiko wann immer möglich durch den Einsatz eines gehärteten und gut getesteten Systems auslagern.

* Die vorgesehene Verwendung bereitgestellter Zugangsdaten prüfen, z. B. bei JWTs die `aud`- und `iss`-Claims sowie Scopes validieren.


## Beispielhafte Angriffsszenarien.

**Szenario Nr. 1:** Credential Stuffing, die Verwendung von Listen bekannter Benutzernamen- und Passwortkombinationen, ist heute ein sehr verbreiteter Angriff. Jüngst wurde beobachtet, dass Angreifende Passwörter basierend auf typischem menschlichem Verhalten „inkrementieren" oder abwandeln, z. B. von „Winter2025" zu „Winter2026" oder von „ILoveMyDog6" zu „ILoveMyDog7". Diese Methode wird als hybrider Credential-Stuffing-Angriff oder Password-Spray-Angriff bezeichnet und kann noch effektiver sein als die klassische Variante. Verfügt eine Anwendung über keine Abwehrmechanismen gegen automatisierte Angriffe oder Credential Stuffing, kann sie als Passwort-Orakel genutzt werden, um gültige Zugangsdaten zu ermitteln und unbefugten Zugriff zu erlangen.

**Szenario Nr. 2:** Die meisten erfolgreichen Authentifizierungsangriffe erfolgen aufgrund der andauernden Verwendung von Passwörtern als einzigem Authentifizierungsfaktor. Die früher als Best Practices geltenden Anforderungen an Passwortwechsel und -komplexität verleiten Nutzende sowohl zur Wiederverwendung als auch zur Wahl schwacher Passwörter. Organisationen wird empfohlen, diese Praktiken gemäß NIST 800-63 einzustellen und die Nutzung von Multi-Faktor-Authentifizierung auf allen wichtigen Systemen durchzusetzen.

**Szenario Nr. 3:** Die Session-Timeouts von Anwendungen sind nicht korrekt implementiert. Eine Nutzerin/Nutzer verwendet einen öffentlichen Computer und schließt die Browser-Registerkarte, anstatt sich abzumelden. Ein weiteres Beispiel: Eine SSO-Sitzung kann nicht per Single Logout (SLO) geschlossen werden – ein einzelner Login gewährt Zugang zu mehreren Systemen (z. B. E-Mail, Dokumente, Chat), aber der Logout erfolgt nur im aktuellen System. Greift ein Angreifer danach auf denselben Browser zu, hat er Zugriff auf alle noch aktiven Sitzungen. Dasselbe Problem kann in Büros auftreten, wenn eine sensible Anwendung nicht ordnungsgemäß beendet wurde und Kolleginnen oder Kollegen vorübergehend Zugriff auf den entsperrten Computer haben.

## Referenzen.

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## Liste der zugeordneten CWEs

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)