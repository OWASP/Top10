# A04:2025 Fehlerhafter Einsatz von Kryptographie ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## Hintergrund. 

Diese Schwachstelle ist um zwei Plätze auf Rang 4 zurückgefallen und konzentriert sich auf Fehler im Zusammenhang mit fehlender Kryptografie, unzureichend starker Kryptografie, dem Verlust kryptografischer Schlüssel und damit verbundenen Fehlern. Drei der häufigsten Common Weakness Enumerations (CWEs) in diesem Risikobereich betrafen die Verwendung eines schwachen Pseudozufallszahlengenerators:  *CWE-327 Use of a Broken or Risky Cryptographic Algorithm, CWE-331: Insufficient Entropy*, *CWE-1241: Use of Predictable Algorithm in Random Number Generator*, and *CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)*.



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
   <td>32
   </td>
   <td>13.77%
   </td>
   <td>3.80%
   </td>
   <td>100.00%
   </td>
   <td>47.74%
   </td>
   <td>7.23
   </td>
   <td>3.90
   </td>
   <td>1,665,348
   </td>
   <td>2,185
   </td>
  </tr>
</table>



## Beschreibung. 

Generell sollten alle Daten während der Übertragung auf der Transportschicht ([OSI-Schicht](https://de.wikipedia.org/wiki/OSI-Modell) 4) verschlüsselt werden. Frühere Hindernisse wie die CPU-Leistung werden nun durch CPUs bewältigt, die über Hardwarebeschleunigung der Verschlüsselung verfügen (z. B.: [AES-Unterstützung](https://en.wikipedia.org/wiki/AES_instruction_set)), und die Verwaltung privater Schlüssel und Zertifikate wird durch Dienste wie [LetsEncrypt.org](https://LetsEncrypt.org) vereinfacht, wobei große Cloud-Anbieter noch stärker integrierte Zertifikatsverwaltungsdienste für ihre spezifischen Plattformen bereitstellen. 

Neben der Absicherung der Transportschicht ist es wichtig zu ermitteln, welche Daten im Ruhezustand verschlüsselt werden müssen und welche Daten während der Übertragung (auf der [Anwendungsschicht](https://en.wikipedia.org/wiki/Application_layer), OSI-Schicht 7) zusätzlich verschlüsselt werden müssen. Beispielsweise erfordern Passwörter, Kreditkartennummern, Gesundheitsakten, persönliche Informationen und Geschäftsgeheimnisse zusätzlichen Schutz, vor allem dann, wenn diese Daten unter Datenschutzgesetze, z. B. die Datenschutz-Grundverordnung (DSGVO) der EU, oder andere Vorschriften fallen, beispielsweise dem Payment Card Industry Data Security Standard (PCI-DSS). 

Folgendes ist zu klären:

* Werden alte oder schwache kryptografische Algorithmen oder Protokolle verwendet, z. B. per Default-Einstellung oder in älterem Code?
* Werden vordefinierte kryptografische Schlüssel verwendet, schwache Schlüssel generiert oder Schlüssel wiederverwendet? Fehlt eine Schlüsselverwaltung oder Schlüsselrotation? 
* Werden kryptografische Schlüssel in Quellcode-Repositories eingecheckt?
* Wird Verschlüsselung nicht verbindlich erzwungen, z. B. fehlen bei Web Anwendungen Vorgaben für den Browser in den entsprechenden HTTP-Headern?
* Werden empfangene Serverzertifikate und die Zertifikatskette korrekt validiert
* Werden Initialisierungsvektoren ignoriert, wiederverwendet oder nicht ausreichend sicher für den kryptografischen Betriebsmodus generiert? Ist ein unsicherer Betriebsmodus wie ECB im Einsatz? Wird ein Betriebsmodus verwendet, der nur verschlüsselt, obwohl ein AEAD Betriebsmodus angebracht wäre, der auch die Integrität schützt?
* Werden Passwörter direkt als kryptografische Schlüssel verwendet ohne eine Schlüsselableitung mittels Key Derivation Function?
* Werden Zufallszahlen für kryptografische Zwecke genutzt, die nicht auf kryptografische Anforderungen ausgelegt sind? Selbst wenn die richtige Funktion genutzt wird, muss diese eventuell vom Entwickler korrekt initialisiert werden. Wurde eine integrierte starke Initialisierung eventuell durch einen Entwickler mit einem schwachen Wert überschrieben, dem es an ausreichender Entropie und Nichtvorhersehbarkeit mangelt?
* Werden Hash-Funktionen mit bekannten Schwächen wie MD5 oder SHA1 verwendet oder werden nicht-kryptografische Hash-Funktionen verwendet, wenn kryptografische Hash-Funktionen benötigt werden?
* Sind kryptografische Fehlermeldungen oder Seitenkanäle ausnutzbar, beispielsweise in Form von Padding-Oracle-Angriffen?
* 

* Are cryptographic error messages or side channel information exploitable, for example in the form of padding oracle attacks?
* Kann der eingesetzte kryptografische Algorithmus abgeschwächt oder umgangen werden?

Siehe ASVS: Cryptography (V11), Secure Communication (V12) and Data Protection (V14).


## Prävention und Gegenmaßnahmen. 

Gehen Sie als Minimum wie folgt vor und konsultieren Sie die Referenzen:

* Klassifizieren Sie die Daten, die von einer Anwendung verarbeitet, gespeichert oder übermittelt werden
nach ihrem Schutzbedarf. Berücksichtigen Sie dabei auch Datenschutzgesetze, regulatorische und Geschäfts-Anforderungen.
* Speichern Sie Ihre sensibelsten Schlüssel in einem Hardware- oder cloudbasierten HSM.
* Verwenden Sie nach Möglichkeit überall bewährte Implementierungen kryptografischer Algorithmen
* Speichern Sie sensible Daten nicht unnötig. Löschen Sie sensible Daten auf sichere Weise sobald wie möglich oder verwenden Sie Techniken wie PCI-DSS-konformes Speichern von Ersatzwerten (tokenization) oder gar gekürzten (truncation) Werten.
Daten, die es nicht mehr gibt, können auch nicht gestohlen werden.
* Stellen Sie sicher, dass alle vertraulichen Daten bei Speicherung verschlüsselt werden.
* Stellen Sie sicher, dass aktuelle, starke, standardisierte Algorithmen, Protokolle und Schlüssel, z. B. gemäß BSI TR-02102, verwendet werden. Etablieren Sie wirksames Schlüsselmanagement für kryptografische Schlüssel.
* Verschlüsseln Sie alle Daten während der Übertragung mit TLS >= 1.2, die Forward Secrecy (FS) bieten, deaktivieren Sie die Unterstützung von cipher block chaining (CBC) Chiffren, unterstützen Sie quantensichere Schlüsselaustauschverfahren. Erzwingen Sie die Verschlüsselung durch HTTP Strict Transport Security (HSTS). Prüfen Sie die Einstellungen mit einem Tool.
* Deaktivieren Sie das Caching für Antworten mit vertraulichen Daten. Dazu gehören das Caching in Ihrem CDN, auf Ihrem Webserver sowie jegliches Anwendungs-Caching (z. B. Redis).
* Wenden Sie die Sicherheitsmaßnahmen gemäß dem Schutzbedarf der Datenklassifizierung an.
* Verwenden Sie keine unverschlüsselten Protokolle wie FTP und STARTTLS. Vermeiden Sie die Verwendung von SMTP für die Übertragung vertraulicher Daten.
* Verwenden Sie spezielle Hash-Funktionen für das Hashen von Passwörtern, bei denen für jedes Passwort ein Salt-Wert (salted hash) und Rechenaufwand (work-factor) zum Einsatz kommt. Beispiele sind: Argon2, yescrypt, scrypt, PBKDF2-HMAC-SHA-512. Für Altsysteme, die bcrypt verwenden, finden Sie weitere Hinweise unter [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* Initialisierungsvektoren müssen passend zum kryptografischen Betriebsmodus gewählt werden. In vielen Fällen bedeutet dies, dass ein CSPRNG (kryptografisch sicherer Pseudozufallszahlengenerator) für die Generierung des Initialisierungsvektors verwendet wird. Für Modi, die eine Nonce erfordern, benötigt der Initialisierungsvektor nicht notwendigerweise einen CSPRNG. In allen Fällen darf der gleiche Initialisierungsvektor niemals zweimal für den gleichen Schlüssel verwendet werden.
* Verwenden Sie immer eine authentifizierte Verschlüsselung statt nur einer Verschlüsselung.
* Schlüssel sollten kryptografisch zufällig generiert und als Byte-Arrays im Speicher gehalten werden. Wenn ein Passwort zur Verschlüsselung verwendet werden soll, muss über eine Funktion zur Schlüsselableitung ein Schlüssel generiert werden.
* Stellen Sie sicher, dass an den notwendigen Stellen kryptografisch sichere, unvorhersagbare Zufallszahlen verwendet werden, und dass der Pseudozufallszahlengenerator nicht auf vorhersehbare Weise oder nur mit geringer Entropie initialisiert wurde. Bei den meisten modernen APIs muss der Entwickler die Initialisierung des Pseudozufallszahlengenerators (CSPRNG) nicht manuell durchführen.
* Vermeiden Sie veraltete kryptografische Funktionen und Padding-Verfahren wie MD5, SHA1, Cipher Block Chaining Mode (CBC), PKCS Nummer 1 v1.5.
* Stellen Sie sicher, dass Einstellungen und Konfigurationen den Sicherheitsanforderungen entsprechen, indem Sie sie von Sicherheitsspezialisten, speziell dafür entwickelten Tools oder beidem überprüfen lassen.
* Sie müssen sich bereits jetzt auf die Post-Quanten-Kryptografie (PQC) vorbereiten (siehe Referenz (ENISA)), damit risikoreiche Systeme spätestens bis Ende 2030 sicher sind.




## Example attack scenarios. 

**Scenario #1**: Eine Webseite benutzt kein TLS, erzwingt dies nicht auf allen Seiten oder lässt schwache Verschlüsselung zu. Die angreifende Person liest die Kommunikation mit (z. B. in einem offenen WLAN), ersetzt HTTPS- durch HTTP-Verbindungen, hört diese ab und stiehlt das Sitzungscookie. Durch Wiedereinspielen dieses Cookies übernimmt die angreifende Person die (authentifizierte) Sitzung des Nutzers und erlangt Zugriff auf dessen private Daten. Anstatt dessen kann die angreifende Person auch die übertragenen Daten ändern, z. B. den Empfänger einer Überweisung.

**Scenario #2**: Die Passwortdatenbank benutzt einfache Hashwerte oder Hashes ohne Salt zur Speicherung der Passwörter. Eine Schwachstelle in der Uploadfunktion erlaubt Angreifenden den Zugriff auf die Passwortdatei. Zu Hashes ohne Salt kann über vorausberechnete Rainbow-Tabellen der Klartext gefunden werden. Hashes, die über einfache oder schnelle Funktionen berechnet wurden, können effizient mit Grafikkarten gebrochen werden.


## Referenzen.

* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data ](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS): ](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12, ](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)


## Liste der zugeordneten CWEs

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)

* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)

* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)

* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)

* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)

* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
