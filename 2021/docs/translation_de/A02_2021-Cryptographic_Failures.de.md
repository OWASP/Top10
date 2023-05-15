# A02:2021 – Kryptografische Fehler ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktoren

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Überblick

Beim Vorrücken um eine Position auf Platz 2, früher bekannt als *Sensible Data Exposure*, bei dem es sich eher um ein allgemeines Symptom als um eine Grundursache handelt, liegt der Schwerpunkt auf Fehlern im Zusammenhang mit der Kryptographie (oder deren Fehlen).
Dies führt häufig zur Offenlegung sensibler Daten. Bemerkenswerte Common Weakness Enumerations (CWEs) sind *CWE-259: Verwendung eines hartcodierten Passworts*, *CWE-327: Defekter oder riskanter Kryptoalgorithmus* und *CWE-331 Unzureichende Entropie*.

## Beschreibung

Zunächst gilt es, den Schutzbedarf der Daten während der Übertragung und im Ruhezustand zu ermitteln. Beispielsweise erfordern Passwörter, Kreditkartennummern, Gesundheitsakten, persönliche Informationen und Geschäftsgeheimnisse zusätzlichen Schutz, vor allem dann, wenn diese Daten unter Datenschutzgesetze, z. B. die Datenschutz-Grundverordnung (DSGVO) der EU, oder Vorschriften, z. B. Finanzdatenschutz, fallen wie PCI Data Security Standard (PCI DSS).
Für alle diese Daten:

- Werden Daten im Klartext übermittelt? Dies betrifft Protokolle wie HTTP, SMTP, FTP, die auch TLS-Upgrades wie STARTTLS verwenden. Externer Internetverkehr ist gefährlich. Überprüfen Sie den gesamten internen Datenverkehr, z. B. zwischen Load Balancern, Webservern oder Back-End-Systemen.

- Werden standardmäßig oder in älterem Code alte oder schwache kryptografische Algorithmen oder Protokolle verwendet?

- Werden Standard-Kryptoschlüssel verwendet, schwache Kryptoschlüssel generiert oder wiederverwendet oder fehlt eine ordnungsgemäße Schlüsselverwaltung oder -rotation? Werden Kryptoschlüssel in Quellcode-Repositorys eingecheckt?

- Wird die Verschlüsselung nicht erzwungen, z. B. fehlen Sicherheitsanweisungen für HTTP-Header (Browser) oder fehlen Header?

- Sind das empfangene Serverzertifikat und die Vertrauenskette ordnungsgemäß validiert?

- Werden Initialisierungsvektoren ignoriert, wiederverwendet oder nicht ausreichend sicher für den kryptografischen Betriebsmodus generiert? Ist eine unsichere Betriebsart wie ECB im Einsatz? Wird Verschlüsselung verwendet, wenn eine authentifizierte Verschlüsselung besser geeignet ist?

- Werden Passwörter als kryptografische Schlüssel verwendet, wenn keine Funktion zur Ableitung des Passwort-Basisschlüssels vorhanden ist?

- Wird Zufälligkeit für kryptografische Zwecke genutzt, die nicht auf kryptografische Anforderungen ausgelegt sind? Selbst wenn die richtige Funktion ausgewählt wird, muss sie vom Entwickler geseed werden, und wenn nicht, hat der Entwickler die darin integrierte starke Seeding-Funktionalität mit einem Seed überschrieben, dem es an ausreichender Entropie/Unvorhersehbarkeit mangelt?

- Werden veraltete Hash-Funktionen wie MD5 oder SHA1 verwendet oder werden nicht-kryptografische Hash-Funktionen verwendet, wenn kryptografische Hash-Funktionen benötigt werden?

– Werden veraltete kryptografische Auffüllmethoden wie PKCS Nummer 1 v1.5 verwendet?

- Sind kryptografische Fehlermeldungen oder Seitenkanalinformationen ausnutzbar, beispielsweise in Form von Padding-Oracle-Angriffen?

Siehe ASVS Crypto (V7), Data Protection (V9) und SSL/TLS (V10)

## Wie man etwas vorbeugt

Gehen Sie mindestens wie folgt vor und konsultieren Sie die Referenzen:

- Von einer Anwendung verarbeitete, gespeicherte oder übermittelte Daten klassifizieren. Identifizieren Sie, welche Daten gemäß Datenschutzgesetzen, behördlichen Anforderungen oder Geschäftsanforderungen vertraulich sind.

- Speichern Sie sensible Daten nicht unnötig. Verwerfen Sie es so schnell wie möglich oder verwenden Sie PCI DSS-kompatible Tokenisierung oder sogar Kürzung. Daten, die nicht gespeichert werden, können nicht gestohlen werden.

- Stellen Sie sicher, dass alle vertraulichen Daten im Ruhezustand verschlüsselt werden.

- Stellen Sie sicher, dass aktuelle und starke Standardalgorithmen, Protokolle und Schlüssel vorhanden sind. Verwenden Sie eine ordnungsgemäße Schlüsselverwaltung.

- Verschlüsseln Sie alle Daten während der Übertragung mit sicheren Protokollen wie TLS mit Forward Secrecy (FS)-Chiffren, Verschlüsselungspriorisierung durch den Server und sicheren Parametern. Erzwingen Sie die Verschlüsselung mithilfe von Anweisungen wie HTTP Strict Transport Security (HSTS).

– Deaktivieren Sie das Caching für Antworten, die vertrauliche Daten enthalten.

- Wenden Sie die erforderlichen Sicherheitskontrollen gemäß der Datenklassifizierung an.

- Verwenden Sie keine älteren Protokolle wie FTP und SMTP für den Transport sensibler Daten.

- Speichern Sie Passwörter mithilfe starker adaptiver und Salted-Hashing-Funktionen mit einem Arbeitsfaktor (Verzögerungsfaktor) wie Argon2, scrypt, bcrypt oder PBKDF2.

- Initialisierungsvektoren müssen passend zur Betriebsart gewählt werden. Für viele Modi bedeutet dies die Verwendung eines CSPRNG (kryptografisch sicherer Pseudozufallszahlengenerator). Für Modi, die eine Nonce erfordern, benötigt der Initialisierungsvektor (IV) kein CSPRNG. In jedem Fall sollte der IV niemals zweimal für einen festen Schlüssel verwendet werden.

- Verwenden Sie immer eine authentifizierte Verschlüsselung statt nur einer Verschlüsselung.

- Schlüssel sollten kryptografisch zufällig generiert und als Byte-Arrays im Speicher gespeichert werden. Wenn ein Passwort verwendet wird, muss es über eine entsprechende Funktion zur Ableitung des Passwortbasisschlüssels in einen Schlüssel umgewandelt werden.

- Stellen Sie sicher, dass gegebenenfalls kryptografische Zufälligkeit verwendet wird und dass diese nicht auf vorhersehbare Weise oder mit geringer Entropie gesät wurde. Bei den meisten modernen APIs muss der Entwickler kein Seeding für CSPRNG durchführen, um Sicherheit zu gewährleisten.

- Vermeiden Sie veraltete kryptografische Funktionen und Auffüllschemata wie MD5, SHA1, PKCS Nummer 1 v1.5.

- Überprüfen Sie unabhängig die Wirksamkeit der Konfiguration und Einstellungen.

## Beispielangriffsszenarien

**Szenario Nr. 1**: Eine Anwendung verschlüsselt Kreditkartennummern in einer Datenbank mithilfe der automatischen Datenbankverschlüsselung. Allerdings werden diese Daten beim Abruf automatisch entschlüsselt, was es einem SQL-Injection-Fehler ermöglicht, Kreditkartennummern im Klartext abzurufen.

**Szenario Nr. 2**: Eine Website verwendet oder erzwingt TLS nicht für alle Seiten oder unterstützt eine schwache Verschlüsselung. Ein Angreifer überwacht den Netzwerkverkehr (z. B. in einem unsicheren drahtlosen Netzwerk), stuft Verbindungen von HTTPS auf HTTP herunter, fängt Anfragen ab und stiehlt das Sitzungscookie des Benutzers. Der Angreifer spielt dann dieses Cookie ab und kapert die (authentifizierte) Sitzung des Benutzers, indem er auf die privaten Daten des Benutzers zugreift oder diese ändert. Stattdessen könnten sie alle übermittelten Daten ändern, z. B. den Empfänger einer Geldüberweisung.

**Szenario Nr. 3**: Die Passwortdatenbank verwendet ungesalzene oder einfache Hashes, um alle Passwörter zu speichern. Ein Datei-Upload-Fehler ermöglicht es einem Angreifer, die Passwortdatenbank abzurufen. Alle ungesalzenen Hashes können mit einer Regenbogentabelle vorberechneter Hashes angezeigt werden. Durch einfache oder schnelle Hash-Funktionen generierte Hashes können von GPUs geknackt werden, selbst wenn sie gesalzen sind.

## Verweise

- [OWASP Proactive Controls: Daten überall schützen](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

- [OWASP Application Security Verification Standard (V7, 9, 10)](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

- [OWASP-Spickzettel: Schutz der Privatsphäre des Benutzers](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

- [OWASP-Spickzettel: Passwortspeicherung](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

- [OWASP-Spickzettel: Kryptografische Speicherung](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

- [OWASP-Spickzettel: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

- [OWASP-Testleitfaden: Testen auf schwache Kryptographie](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)

## Liste der zugeordneten CWEs

[CWE-261 Schwache Codierung für Passwörter](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Unsachgemäßes Befolgen der Vertrauenskette eines Zertifikats](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 kryptografische Probleme](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Klartextübertragung sensibler Informationen](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Verwendung eines hartcodierten kryptografischen Schlüssels](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322-Schlüsselaustausch ohne Entitätsauthentifizierung](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Wiederverwendung eines Nonce-Schlüsselpaars in der Verschlüsselung](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Verwendung eines Schlüssels nach seinem Ablaufdatum](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Fehlender erforderlicher kryptografischer Schritt](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Unzureichende Verschlüsselungsstärke](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Verwendung eines fehlerhaften oder riskanten kryptografischen Algorithmus](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 verwendet keine Zufalls-IV im CBC-Modus](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Verwendung unzureichend zufälliger Werte](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Unzureichende Entropie](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Falsche Verwendung von Seeds im Pseudozufallszahlengenerator (PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Gleicher Startwert im Pseudozufallszahlengenerator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Verwendung des kryptografisch schwachen Pseudozufallszahlengenerators (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340-Generierung vorhersagbarer Zahlen oder Bezeichner](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Unsachgemäße Überprüfung der kryptografischen Signatur](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Ungeschützter Transport von Anmeldeinformationen](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007, Kategorie A9 – Unsichere Kommunikation](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757-Auswahl eines weniger sicheren Algorithmus während der Verhandlung („Algorithmus-Downgrade“)](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Verwendung eines Einweg-Hash ohne Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Verwendung eines Einweg-Hash mit einem vorhersehbaren Salz](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Verwendung des RSA-Algorithmus ohne OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Unzureichender Transportschichtschutz](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Verwendung von Passwort-Hash mit unzureichendem Rechenaufwand](https://cwe.mitre.org/data/definitions/916.html)
