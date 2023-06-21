---
source:	"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
title:	"A02:2021 – Kryptografische Ausfälle“
id:		"A02:2021“
lang:	"de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".2" -%}
#A02:2021 – Kryptografische Fehler ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"} {{ osib_anchor(osib=osib, id=id, name ="Kryptografische Fehler", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.3") }}


## Faktoren {{ osib_anchor(osib=osib~".factors", id=id~"-factors", name=title~":Factors", aussehen=appearance, source=source~"#"~id, parent= osib) }}

| CWEs kartiert | Maximale Inzidenzrate | Durchschnittliche Inzidenzrate | Durchschnittlich gewichteter Exploit | Durchschnittliche gewichtete Auswirkung | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtzahl der Vorkommen | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Übersicht", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Beim Vorrücken um eine Position auf Platz 2, früher bekannt als *Sensible Data Exposure*, bei dem es sich eher um ein allgemeines Symptom als um eine Grundursache handelt, liegt der Schwerpunkt auf Fehlern im Zusammenhang mit der Kryptographie (oder deren Fehlen). Dies führt häufig zur Offenlegung sensibler Daten. Bemerkenswerte Common Weakness Enumerations (CWEs) sind *CWE-259: Verwendung eines hartcodierten Passworts*, *CWE-327: Defekter oder riskanter Kryptoalgorithmus* und *CWE-331 Unzureichende Entropie*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Zunächst gilt es, den Schutzbedarf der Daten während der Übertragung und im Ruhezustand zu ermitteln. Beispielsweise erfordern Passwörter, Kreditkartennummern, Gesundheitsakten, persönliche Informationen und Geschäftsgeheimnisse zusätzlichen Schutz, vor allem dann, wenn diese Daten unter Datenschutzgesetze, z. B. die Datenschutz-Grundverordnung (DSGVO) der EU, oder Vorschriften, z. B. Finanzdatenschutz, fallen wie PCI Data Security Standard (PCI DSS). Für alle diese Daten:

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

Siehe {{ osib_link(link="osib.owasp.asvs.4-0.6", prefix="ASVS ", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs. 4-0.8", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.9", doc="", osib=osib) }}<!-- - ASVS Crypto (V7), Datenschutz (V9) und SSL/TLS (V10)--->

## Vorbeugende Maßnahmen " ~ id, parent=osib) }}

Gehen Sie mindestens wie folgt vor und konsultieren Sie die Referenzen:

- Von einer Anwendung verarbeitete, gespeicherte oder übermittelte Daten klassifizieren. identifizieren Sie, welche Daten gemäß Datenschutzgesetzen, behördlichen Anforderungen oder Geschäftsanforderungen vertraulich sind.

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

## Beispiel-Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispiel-Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1**: Eine Anwendung verschlüsselt Kreditkartennummern in einer Datenbank mithilfe der automatischen Datenbankverschlüsselung. Allerdings werden diese Daten beim Abruf automatisch entschlüsselt, was es einem SQL-Injection-Fehler ermöglicht, Kreditkartennummern im Klartext abzurufen.

**Szenario Nr. 2**: Eine Website verwendet oder erzwingt TLS nicht für alle Seiten oder unterstützt eine schwache Verschlüsselung. Ein Angreifer überwacht den Netzwerkverkehr (z. B. in einem unsicheren drahtlosen Netzwerk), stuft Verbindungen von HTTPS auf HTTP herunter, fängt Anfragen ab und stiehlt das Sitzungscookie des Benutzers. Der Angreifer spielt dann dieses Cookie ab und kapert die (authentifizierte) Sitzung des Benutzers, indem er auf die privaten Daten des Benutzers zugreift oder diese ändert. Stattdessen könnten sie alle übermittelten Daten ändern, z. B. den Empfänger einer Geldüberweisung.

**Szenario Nr. 3**: Die Passwortdatenbank verwendet ungesalzene oder einfache Hashes, um alle Passwörter zu speichern. Ein Datei-Upload-Fehler ermöglicht es einem Angreifer, die Passwortdatenbank abzurufen. Alle ungesalzenen Hashes können mit einer Regenbogentabelle vorberechneter Hashes angezeigt werden. Durch einfache oder schnelle Hash-Funktionen generierte Hashes können von GPUs geknackt werden, selbst wenn sie gesalzen sind.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": References", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3." ~ "8", osib=osib) }} <!-- [OWASP Proactive Controls: Protect Data Everywhere](https://owasp.org/ www-project-proactive-controls/v3/en/c8-protect-data-everywhere) -->
- {{ osib_link(link="osib.owasp.asvs.4-0.6", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.8", doc="", osib =osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.9", doc="", osib=osib) }} <!--- [OWASP Application Security Verification Standard (V7, 9 , 10)](https://owasp.org/www-project-application-security-verification-standard) --->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Transport Layer Protection", osib=osib) }} <!-- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries. owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "User Privacy Protection", osib=osib) }} <!-- [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries. owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Passwortspeicherung", osib=osib) }} <!-- [OWASP-Spickzettel: Passwortspeicherung](https://cheatsheetseries.owasp. org/cheatsheets/Password_Storage_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Cryptographic Storage", osib=osib) }} <!-- [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp. org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "HSTS", osib=osib) }} <!-- [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/ cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.9", osib=osib) }} <!-- [OWASP-Testleitfaden: Testen auf schwache Kryptographie](https://owasp.org/ www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README) ->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":List of Mapped CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

- {{ osib_link(link="osib.mitre.cwe.0.261", doc="", osib=osib) }} <!-- [CWE-261: Schwache Codierung für Passwort](https://cwe.mitre .org/data/definitions/261.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.296", doc="", osib=osib) }} <!-- [CWE-296: Unsachgemäßes Befolgen der Vertrauenskette eines Zertifikats](https:/ /cwe.mitre.org/data/definitions/296.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.310", doc="", osib=osib) }} <!-- [CWE-310: Kryptografische Probleme](https://cwe.mitre.org /data/definitions/310.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.319", doc="", osib=osib) }} <!-- [CWE-319: Klartextübertragung sensibler Informationen](https://cwe. mitre.org/data/definitions/319.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.321", doc="", osib=osib) }} <!-- [CWE-321: Verwendung eines hartcodierten kryptografischen Schlüssels](https:// cwe.mitre.org/data/definitions/321.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.322", doc="", osib=osib) }} <!-- [CWE-322: Schlüsselaustausch ohne Entitätsauthentifizierung](https://cwe. mitre.org/data/definitions/322.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.323", doc="", osib=osib) }} <!-- [CWE-323: Wiederverwendung eines Nonce-Schlüsselpaars in der Verschlüsselung](https:/ /cwe.mitre.org/data/definitions/323.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.324", doc="", osib=osib) }} <!-- [CWE-324: Verwendung eines Schlüssels nach seinem Ablaufdatum](https:/ /cwe.mitre.org/data/definitions/324.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.325", doc="", osib=osib) }} <!-- [CWE-325: Erforderlicher kryptografischer Schritt fehlt](https://cwe.mitre .org/data/definitions/325.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.326", doc="", osib=osib) }} <!-- [CWE-326: Unzureichende Verschlüsselungsstärke](https://cwe.mitre. org/data/definitions/326.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.327", doc="", osib=osib) }} <!-- [CWE-327: Verwendung eines defekten oder riskanten kryptografischen Algorithmus](https:/ /cwe.mitre.org/data/definitions/327.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.328", doc="", osib=osib) }} <!-- [CWE-328: Reversible One-Way Hash](https://cwe. mitre.org/data/definitions/328.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.329", doc="", osib=osib) }} <!-- [CWE-329: Keine zufällige IV mit CBC-Modus verwenden](https:/ /cwe.mitre.org/data/definitions/329.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.330", doc="", osib=osib) }} <!-- [CWE-330: Verwendung unzureichend zufälliger Werte](https://cwe. mitre.org/data/definitions/330.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.331", doc="", osib=osib) }} <!-- [CWE-331: Unzureichende Entropie](https://cwe.mitre.org /data/definitions/331.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.335", doc="", osib=osib) }} <!-- [CWE-335: Falsche Verwendung von Seeds im Pseudozufallszahlengenerator (PRNG) ](https://cwe.mitre.org/data/definitions/335.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.336", doc="", osib=osib) }} <!-- [CWE-336: Gleicher Startwert im Pseudozufallszahlengenerator (PRNG)]( https://cwe.mitre.org/data/definitions/336.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.337", doc="", osib=osib) }} <!-- [CWE-337: Vorhersagbarer Startwert im Pseudozufallszahlengenerator (PRNG)]( https://cwe.mitre.org/data/definitions/337.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.338", doc="", osib=osib) }} <!-- [CWE-338: Verwendung des kryptographisch schwachen Pseudozufallszahlengenerators (PRNG)] (https://cwe.mitre.org/data/definitions/338.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.340", doc="", osib=osib) }} <!-- [CWE-340: Erzeugung vorhersagbarer Zahlen oder Bezeichner](https://cwe .mitre.org/data/definitions/340.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.347", doc="", osib=osib) }} <!-- [CWE-347: Unsachgemäße Überprüfung der kryptografischen Signatur](https://cwe. mitre.org/data/definitions/347.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.523", doc="", osib=osib) }} <!-- [CWE-523: Ungeschützter Transport von Anmeldeinformationen](https://cwe.mitre .org/data/definitions/523.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.720", doc="", osib=osib) }} <!-- [CWE-720: OWASP Top Ten 2007 Kategorie A9 – Unsichere Kommunikation](https: //cwe.mitre.org/data/definitions/720.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.757", doc="", osib=osib) }} <!-- [CWE-757: Auswahl weniger sicherer Algorithmen während der Aushandlung('Algorithmus-Downgrade' )](https://cwe.mitre.org/data/definitions/757.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.759", doc="", osib=osib) }} <!-- [CWE-759: Verwendung eines Einweg-Hash ohne Salt](https ://cwe.mitre.org/data/definitions/759.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.760", doc="", osib=osib) }} <!-- [CWE-760: Verwendung eines Einweg-Hash mit einem vorhersehbaren Salt]( https://cwe.mitre.org/data/definitions/760.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.780", doc="", osib=osib) }} <!-- [CWE-780: Verwendung des RSA-Algorithmus ohne OAEP](https://cwe .mitre.org/data/definitions/780.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.818", doc="", osib=osib) }} <!-- [CWE-818: Unzureichender Transportschichtschutz](https://cwe.mitre .org/data/definitions/818.html) ->
- {{ osib_link(link="osib.mitre.cwe.0.916", doc="", osib=osib) }} <!-- [CWE-916: Verwendung von Passwort-Hash mit unzureichendem Rechenaufwand](https:/ /cwe.mitre.org/data/definitions/916.html) ->
