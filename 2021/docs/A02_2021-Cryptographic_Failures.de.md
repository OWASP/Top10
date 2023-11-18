---
source:	"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
title:	"A02:2021 – Fehlerhafter Einsatz von Kryptographie"
id:		"A02:2021"
lang:	"de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".2" -%}
#A02:2021 – Fehlerhafter Einsatz von Kryptographie ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"} 
{{ osib_anchor(osib=osib, id=id, name ="Kryptografische Fehler", lang=lang, source=source, parent=parent, previous=extra.osib.document ~ ".2017.3") }}


## Beurteilungskriterien {{ osib_anchor(osib=osib ~ ".factors", id=id ~ "-factors", name=title ~ ": Factors", lang=lang, source=source ~ "#" ~ id, parent=osib) }}

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              |7.29                 | 6.81                |  79.33%       | 34.85%       | 233,788           | 3,075      |

## Übersicht {{ osib_anchor(osib=osib ~ ".overview", id=id ~ "-overview", name=title ~ ": Bezug / Kontext / Auswertung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Dieses Thema ist vorgerückt um eine Position auf Platz 2 und war früher bekannt als *Verlust der Vertraulichkeit sensibler Daten*, bei dem es sich eher um ein allgemeines Symptom als um eine Grundursache handelt.
Nun liegt der Schwerpunkt mehr auf Fehlern im Zusammenhang mit Kryptographie oder dass diese nicht zur Anwendung kommt, was häufig zur Offenlegung sensibler Daten führt.
Bemerkenswerte Common Weakness Enumerations (CWEs) sind *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky Crypto Algorithm* und *CWE-331 Insufficient Entropy*.

## Beschreibung {{ osib_anchor(osib=osib ~ ".description", id=id ~ "-description", name=title ~ ": Beschreibung", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

Zunächst gilt es, den Schutzbedarf der Daten während der Übermittlung und der Speicherung zu ermitteln. Beispielsweise erfordern Passwörter, Kreditkartennummern, Gesundheitsakten, persönliche Informationen und Geschäftsgeheimnisse zusätzlichen Schutz, vor allem dann, wenn diese Daten unter Datenschutzgesetze, z. B. die Datenschutz-Grundverordnung (DSGVO) der EU, oder andere Vorschriften fallen, beispielsweise dem Payment Card Industry Data Security Standard (PCI DSS).

Folgendes ist zu klären:

- Werden Daten im Klartext übermittelt? Das betrifft Protokolle wie HTTP, SMTP, und FTP unter Umständen auch bei Verwendung von TLS-Upgrades wie STARTTLS. Das Internet ist hier besonders gefährlich. Überprüfen Sie auch internen Datenverkehr, z.B. zwischen Load Balancern, Webservern oder Back-End-Systemen.

- Werden alte oder schwache kryptografische Algorithmen oder Protokolle verwendet, z.B. per Default-Einstellung oder in älterem Code?

- Werden vordefinierte kryptografische Schlüssel verwendet, schwache Schlüssel generiert oder Schlüssel wiederverwendet? Fehlt eine Schlüsselverwaltung oder Schlüsselrotation? Werden kryptografische Schlüssel in Quellcode-Repositorys eingecheckt?

- Wird Verschlüsselung nicht verbindlich erzwungen, z.B. fehlen bei Web Anwendungen Vorgaben für den Browser in den entsprechenden HTTP-Headern?

- Werden empfangene Serverzertifikate und die Zertifikatskette korrekt validiert?

- Werden Initialisierungsvektoren ignoriert, wiederverwendet oder nicht ausreichend sicher für den kryptografischen Betriebsmodus generiert? Ist ein unsicherer Betriebsmodus wie ECB im Einsatz? Wird ein Betriebsmodus verwendet, der nur verschüsselt, obwohl ein AEAD Betriebsmodus angebracht wäre, der auch die Integrität schützt?

- Werden Passwörter direkt als kryptografische Schlüssel verwendet ohne eine Schlüsselableitung mittels Key Derivation Function?

- Werden Zufallszahlen für kryptografische Zwecke genutzt, die nicht auf kryptografische Anforderungen ausgelegt sind? Selbst wenn die richtige Funktion genutzt wird, muss diese eventuell vom Entwickler korrekt initialisiert werden. Wurde eine integrierte starke Initialisierung eventuell durch einen Entwickler mit einem schwachen Wert überschrieben, dem es an ausreichender Entropie und Nichtvorhersehbarkeit mangelt?

- Werden Hash-Funktionen mit bekannten Schwächen wie MD5 oder SHA1 verwendet oder werden nicht-kryptografische Hash-Funktionen verwendet, wenn kryptografische Hash-Funktionen benötigt werden?

– Werden veraltete kryptografische Padding Methoden verwendet, z.B. PKCS#1 v1.5?

- Sind kryptografische Fehlermeldungen oder Seitenkanäle ausnutzbar, beispielsweise in Form von Padding-Oracle-Angriffen?

Siehe {{ osib_link(link="osib.owasp.asvs.4-0.6", prefix="ASVS ", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs. 4-0.8", doc="", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.9", doc="", osib=osib) }}<!-- - ASVS Crypto (V7), Datenschutz (V9) und SSL/TLS (V10)--->

## Prävention und Gegenmaßnahmen {{ osib_anchor(osib=osib ~ ".how to prevent", id=id ~ "-how_to_prevent", name=title ~ ": Prävention und Gegenmaßnahmen", lang=lang, source=source ~ "#" ~ id, parent=osib) }}


Gehen Sie als Minimum wie folgt vor und konsultieren Sie die Referenzen:

- Klassifizieren Sie die Daten, die von einer Anwendung verarbeitet, gespeichert oder übermittelt werden, nach ihrem Schutzbedarf. Berücksichtigen Sie dabei auch Datenschutzgesetze, regulatorische und Geschäfts-Anforderungen.

- Speichern Sie sensible Daten nicht unnötig. Löschen Sie sensible Daten auf sichere Weise sobald wie möglich oder verwenden Sie Techniken wie PCI-DSS-konformes Speichern von Ersatzwerten (Tokenisierung) oder gar gekürzten (trunkierten) Werten.
Daten, die es nicht mehr gibt, können auch nicht gestohlen werden.

- Stellen Sie sicher, dass alle vertraulichen Daten bei Speicherung verschlüsselt werden.

- Aktuelle, starke Algorithmen und Schlüssel 
- Stellen Sie sicher, dass aktuelle, starke, standardisierte Algorithmen, Protokolle und Schlüssel, z.B. gemäß BSI TR-02102, verwendet werden. Etablieren Sie wirksames 
Schlüsselmanagement für kryptografische Schlüssel.

- Verschlüsseln Sie alle Daten während der Übertragung mit sicheren Protokollen wie TLS. Priorisieren Sie dabei durch serverseitig Cipher-Suiten, die Forward Secrecy (FS) bieten, und sichere Parameter.
Erzwingen Sie die Verschlüsselung wenn möglich, z.B. durch Einführung von HTTP Strict Transport Security (HSTS).

- Deaktivieren Sie das Caching für den Empfang vertraulicher Daten.

- Wenden Sie die Sicherheitsmaßnahmen gemäß dem Schutzbedarf der Datenklassifizierung an.

- Verwenden Sie keine älteren Protokolle wie FTP und SMTP für den Transport sensibler Daten.
//?????????????????????

- Verwenden Sie spezielle Hash-Funktionen für das Hashen von Passwörtern, bei denen für jedes Passwort ein Salz-Wert (salted hash) zum Einsatz kommt und durch Parameterierung der Rechenaufwand adaptiv gesteuert werden kann (work-factor). Beispiele sind: Argon2, scrypt, bcrypt oder PBKDF2.

- Initialisierungsvektoren müssen passend zum kryptografischen Betriebsmodus gewählt werden. In vielen Fällen bedeutet dies, dass ein CSPRNG (kryptografisch sicherer Pseudozufallszahlengenerator) für die Generierung des Initialisierungsvektors verwendet wird. Für Modi, die eine Nonce erfordern, benötigt der Initialisierungsvektor nicht notwendigerweise einen CSPRNG. In allen Fällen darf der gleiche Initialisierungsvektor niemals zweimal für den gleichen Schlüssel verwendet werden.

- Verwenden Sie immer eine authentifizierte Verschlüsselung statt nur einer Verschlüsselung.

- Schlüssel sollten kryptografisch zufällig generiert und als Byte-Arrays im Speicher gehalten werden. Wenn ein Passwort zur Verschlüsselung verwendet werden soll, muss über eine Funktion zur Schlüsselableitung ein Schlüssel generiert werden.

- Stellen Sie sicher, dass an den notwendigen Stellen kryptografisch sichere, unvorhersagbare Zufallszahlen verwendet werden, und dass der Pseudozufallszahlengenerator nicht auf vorhersehbare Weise oder nur mit geringer Entropie initialisiert wurde. Bei den meisten modernen APIs muss der Entwickler die Initialisierung des Pseudozufallszahlengenerators (CSPRNG) nicht manuell durchführen.

- Vermeiden Sie veraltete kryptografische Funktionen und Padding-Verfahren wie MD5, SHA1, PKCS Nummer 1 v1.5.

- Lassen Sie die Wirksamkeit der Einstellungen unabhängig überprüfen.

## Beispielhafte Angriffsszenarien {{ osib_anchor(osib=osib ~ ".example attack Scenarios", id=id ~ "-example_attack_scenarios", name=title ~ ": Beispielhafte Angriffsszenarien", lang=lang, source=source ~ "# " ~ id, parent=osib) }}

**Szenario Nr. 1**: Eine Anwendung verschlüsselt Kreditkartendaten automatisch bei der Speicherung in einer Datenbank. Das bedeutet aber auch, dass durch SQL-Injection erlangte Kreditkartendaten in diesem Fall automatisch entschlüsselt werden.

**Szenario Nr. 2**: Eine Webseite benutzt kein TLS, erzwingt dies nicht auf allen Seiten oder lässt schwache Verschlüsselung zu. Der Angreifer liest die Kommunikation mit (z.B. in einem offenen WLAN), ersetzt HTTPS- durch HTTP-Verbindungen, hört diese ab und stiehlt das Sitzungscookie. Durch Wiedereinspielen dieses Cookies übernimmt der Angreifer die (authentifizierte) Sitzung des Nutzers und erlangt Zugriff auf dessen private Daten. Anstatt dessen kann der Angreifer auch die übertragenen Daten ändern, z.B. den Empfänger einer Überweisung.

**Szenario Nr. 3**: Die Passwortdatenbank benutzt einfache Hashwerte oder Hashes ohne Salt zur Speicherung der Passwörter. Eine Schwachstelle in der Downloadfunktion erlaubt dem Angreifer den Zugriff auf die Passwortdatei. Zu Hashes ohne Salt kann über vorausberechnete Rainbow-Tabellen der Klartext gefunden werden. Hashes, die über einfache oder schnelle Funktionen berechnet wurden, können effizient mit Grafikkarten gebrochen werden.

## Referenzen {{ osib_anchor(osib=osib ~ ".references", id=id ~ "-references", name=title ~ ": Referenzen", lang=lang, source=source ~ "#" ~ id, parent= osib) }}

- {{ osib_link(link="osib.owasp.opc.3." ~ "8", osib=osib) }} <!-- [OWASP Proactive Controls: Protect Data Everywhere](https://owasp.org/ www-project-proactive-controls/v3/en/c8-protect-data-everywhere) -->
- {{ osib_link(link="osib.owasp.asvs.4-0.6", osib=osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.8", doc="", osib =osib) }}, {{ osib_link(link= "osib.owasp.asvs.4-0.9", doc="", osib=osib) }} <!--- [OWASP Application Security Verification Standard (V7, 9 , 10)](https://owasp.org/www-project-application-security-verification-standard) --->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Transport Layer Protection", osib=osib) }} <!-- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries. owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "User Privacy Protection", osib=osib) }} <!-- [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries. owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Passwortspeicherung", osib=osib) }} <!-- [OWASP-Spickzettel: Passwortspeicherung](https://cheatsheetseries.owasp. org/cheatsheets/Password_Storage_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "Cryptographic Storage", osib=osib) }} <!-- [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp. org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.cheatsheetseries.0." ~ "HSTS", osib=osib) }} <!-- [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/ cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) ->
- {{ osib_link(link="osib.owasp.wstg.4-2.4.9", osib=osib) }} <!-- [OWASP-Testleitfaden: Testen auf schwache Kryptographie](https://owasp.org/ www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README) ->

## Liste der zugeordneten CWEs {{ osib_anchor(osib=osib~".mapped cwes", id=id~"-mapped_cwes", name=title~":Liste der zugeordneten CWEs", lang=lang, source=source~" #" ~id, parent=osib) }}

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
