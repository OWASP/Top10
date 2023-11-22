---
Quelle: "https://owasp.org/Top10/A11_2021-Next_Steps.md/"
Titel: "A11:2021 – Nächste Schritte"
ID: "A11:2021"
lang: "de"
---
{%- set parent = extra.osib.document ~ "." ~ extra.osib.version -%}
{%- set osib = parent ~ ".11" -%}
#A11:2021 – Nächste Schritte
{{ osib_anchor(osib=osib, id=id, name="Nächste Schritte", lang=lang, source=source, parent=parent) }}

Die OWASP Top 10 sind von Natur aus auf die zehn bedeutendsten Risiken beschränkt.
Bei allen OWASP Top 10 gibt es Risiken an der Schwelle,
deren Aufnahme ausführlich eruiert wurde, die es aber am Ende nicht geschafft haben.
Wie auch immer wir versuchten, die Daten zu interpretieren oder zu verdrehen, waren die anderen Risiken doch weit verbreiteter und schwerwiegender.

Für Unternehmen, die auf ein ausgereiftes Programm zur Anwendungssicherheit hinarbeiten, für Sicherheitsberatungsunternehmen oder Tool-Anbieter, die die Abdeckung ihrer Angebote erweitern möchten, lohnt es sich, auch die folgenden vier Probleme zu identifizieren und zu beheben.

## Probleme mit der Codequalität

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

- **Beschreibung.** Zu den Problemen mit der Codequalität gehören bekannte Sicherheitsmängel oder -muster, die Wiederverwendung von Variablen für mehrere Zwecke, die Offenlegung vertraulicher Informationen in der Debugging-Ausgabe, Off-by-One-Fehler und
TOCTOU-Race-Conditions, Konvertierungsfehler zwischen signed/unsigned-Werten, use-after-free und mehr.
Das Besondere an diesem Abschnitt ist, dass sie normalerweise durch strenge Compiler-Flags,
Statische Code-Analyse oder Linter-IDE-Plugins zu erkennen sind.
Durch das Design moderner Sprachen wurden viele dieser Probleme beseitigt, beispielsweise das Konzept von Memory Ownership und Borrowing in Rust,
das Threading-Design in Rust und die strikte Typisierung und Grenzwert-Prüfung in Go.

-   **Prävention und Gegenmaßnahmen**. Aktivieren und nutzen Sie die Statische Code-Analyse Ihres Editors und Ihrer Sprache. Erwägen Sie die Verwendung eines Werkzeugs zur Statischen Code-Analyse. Überlegen Sie, ob es möglich ist, eine Sprache oder ein Framework zu verwenden oder darauf zu migrieren, das Fehlerklassen eliminiert, wie Rust oder Go.

- **Beispielhafte Angriffsszenarien**. Ein Angreifer könnte vertrauliche Informationen erhalten oder aktualisieren, indem er eine Race-Bedingung unter Verwendung einer gemeinsam von mehreren Threads genutzten statischen Variablen ausnutzt.

- **Referenzen**
- {{ osib_link(link="osib.owasp.code review guide.2-0.pdf", osib=osib) }} <!--- [OWASP Code Review Guide](https:/ /owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf) ---> 
- {{ osib_link(link="osib.google.eng practices.review", osib=osib) }} <!--- [Google Leitfaden zur Codeüberprüfung](https://google.github.io/eng-practices/review/) --->


## Denial of Service

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **Beschreibung**. Mit den nötigen Ressourcen ist ein Denial-of-Service immer möglich.
Design- und Programmierpraktiken haben jedoch einen erheblichen Einfluss auf das Ausmaß des Denial-of-Service.
Stellen Sie sich vor, jede Person, die über den Link verfügt, könnte auf eine große Datei zugreifen
oder auf jeder Seite fände eine rechenintensive Transaktion statt.
In diesen Fällen ist ein Denial-of-Service mit geringerem Aufwand durchzuführen.

-   **Prävention und Gegenmaßnahmen**. Testen Sie die Performanz der Anwendung bezüglich CPU-, I/O- und Speichernutzung.
Optimieren Sie teure Operationen, entwerfen Sie diese neu oder führen Sie Caching ein.
Erwägen Sie Zugriffskontrollen für größere Objekte, um sicherzustellen, dass nur autorisierte Personen auf große Dateien oder Objekte zugreifen
oder bieten Sie diese über ein Edge-Caching-Netzwerk an.

- **Beispielhafte Angriffsszenarien**. Ein Angreifer könnte feststellen, dass ein Vorgang 5 bis 10 Sekunden dauert. Beim Ausführen von vier gleichzeitigen Threads scheint der Server nicht mehr zu reagieren. Der Angreifer nutzt 1000 Threads und nimmt das gesamte System offline.

-   **Referenzen** 
    - {{ osib_link(link= "osib.owasp.cheatsheetseries.0.denial of service", osib=osib) }} <!-- [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) -->
    - {{ osib_link(link= "osib.owasp.community.0.attacks.denial of service", osib=osib) }} <!-- [OWASP-Angriffe: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service) --->

## Speicherverwaltungsfehler

| Zugeordnete CWEs | Maximale Häufigkeit | Durchschn. Häufigkeit | Durchschn. Ausnutzbarkeit (gewichtet) | Durchschn. Auswirkungen (gewichtet) | Maximale Abdeckung | Durchschnittliche Abdeckung | Gesamtanzahl | CVEs insgesamt |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Beschreibung**. Webanwendungen werden in der Regel in Managed-Memory-Sprachen wie Java, .NET oder Node.js (JavaScript oder TypeScript) geschrieben.
Allerdings sind diese Sprachen in Systemsprachen geschrieben, die Probleme bei der Speicherverwaltung haben,
wie z. B. Puffer- oder Heap-Überläufe, Use-After-Free, Integer-Überläufe und mehr. Im Laufe der Jahre gab es viele Sandbox-Ausweichmanöver, die beweisen, dass die Grundlagen der Webanwendungssprache nicht sicher sind, auch wenn sie nominell speichersicher sind.

-   **Prävention und Gegenmaßnahmen**. Viele moderne APIs sind mittlerweile in speichersicheren Sprachen wie Rust oder Go geschrieben. Im Fall von Rust ist die Speichersicherheit ein entscheidendes Merkmal der Sprache. Bei vorhandenem Code kann die Verwendung strenger Compiler-Flags, starker Typisierung, Statischer Codeanalyse und Fuzzing-Tests bei der Identifizierung von Speicherlecks, Speicher- und Array-Überläufen und mehr hilfreich sein.

- **Beispielhafte Angriffsszenarien**. Puffer- und Heap-Überläufe waren im Laufe der Jahre eine der Hauptursachen für Angriffe.
Der Angreifer sendet Daten an ein Programm, das dieses in einem zu kleinen Stack-Puffer speichert.
Das Ergebnis ist, dass Informationen auf dem Stack überschrieben werden,
einschließlich des Rückgabezeigers der Funktion. Die Daten legen den Wert des Rückgabezeigers fest, sodass die Funktion bei der Rückkehr die Kontrolle an den in den Daten des Angreifers enthaltenen Schadcode übergibt.

-   **Referenzen**
    - {{ osib_link(link="osib.owasp.community.0.vulnerabilities.buffer overflow", osib=osib) }} <!--- [OWASP-Sicherheitslücken: Pufferüberlauf](https:/ /owasp.org/www-community/vulnerabilities/Buffer_Overflow) --->
    - {{ osib_link(link="osib.owasp.community.0.attacks.buffer overflow attack", osib=osib) }} <!-- - [OWASP-Angriffe: Pufferüberlauf](https://owasp.org/www-community/attacks/Buffer_overflow_attack) --->
    - {{ osib_link(link="osib.sciencedirect.computer science.integer overflow", osib= osib) }} <!--- [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow) --->
