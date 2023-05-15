# A11:2021 – Nächste Schritte

Die OWASP Top 10 sind von Natur aus auf die zehn bedeutendsten Risiken beschränkt. Bei allen OWASP Top 10 stehen Risiken kurz vor der Tür, über deren Aufnahme sie ausführlich nachgedacht haben, aber am Ende haben sie es nicht geschafft. Unabhängig davon, wie wir versuchten, die Daten zu interpretieren oder zu verdrehen, waren die anderen Risiken weit verbreiteter und schwerwiegender.

Für Unternehmen, die auf ein ausgereiftes Appsec-Programm hinarbeiten, oder für Sicherheitsberatungsunternehmen oder Tool-Anbieter, die die Abdeckung ihrer Angebote erweitern möchten, lohnt es sich, die folgenden vier Probleme zu identifizieren und zu beheben.

## Probleme mit der Codequalität

| CWEs kartiert  | Maximale Inzidenzrate  | Durchschnittliche Inzidenzrate  | Durchschnittlich gewichteter Exploit  | Durchschnittliche gewichtete Auswirkung  | Maximale Abdeckung  | Durchschnittliche Abdeckung  | Gesamtzahl der Vorkommen  | CVEs insgesamt  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

- **Beschreibung.** Zu den Problemen mit der Codequalität gehören bekannte Sicherheitsmängel oder -muster, die Wiederverwendung von Variablen für mehrere Zwecke, die Offenlegung vertraulicher Informationen in der Debugging-Ausgabe, Off-by-One-Fehler und Race-Conditions zur Zeit der Überprüfung/Zeit der Nutzung (TOCTOU). , unsignierte oder signierte Konvertierungsfehler, Verwendung nach kostenloser Nutzung und mehr. Das Besondere an diesem Abschnitt ist, dass sie normalerweise an strengen Compiler-Flags, statischen Code-Analysetools und Linter-IDE-Plugins zu erkennen sind. Durch das Design moderner Sprachen wurden viele dieser Probleme beseitigt, beispielsweise das Speicherbesitz- und Ausleihkonzept von Rust, das Threading-Design von Rust und die strikte Typisierung und Grenzprüfung von Go.

-   **Wie man etwas vorbeugt**. Aktivieren und nutzen Sie die statischen Code-Analyseoptionen Ihres Editors und Ihrer Sprache. Erwägen Sie die Verwendung eines statischen Code-Analysetools. Überlegen Sie, ob es möglich ist, eine Sprache oder ein Framework zu verwenden oder darauf zu migrieren, das Fehlerklassen eliminiert, wie Rust oder Go.

- **Beispielhafte Angriffsszenarien**. Ein Angreifer könnte vertrauliche Informationen erhalten oder aktualisieren, indem er eine Race-Bedingung unter Verwendung einer statisch gemeinsam genutzten Variablen über mehrere Threads hinweg ausnutzt.

-   **Verweise**
- [OWASP-Codeüberprüfungsleitfaden](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

- [Google Code Review Guide](https://google.github.io/eng-practices/review/)


## Denial of Service

| CWEs kartiert  | Maximale Inzidenzrate  | Durchschnittliche Inzidenzrate  | Durchschnittlich gewichteter Exploit  | Durchschnittliche gewichtete Auswirkung  | Maximale Abdeckung  | Durchschnittliche Abdeckung  | Gesamtzahl der Vorkommen  | CVEs insgesamt  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **Beschreibung**. Bei ausreichenden Ressourcen ist ein Denial-of-Service immer möglich. Design- und Codierungspraktiken haben jedoch einen erheblichen Einfluss auf das Ausmaß des Denial-of-Service. Angenommen, jeder, der über den Link verfügt, kann auf eine große Datei zugreifen oder auf jeder Seite findet eine rechenintensive Transaktion statt. In diesem Fall ist ein Denial-of-Service mit weniger Aufwand durchzuführen.

-   **Wie man etwas vorbeugt**. Leistungstestcode für CPU-, I/O- und Speichernutzung, Neuarchitektur, Optimierung oder Zwischenspeicherung teurer Vorgänge. Erwägen Sie Zugriffskontrollen für größere Objekte, um sicherzustellen, dass nur autorisierte Personen auf große Dateien oder Objekte zugreifen oder diese über ein Edge-Caching-Netzwerk bereitstellen können.

- **Beispielhafte Angriffsszenarien**. Ein Angreifer könnte feststellen, dass ein Vorgang 5 bis 10 Sekunden dauert. Beim Ausführen von vier gleichzeitigen Threads scheint der Server nicht mehr zu reagieren. Der Angreifer nutzt 1000 Threads und schaltet das gesamte System offline.

-   **Verweise**
- [OWASP-Spickzettel: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

- [OWASP-Angriffe: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Speicherverwaltungsfehler

| CWEs kartiert  | Maximale Inzidenzrate  | Durchschnittliche Inzidenzrate  | Durchschnittlich gewichteter Exploit  | Durchschnittliche gewichtete Auswirkung  | Maximale Abdeckung  | Durchschnittliche Abdeckung  | Gesamtzahl der Vorkommen  | CVEs insgesamt  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Beschreibung**. Webanwendungen werden in der Regel in Managed-Memory-Sprachen wie Java, .NET oder node.js (JavaScript oder TypeScript) geschrieben. Allerdings sind diese Sprachen in Systemsprachen geschrieben, die Probleme bei der Speicherverwaltung haben, wie z. B. Puffer- oder Heap-Überläufe, Use After Free, Integer-Überläufe und mehr. Im Laufe der Jahre gab es viele Sandbox-Ausweichmanöver, die beweisen, dass die Grundlagen der Webanwendungssprache nicht sicher sind, nur weil sie nominell speichersicher ist.

-   **Wie man etwas vorbeugt**. Viele moderne APIs sind mittlerweile in speichersicheren Sprachen wie Rust oder Go geschrieben. Im Fall von Rust ist die Speichersicherheit ein entscheidendes Merkmal der Sprache. Bei vorhandenem Code kann die Verwendung strenger Compiler-Flags, starker Typisierung, statischer Codeanalyse und Fuzz-Tests bei der Identifizierung von Speicherlecks, Speicher- und Array-Überläufen und mehr hilfreich sein.

- **Beispielhafte Angriffsszenarien**. Puffer- und Heap-Überläufe waren im Laufe der Jahre eine der Hauptursachen für Angreifer. Der Angreifer sendet Daten an ein Programm, das dieses in einem zu kleinen Stapelpuffer speichert. Das Ergebnis ist, dass Informationen auf dem Aufrufstapel überschrieben werden, einschließlich des Rückgabezeigers der Funktion. Die Daten legen den Wert des Rückgabezeigers fest, sodass die Funktion bei der Rückkehr die Kontrolle an den in den Daten des Angreifers enthaltenen Schadcode übergibt.

-   **Verweise**
- [OWASP-Sicherheitslücken: Pufferüberlauf](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

- [OWASP-Angriffe: Pufferüberlauf](https://owasp.org/www-community/attacks/Buffer_overflow_attack)

- [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
