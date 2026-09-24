# Was sind Sicherheitsrisiken für die Anwendungen?
Angreifer:innen können potenziell viele verschiedene Wege über Ihre Anwendung nutzen, um Ihrem Unternehmen oder Ihrer Organisation Schaden zuzufügen. Jeder dieser Wege birgt ein potenzielles Risiko, das untersucht werden muss.

![Calculation diagram](../assets/2025-algorithm-diagram.png)

<table>
  <tr>
   <td>
    <strong>Bedrohungsakteur:innen</strong>
   </td>
   <td>
    <strong>Angriff /
Vektoren</strong>
   </td>
   <td>
    <strong>Ausnutzbarkeit</strong>
   </td>
   <td>
    <strong>Wahrscheinlichkeit von fehlenden</strong>
    <strong>Sicherheitsmaßnahmen</strong>
   </td>
   <td>
    <strong>Technische</strong>
    <strong>Auswirkungen</strong>
   </td>
   <td>
    <strong>Geschäftliche</strong>
    <strong>Auswirkungen</strong>
   </td>
  </tr>
  <tr>
   <td>
    <strong>Je nach Umgebung /
dynamisch von der Situation abhänging</strong>
   </td>
   <td>
    <strong>Je nach Ausgesetztheit der Anwendung (in der Umgebung)</strong>
   </td>
   <td>
    <strong>Durchschn. gewichtete Ausnutzbarkeit</strong>
   </td>
   <td>
    <strong>Fehlende Maßnahmen /
zu durchschnittlicher Inzidenzrate /
gewichtet nach Abdeckung</strong>
   </td>
   <td>
    <strong>Durchschn. gewichtete Auswirkung</strong>
   </td>
   <td>
    <strong>Je nach Geschäft</strong>
   </td>
  </tr>
</table>

Bei unserer Risikobewertung haben wir die allgemeinen Parameter der Ausnutzbarkeit, der durchschnittlichen Wahrscheinlichkeit von Sicherheitsmaßnahmen für eine Schwachstelle und deren technische Auswirkungen berücksichtigt. 

Jede Organisation ist einzigartig, ebenso wie die Angreifer:innen, die es auf sie abgesehen haben, ihre Ziele und die Auswirkungen eines möglichen Sicherheitsvorfalls. Wenn eine Organisation von öffentlichem Interesse ein Content-Management-System (CMS) für öffentliche Informationen nutzt und ein Gesundheitssystem genau dasselbe CMS für sensible Gesundheitsdaten verwendet, können die Angreifer:innen und die geschäftlichen Auswirkungen bei derselben Software sehr unterschiedlich sein. Es ist entscheidend, das Risiko für Ihre Organisation zu verstehen, basierend auf der Gefährdung der Anwendung, den relevanten Bedrohungsakteur:innen je nach Lagebild (für gezielte und ungezielte Angriffe je nach Geschäftsbereich und Standort) und den individuellen geschäftlichen Auswirkungen. 

## Wie die Daten zur Auswahl und Einstufung der Kategorien verwendet werden

Im Jahr 2017 wählten wir die Kategorien anhand der Häufigkeit aus, um die Wahrscheinlichkeit zu ermitteln, und stuften sie anschließend auf der Grundlage jahrzehntelanger Erfahrung in den Bereichen Ausnutzbarkeit, Erkennbarkeit (ebenfalls Wahrscheinlichkeit) und technische Auswirkungen im Rahmen von Teamdiskussionen ein. Für das Jahr 2021 verwendeten wir Daten zur Ausnutzbarkeit und zu den (technischen) Auswirkungen aus den CVSSv2- und CVSSv3-Bewertungen in der National Vulnerability Database (NVD). Für das Jahr 2025 setzten wir die gleiche Methodik fort, die wir 2021 entwickelt hatten.

Mittels OWASP Dependency Check extrahierten wir die CVSS-Bewertungen für Ausnutzbarkeit und Auswirkungen und gruppiert nach den zugehörigen CWEs. Dies erforderte einiges an Recherche und Aufwand, da alle CVEs zwar CVSSv2-Werte aufweisen, CVSSv2 jedoch Mängel aufweist, die CVSSv3 beheben sollte. Ab einem bestimmten Zeitpunkt werden allen CVEs auch CVSSv3-Werte zugewiesen. Zudem wurden die Bewertungsbereiche und Formeln zwischen CVSSv2 und CVSSv3 aktualisiert. 

In CVSSv2 konnten sowohl „Ausnutzbarkeit“ als auch „(Technische) 'Auswirkungen'“ bis zu 10,0 betragen, doch die Formel reduzierte diese Werte auf 60 % für „Ausnutzbarkeit“ und 40 % für Auswirkungen. In CVSSv3 war das theoretische Maximum auf 6,0 für „Ausnutzbarkeit“ und 4,0 für „Auswirkungen“ begrenzt. Unter Berücksichtigung der Gewichtung verschob sich die Auswirkungsbewertung nach oben, im Durchschnitt um fast eineinhalb Punkte in CVSSv3, während die Ausnutzbarkeit im Durchschnitt um fast einen halben Punkt nach unten ging, als wir die Analyse für die Top 10 2021 durchführten.

In der National Vulnerability Database (NVD) gibt es etwa 175.000 Datensätze (gegenüber 125.000 im Jahr 2021) von CVEs, die CWEs zugeordnet sind und aus dem OWASP Dependency Check extrahiert wurden. Darüber hinaus gibt es 643 eindeutige CWEs, die CVEs zugeordnet sind (gegenüber 241 im Jahr 2021). Von den fast 220.000 extrahierten CVEs wiesen 160.000 CVSS-v2-Werte, 156.000 CVSS-v3-Werte und 6.000 CVSS-v4-Werte auf. Viele CVEs haben mehrere Werte, weshalb die Gesamtzahl über 220.000 liegt.

Für die Top 10 2025 haben wir die durchschnittlichen Ausnutzbarkeits- und Auswirkungs-Werte wie folgt berechnet: Wir haben alle CVEs mit CVSS-Werten nach CWE gruppiert und sowohl die Ausnutzbarkeit- als auch die Auswirkungen-Werte nach dem prozentualen Anteil der Population mit CVSSv3 sowie der verbleibenden Population mit CVSSv2-Werten gewichtet, um einen Gesamtdurchschnitt zu erhalten. Diese Durchschnittswerte haben wir den CWEs im Datensatz zugeordnet, um sie als Ausnutzbarkeit- und (technische) Auswirkungen-Werte für die andere Hälfte der Risikogleichung zu verwenden.

Sie fragen sich vielleicht, warum wir nicht CVSS v4.0 verwenden? Das liegt daran, dass der Bewertungsalgorithmus grundlegend geändert wurde und er nicht mehr so einfach die *Ausnutzbarkeit*- oder *Auswirkungen*-Werte liefert wie CVSSv2 und CVSSv3. Wir werden versuchen, einen Weg zu finden, die CVSS v4.0-Bewertung für zukünftige Versionen der Top 10 zu nutzen, aber für die Ausgabe 2025 konnten wir keine zeitnahe Lösung dafür finden.

Für die Inzidenzrate haben wir den prozentualen Anteil der Anwendungen berechnet, die für jedes CWE anfällig sind, bezogen auf die von einer Organisation über einen bestimmten Zeitraum getestete Gesamtzahl an Anwendungen. Zur Erinnerung: Wir verwenden nicht die Häufigkeit (d. h. wie oft ein Problem in einer Anwendung auftritt), sondern uns interessiert, bei wie viel Prozent der Anwendungen jedes CWE festgestellt wurde. 

Für die Abdeckung betrachten wir den Prozentsatz der Anwendungen, die von allen Organisationen auf eine bestimmte CWE getestet wurden. Je höher die berechnete Abdeckung ist, desto größer ist die Sicherheit, dass die Inzidenzrate korrekt ist, da die Stichprobengröße repräsentativer für die Grundgesamtheit ist.

Die Formel, die wir für diese Iteration verwendet haben, ähnelt der von 2021, mit einigen Änderungen bei der Gewichtung:
(Max. Inzidenzrate % * 1000) + (Max. Abdeckung % * 100) + (Durchschnittliche Ausnutzbarkeit * 10) + (Durchschnittliche Auswirkungen * 20) + (Summe der Vorkommen / 10000) = Risikowert

Die berechneten Werte reichten von 621,60 für die Kategorie „Mangelhafte Zugriffskontrolle“ bis zu 271,08 für „Fehler bei der Speicherverwaltung“.

Dies ist kein perfektes System, aber es ist wertvoll für die Einstufung von Risikokategorien.

Eine weitere Herausforderung, die zunehmend an Bedeutung gewinnt, ist die Definition des Begriffs „Anwendung“. Da die Branche zunehmend auf andere Architekturen umstellt, die aus Microservices und anderen Implementierungen bestehen, die kleiner sind als eine herkömmliche Anwendung, werden die Berechnungen schwieriger. Wenn ein Unternehmen beispielsweise Code-Repositorys testet, was versteht es dann unter einer Anwendung? Ähnlich wie bei der Weiterentwicklung von CVSSv4 müssen möglicherweise auch in der nächsten Ausgabe der „Top 10“ die Analyse und die Bewertung angepasst werden, um der sich ständig wandelnden Branche Rechnung zu tragen.

## Daten Werte

Für jede der Top-Ten-Kategorien werden bestimmte Datenfaktoren aufgeführt. Hier ihre Bedeutung:

**Zuordnete CWEs:** Die Anzahl der CWEs, die vom Top-10-Team einer Kategorie zugeordnet wurden.

**Häufigkeit:** Die Häufigkeit ist der prozentuale Anteil der Anwendungen, die für diese CWE anfällig sind, gemessen an der von dieser Organisation in diesem Jahr getesteten Gesamtzahl.

**Gewichtete Ausnutzbarkeit:** Die Ausnutzbarkeits-Teilpunktezahl aus den CVSSv2- und CVSSv3-Bewertungen wurde den den CWEs zugeordneten CVEs zugewiesen, normalisiert und auf einer 10-Punkte-Skala dargestellt.

**Gewichtete Auswirkung:** Die Auswirkungs-Teilpunktzahl aus den CVSSv2- und CVSSv3-Bewertungen, die den den CWEs zugeordneten CVEs zugewiesen, normalisiert und auf einer 10-Punkte-Skala dargestellt wurden.

**(Test-)Abdeckung:** Der Prozentsatz der Anwendungen, die von allen Organisationen für eine bestimmte CWE getestet wurden.

**Gesamtanzahl:** Gesamtzahl der Anwendungen, bei denen die einer Kategorie zugeordneten CWEs festgestellt wurden.

**Gesamtzahl der CVEs:** Gesamtzahl der CVEs in der NVD-Datenbank, die den einer Kategorie zugeordneten CWEs zugeordnet wurden.

**Formel:** (Max. Inzidenzrate % * 1000) + (Max. Abdeckung % * 100) + (Durchschnittliche Ausnutzbarkeit * 10) + (Durchschnittliche Auswirkungen * 20) + (Summe der Vorkommen / 10000) = Risikowert
