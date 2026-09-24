# Aufbau eines modernen Programms zur Anwendungssicherheit

Die OWASP-Top-10-Listen sind Informationsdokumente, die darauf abzielen, das Bewusstsein für die kritischsten Risiken des jeweiligen Themas zu schärfen. Sie sind nicht als vollständige Liste gedacht, sondern lediglich als Ausgangspunkt. In früheren Versionen dieser Liste haben wir die Einführung eines Programms zur Anwendungssicherheit als besten Weg empfohlen, um diese und weitere Risiken zu vermeiden. In diesem Abschnitt behandeln wir, wie man ein modernes Programm zur Anwendungssicherheit aufbaut und weiterentwickelt.

Wenn Sie bereits über ein Anwendungssicherheitsprogramm verfügen, sollten Sie eine Reifegradbewertung mithilfe von [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) oder DSOMM (DevSecOps Maturity Model) durchführen. Diese Reifegradmodelle sind umfassend und ausführlich und können Ihnen dabei helfen, herauszufinden, worauf Sie Ihre Bemühungen zur Erweiterung und Weiterentwicklung Ihres Programms am besten konzentrieren sollten. Bitte beachten Sie: Sie müssen nicht alle Schritte in OWASP SAMM oder DSOMM durchführen, um gute Arbeit zu leisten; die Modelle dienen als Leitfaden und bieten viele Optionen. Sie sollen keine unerreichbaren Standards vorgeben oder unerschwingliche Programme beschreiben. Sie sind umfassend, um Ihnen viele Ideen und Optionen zu bieten.

Wenn Sie ein Programm von Grund auf neu starten oder OWASP SAMM oder DSOMM für Ihr Team derzeit als „zu viel“ empfinden, lesen Sie bitte die folgenden Ratschläge.


### 1. Einführung eines risikobasierten Portfolioansatzes:

* Ermitteln Sie den Schutzbedarf Ihres Anwendungsportfolios aus geschäftlicher Sicht. Dabei sollten unter anderem Datenschutzgesetze und andere Vorschriften berücksichtigt werden, die für die zu schützenden Datenbestände relevant sind.

* Erstellen Sie ein [Risikobewertungsmodell](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) mit einem einheitlichen Satz von Wahrscheinlichkeits- und Auswirkungsfaktoren, die die Risikotoleranz Ihres Unternehmens widerspiegeln.

* Bewerten und priorisieren Sie entsprechend alle Ihre Anwendungen und APIs. Fügen Sie die Ergebnisse Ihrer [Konfigurationsmanagement-Datenbank (CMDB)](https://de.wikipedia.org/wiki/Configuration_Management_Database) hinzu.

* Legen Sie Sicherheitsrichtlinien fest, um den erforderlichen Umfang und Grad an Genauigkeit richtig zu definieren.


### 2. Schaffung einer soliden Grundlage:

* Legen Sie eine Reihe gezielter Richtlinien und Standards fest, die allen Entwicklungsteams als Grundlage für die Anwendungssicherheit dienen.

* Definieren Sie einen gemeinsamen Satz wiederverwendbarer Sicherheitsmaßnahmen, die diese Richtlinien und Standards ergänzen, und geben Sie Leitlinien für deren Anwendung in den Bereichen Design und Entwicklung vor.

* Erstellen Sie ein obligatorisches Schulungsprogramm zur Anwendungssicherheit, das auf verschiedene Entwicklungsrollen und Themen zugeschnitten ist.

### 3. Integration von Sicherheit in bestehende Prozesse:

* Definieren und integrieren Sie Maßnahmen zur sicheren Implementierung und Verifizierung in bestehende Entwicklungs- und Betriebsprozesse.

* Zu diesen Maßnahmen gehören Bedrohungsmodellierung, sicheres Design und Designprüfung, sicheres Programmieren und Codeüberprüfung, Penetrationstests sowie die Behebung von Schwachstellen.

* Stellen Sie Fachexpert:innen und Unterstützungsdienste bereit, damit Entwicklungs- und Projektteams erfolgreich arbeiten können.

* Überprüfen Sie Ihren aktuellen Systementwicklungslebenszyklus sowie alle Aktivitäten, Werkzeuge, Richtlinien und Prozesse im Bereich Softwaresicherheit und dokumentieren Sie diese anschließend.

* Fügen Sie bei neuer Software eine oder mehrere Sicherheitsmaßnahmen in jede Phase des Systementwicklungslebenszyklus (SDLC) ein. Im Folgenden finden Sie zahlreiche Vorschläge, was Sie tun können. Stellen Sie sicher, dass Sie diese neuen Maßnahmen bei jedem neuen Projekt oder jeder neuen Softwareinitiative durchführen. Auf diese Weise können Sie sicher sein, dass jede neue Software mit einem für Ihr Unternehmen akzeptablen Sicherheitsniveau ausgeliefert wird.

* Wählen Sie Ihre Maßnahmen so aus, dass Ihr Endprodukt ein für Ihr Unternehmen akzeptables Risikoniveau aufweist.

* Für bestehende Software (manchmal auch als Legacy-Software bezeichnet) sollten Sie über einen formellen Wartungsplan verfügen. Ideen zur Aufrechterhaltung sicherer Anwendungen finden Sie weiter unten im Abschnitt „Betrieb und Änderungsmanagement“.


### 4. Schulungen zur Anwendungssicherheit:

* Erwägen Sie die Einführung eines „Security Champion“-Programms oder eines allgemeinen Sicherheitsschulungsprogramms für Ihre Entwickler:innen (manchmal auch als „Security Awareness“-Programm bezeichnet), um ihnen alles beizubringen, was sie Ihrer Meinung nach wissen sollten. So bleiben sie auf dem neuesten Stand, lernen, wie sie ihre Arbeit sicher ausführen können, und tragen dazu bei, die Sicherheitskultur in Ihrem Unternehmen positiver zu gestalten. Oft verbessert dies auch das Vertrauen zwischen den Teams und sorgt für ein harmonischeres Arbeitsklima. OWASP unterstützt Sie dabei mit dem [OWASP Security Champions Guide](https://securitychampions.owasp.org/), der Schritt für Schritt erweitert wird.

* Das OWASP Education Project stellt Schulungsmaterialien bereit, um Entwickler:innen in Bezug auf Webanwendungssicherheit zu schulen. Für praktisches Lernen über Schwachstellen probieren Sie das [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/) oder [OWASP WebGoat](https://owasp.org/www-project-webgoat/) aus. Um auf dem Laufenden zu bleiben, besuchen Sie eine [OWASP AppSec Konferenz](https://owasp.org/events/), ein [OWASP Konferenz Training](https://owasp.org/events/) oder lokale Treffen der [OWASP-Chapters](https://owasp.org/chapters/).


### 5. Transparenz für das Management schaffen:

* Managen Sie anhand von Kennzahlen. Treiben Sie Verbesserungen und Finanzierungsentscheidungen auf der Grundlage der erfassten Kennzahlen und Analysedaten voran. Zu den Kennzahlen gehören die Einhaltung von Sicherheitspraktiken und -maßnahmen, neu auftretende Schwachstellen, behobene Schwachstellen, Anwendungsabdeckung, Fehlerdichte nach Art und Anzahl der Vorkommen usw.

* Analysieren Sie Daten aus den Implementierungs- und Verifizierungsaktivitäten, um nach Ursachen und Schwachstellenmustern zu suchen und so strategische und systemische Verbesserungen im gesamten Unternehmen voranzutreiben. Lernen Sie aus Fehlern und bieten Sie positive Anreize, um Verbesserungen zu fördern.



## Einrichtung und Anwendung wiederholbarer Sicherheitsprozesse und standardisierter Sicherheitskontrollen

### Phase der Anforderungs- und Ressourcenverwaltung:

* Erfassen und verhandeln Sie gemeinsam mit dem Fachbereich die geschäftlichen Anforderungen an eine Anwendung, einschließlich der Schutzanforderungen hinsichtlich Vertraulichkeit, Authentizität, Integrität und Verfügbarkeit aller Datenbestände sowie der erwarteten Geschäftslogik.

* Erstellen Sie die technischen Anforderungen, einschließlich funktionaler und nicht-funktionaler Sicherheitsanforderungen. OWASP empfiehlt, den [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) als Leitfaden für die Festlegung der Sicherheitsanforderungen für Ihre Anwendung(en) zu verwenden.

* Planen und verhandeln Sie das Budget, das alle Aspekte von Entwurf, Entwicklung, Test und Betrieb abdeckt, einschließlich der Sicherheitsmaßnahmen.

* Nehmen Sie Sicherheitsmaßnahmen in Ihren Projektplan auf.

* Stellen Sie sich beim Projektstart als Sicherheitsbeauftragte:r vor, damit die Projektbeteiligten wissen, an wen sie sich wenden können.


### Ausschreibung und Vertragsabschluss:

* Verhandeln Sie die Anforderungen mit internen oder externen Entwickler:innen, einschließlich Richtlinien und Sicherheitsanforderungen im Hinblick auf Ihr Sicherheitsprogramm, z. B. SDLC und bewährte Methoden.

* Bewerten Sie die Erfüllung aller technischen Anforderungen, einschließlich einer Planungs- und Entwurfsphase.

* Verhandeln Sie alle technischen Anforderungen, einschließlich Design, Sicherheit und Leistungsvereinbarung (SLA).

*  Verwenden Sie Vorlagen und Checklisten, wie z. B. den [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex).<br>**Hinweis:** *Der Anhang bezieht sich auf das US-Vertragsrecht; bitte holen Sie daher qualifizierten Rechtsrat ein, bevor Sie den Musteranhang verwenden.*


### Planungs- und Entwurfsphase:

*  Besprechen Sie die Planung und den Entwurf mit den Entwicklern und internen Beteiligten, z. B. Sicherheitsspezialisten.

*  Definieren Sie die Sicherheitsarchitektur, Kontrollmaßnahmen, Gegenmaßnahmen und Entwurfsprüfungen (design reviews) entsprechend den Schutzanforderungen und dem erwarteten Bedrohungsniveau. Dies sollte von Sicherheitsspezialisten unterstützt werden.

*  Anstatt Sicherheitsfunktionen nachträglich in Ihre Anwendungen und APIs zu integrieren, ist es weitaus kostengünstiger, die Sicherheit von Anfang an mit einzuplanen. OWASP empfiehlt die [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) und die [OWASP Proactive Controls](https://top10proactive.owasp.org/) als guten Ausgangspunkt für Anleitungen zur Gestaltung von von Anfang an integrierter Sicherheit.

*  Führen Sie eine Bedrohungsmodellierung durch, siehe [OWASP Cheat Sheet: Bedrohungsmodellierung](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

*  Vermitteln Sie Ihren Softwarearchitekt:innen sichere Designkonzepte und -muster und bitten Sie sie, diese nach Möglichkeit in ihre Entwürfe zu integrieren.

*  Prüfen Sie gemeinsam mit Ihren Entwickler:innen die Datenflüsse.

*  Fügen Sie neben all Ihren anderen User Stories auch Sicherheits-User-Stories hinzu.


### Sicherer Entwicklungslebenszyklus:

* Um den Prozess zu verbessern, den Ihr Unternehmen bei der Entwicklung von Anwendungen und APIs befolgt, empfiehlt OWASP das [OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/). Dieses Modell hilft Unternehmen dabei, eine Strategie für Softwaresicherheit zu formulieren und umzusetzen, die auf die spezifischen Risiken zugeschnitten ist, denen Ihr Unternehmen ausgesetzt ist.

*  Bieten Sie Ihren Softwareentwickler:innen Schulungen zum sicheren Programmieren sowie alle anderen Schulungen an, von denen Sie glauben, dass sie ihnen helfen, robustere und sicherere Anwendungen zu erstellen.

*  Code-Review, siehe [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).

*  Stellen Sie Ihren Entwickler:innen Sicherheitswerkzeuge zur Verfügung und bringen Sie ihnen deren Nutzung bei, insbesondere im Hinblick auf statische Analyse, Software-Kompositionsanalyse, Geheimnisscanner (Secrets) und [Infrastructure als Code (IaC)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html).

*  Schaffen Sie nach Möglichkeit Leitplanken für Ihre Entwickler:innen (technische Schutzmaßnahmen, die sie zu sichereren Entscheidungen lenken).

*   Die Entwicklung robuster und benutzungsfreundlicher Sicherheitsmaßnahmen ist schwierig. Bieten Sie nach Möglichkeit sichere Standardeinstellungen an und schaffen Sie „gepflasterte Wege“ (indem Sie den einfachsten Weg auch zum sichersten Weg machen, also zur naheliegenden und bevorzugten Vorgehensweise). Die [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) sind ein guter Ausgangspunkt für Entwickler:innen, und viele moderne Frameworks verfügen mittlerweile über standardmäßige und wirksame Sicherheitskontrollen für Autorisierung, Validierung, CSRF-Prävention usw.

*  Stellen Sie Ihren Entwickler:innen sicherheitsrelevante Entwicklungsumgebungsplugins zur Verfügung und ermutigen Sie sie, diese zu nutzen.

*  Stellen Sie ihnen ein Werkzeug zur Verwaltung von Geheimnissen (Secrets)  und die nötigen Lizenzen und eine Dokumentation zur Verwendung bereit.

*  Stellen Sie ihnen eine private KI zur Verfügung, idealerweise eingerichtet mit einem RAG-Server voller nützlicher Sicherheitsdokumentation, Prompts, die Ihr Team für bessere Ergebnisse verfasst hat, und einem MCP-Server, der die für Ihre Organisation ausgewählten Sicherheitswerkzeuge aufruft. Bringen Sie ihnen bei, wie man KI sicher nutzt, denn sie werden es tun, ob es Ihnen gefällt oder nicht.


### Einführung kontinuierlicher Tests zur Anwendungssicherheit:

*  Prüfen Sie technische Funktionen, die Integration in die IT-Architektur und Koordinieren Sie Tests der Fachlogik.

*  Erstellung von Testfällen für „korrekte“ und „missbräuchliche“ Nutzung aus technischer und geschäftlicher Perspektive.

* Verwalten Sie Sicherheitstests gemäß internen Prozessen, den Schutzanforderungen und dem von der Anwendung angenommenen Bedrohungsgrad.

* Stellen Sie Sicherheitstest-Werkzeuge (Fuzzer, DAST usw.), eine sichere Testumgebung und Schulungen zu deren Verwendung bereit, ODER führen Sie die Tests für sie durch ODER beauftragen Sie eine:n Tester:in.

*  Wenn Sie ein hohes Maß an Sicherheit benötigen, ziehen Sie einen formellen Penetrationstest sowie Stress- und Leistungstests (Performance) in Betracht.

*  Arbeiten Sie mit Ihren Entwickler:innen zusammen, um ihnen bei der Entscheidung zu helfen, was aus den Fehlerberichten behoben werden muss, und stellen Sie sicher, dass ihre Vorgesetzten ihnen die dafür erforderliche Zeit einräumen.


### Inbetriebnahme:

* Die Anwendung in Betrieb nehmen und bei Bedarf von zuvor verwendeten Anwendungen migrieren.

* Die gesamte Dokumentation fertigstellen, einschließlich der Change-Management-Datenbank (CMDB) und der Sicherheitsarchitektur.


### Betrieb und Änderungsmanagement:

*  Der Betrieb muss Richtlinien für das Sicherheitsmanagement der Anwendung enthalten (z. B. Patch-Management).

*  Das Sicherheitsbewusstsein der Benutzer:innen schärfen und Konflikte zwischen Benutzbarkeit und Sicherheit bewältigen.

*  Änderungen planen (Change Management) und verwalten, z. B. die Migration auf neue Versionen der Anwendung oder anderer Komponenten wie Betriebssystem, Middleware und Bibliotheken.

*  Stellen Sie sicher, dass alle Anwendungen in Ihrem Bestand erfasst sind und alle wichtigen Details dokumentiert sind. Aktualisieren Sie die gesamte Dokumentation, einschließlich der CMDB sowie der Sicherheitsarchitektur, Kontrollen und Gegenmaßnahmen, einschließlich aller Betriebshandbücher oder Projektdokumentationen.

*  Nutzen Sie Protokollierung, Überwachung und Alarmierung für alle Anwendungen. Fügen Sie diese hinzu, falls sie fehlen.

*  Erstellen Sie Prozesse für eine effektive und effiziente Aktualisierung und Patch-Verwaltung.

*  Erstellen Sie regelmäßige Scan-Zeitpläne (idealerweise für dynamische, statische, Secret-, IaC- und Software-Composition-Analysen).

*  Definieren Sie SLAs für die Behebung von Sicherheitsfehlern.

*  Stellen Sie eine Möglichkeit für Mitarbeiter:innen (und idealerweise auch für Ihre Kund:innen) bereit, Fehler zu melden.

*  Richten Sie ein geschultes Vorfallreaktionsteam (Incident Response) ein, das weiß, wie Softwareangriffe aussehen, und das mit Überwachungswerkzeugen (Observability-Tools) vertraut ist.

*  Setzen Sie Blockierungs- oder Schutz-Werkzeuge ein, um automatisierte Angriffe zu stoppen.

*  Jährliche (oder häufigere) Absicherung der Konfigurationen.

*  Mindestens jährliche Penetrationstests (abhängig vom für Ihre Anwendung erforderlichen Sicherheitsniveau).

*  Richten Sie Prozesse und Werkzeuge zur Absicherung und zum Schutz Ihrer Software-Lieferkette ein.

*  Erstellen und aktualisieren Sie Pläne zur Geschäftskontinuität und Notfallwiederherstellung, die Ihre wichtigsten Anwendungen sowie die zu deren Wartung verwendeten Werkzeuge umfassen.


### Außerbetriebnahme von Systemen:

* Alle erforderlichen Daten sollten archiviert werden. Alle übrigen Daten sollten sicher gelöscht werden.

* Nehmen Sie die Anwendung sicher außer Betrieb, einschließlich der Löschung nicht mehr genutzter Konten, Rollen und Berechtigungen.

* Setzen Sie den Status Ihrer Anwendung in der CMDB auf „außer Betrieb“.


## Die Verwendung der OWASP Top 10 als Standard

Die OWASP Top 10 ist in erster Linie ein Dokument zur Sensibilisierung. Dies hat Unternehmen jedoch nicht davon abgehalten, sie seit ihrer Einführung im Jahr 2003 als de-facto-Standard für die Anwendungssicherheit in der Branche zu nutzen. Wenn Sie die OWASP Top 10 als Standard für die Programmierung oder das Testen verwenden möchten, sollten Sie sich bewusst sein, dass sie das absolute Minimum darstellt und lediglich einen Ausgangspunkt bildet.

Eine der Schwierigkeiten bei der Verwendung der OWASP Top 10 als Standard besteht darin, dass wir AppSec-Risiken und nicht unbedingt leicht testbare Probleme dokumentieren. Beispielsweise geht [A06:2025 – Unsicheres Design](A06_2025-Insecure_Design.md) über den Rahmen der meisten Testverfahren hinaus. Ein weiteres Beispiel ist die Prüfung, ob eine vor Ort vorhandene, genutzte und wirksame Protokollierung und Überwachung implementiert ist, was nur durch Befragungen und die Anforderung einer Stichprobe wirksamer Reaktionen auf Vorfälle erfolgen kann. Ein statisches Code-Analyse-Werkzeug kann zwar nach fehlender Protokollierung suchen, aber es ist möglicherweise unmöglich festzustellen, ob die Geschäftslogik oder die Zugriffskontrolle kritische Sicherheitsverletzungen protokolliert. Penetrationstester:innen können möglicherweise nur feststellen, dass sie in einer Testumgebung eine Reaktion auf Vorfälle ausgelöst haben, die selten auf die gleiche Weise überwacht wird wie die Produktionsumgebung.

Hier sind unsere Empfehlungen dazu, wann die Verwendung der OWASP Top 10 sinnvoll ist:

<table>
  <tr>
   <td><strong>Anwendungsfall</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>OWASP Application Security Verification Standard</strong>
   </td>
  </tr>
  <tr>
   <td>Sensibilisierung
   </td>
   <td>Ja
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Schulung
   </td>
   <td>Zum Einstieg
   </td>
   <td>Umfassend
   </td>
  </tr>
  <tr>
   <td>Design und Architektur
   </td>
   <td>Gelegentlich
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Programmier-Standard
   </td>
   <td>Absolutes Minimum
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Prüfung des Codes<br />(Secure Code Review)
   </td>
   <td>Absolutes Minimum
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Checkliste für gegenseitige Begutachtung (Peer Review)
   </td>
   <td>Absolutes Minimum
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Unit-Tests
   </td>
   <td>Gelegentlich
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Integrationstests
   </td>
   <td>Gelegentlich
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Penetrations-Tests
   </td>
   <td>Absolutes Minimum
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Werkzeug-Unterstützung
   </td>
   <td>Absolutes Minimum
   </td>
   <td>Ja
   </td>
  </tr>
  <tr>
   <td>Sichere Lieferketten
   </td>
   <td>Gelegentlich
   </td>
   <td>Ja
   </td>
  </tr>
</table>


Wir empfehlen allen, die einen Standard für die Anwendungssicherheit einführen möchten, den [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) zu verwenden, da dieser so konzipiert ist, dass er überprüfbar und testbar ist, und in allen Phasen eines sicheren Entwicklungszyklus eingesetzt werden kann.

Der ASVS ist die einzig akzeptable Wahl für Werkzeug-Anbieter:innen. Werkzeuge können die OWASP Top 10 aufgrund der Natur einiger der darin enthaltenen Risiken nicht umfassend erkennen, testen oder dagegen schützen, siehe [A06:2025 – Unsicheres Design](A06_2025-Insecure_Design.md). OWASP rät von jeglichen Behauptungen ab, die OWASP Top 10 vollständig abzudecken, da dies schlichtweg nicht der Wahrheit entspricht.
