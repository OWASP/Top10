

# Für OWASP 2021

```
# Tabellenüberschriften
CWEs Mapped                     Zugeordnete CWEs
Max Incidence Rate              Maximale Häufigkeit
Avg Incidence Rate              Durchschn. Häufigkeit
Avg Weighted Exploit            Durchschn. Ausnutzbarkeit (gewichtet)
Avg Weighted Impact             Durchschn. Auswirkungen (gewichtet)
Max Coverage                    Maximale Abdeckung
Avg Coverage                    Durchschnittliche Abdeckung
Total Occurrences               Gesamtanzahl
Total CVEs                      CVEs insgesamt


# Überschriften
Factors                         Beurteilungskriterien
Overview                        Bezug / Kontext / Auswertung
Description                     Beschreibung
How to Prevent                  Prävention und Gegenmaßnahmen
Example Attack Scenarios        Beispielhafte Angriffsszenarien 
References			Referenzen
List of Mapped CWEs		Liste der zugeordneten CWEs


# OWASP Kategorien
Broken Access Control                           Mangelhafte Zugriffskontrolle
Cryptographic Failures                          Fehlerhafter Einsatz von Kryptographie
Injection                                       Injection
Insecure Design                                 Unsicheres Anwendungsdesign
Security Misconfiguration                       Sicherheitsrelevante Fehlkonfiguration
Vulnerable and Outdated Components              Unsichere oder veraltete Komponenten
Identification and Authentication Failures      Fehlerhafte Authentifizierung
Software and Data Integrity Failures            Fehlerhafte Prüfung der Software- und Datenintegrität
Security Logging and Monitoring Failures        Unzureichendes Logging und Sicherheitsmonitoring
Server-Side Request Forgery (SSRF)              Server-Side Request Forgery (SSRF)

# Häufig verwendete Fachbegriffe
Cross site scripting                            Cross-Site-Scripting (XSS)
application stack                               Anwendungsstack
application security                            Anwendungssicherheit
network service                                 Netzwerkdienste
platform                                        Plattform
web server                                      Web-Server
application server                              Anwendungsserver
database                                        Datenbank
frameworks                                      Frameworks
Shift-Left					                    "Shift-Left-Ansatz"
governance                                      Governance
library                                         Programmbibliothek
custom code                                     selbstentwickelter Code
virtual machines                                virtuelle Maschinen
containers                                      Container
storage.                                        Speicher
scanners                                        Scanner
misconfigurations                               Fehlkonfigurationen
mitigation                                      Mitigierung
operations team                                 Betriebsteam
default accounts                                Default-Konten
default configurations                          Default-Konfigurationen
unnecessary services                            nicht benötigte Dienste
compromise                                      Kompromittierung
security development lifecycle                  Sicherer Entwicklungs-Lifecycle
security posture                                Sicherheitslage /-status
stack trace                                   	Stacktrace
threat modelling                                Bedrohungsanalyse
vulnerability                                   Schwachstelle


# Aus OWASP 2010
Englisch			Deutsch	Abschnitt		Bemerkungen
Am I vulnerable?		Bin ich verwundbar?		
Application			Anwendung		
Application Security		Anwendungssicherheit		
Application Security Program	???				O: About OWASP	
appropriate			geeignet		
Asset				Ressource	Flow-Chart bei "Technical Impact"	Im Sinne technisches Asset
Attack				Angriff		
Attack Vector			Angriffsvektor		
Attack Vector			Ausnutzbarkeit	Tabelle bei "Wie groß ist mein Risiko?"	Hier keine Übersetzung, da die Überschrift schon im Englischen "falsch ist". Attack Vector ist kein messbares Attribut
Average	Durchschnittlich	Tabelle bei "Wie groß ist mein Risiko?" / Attack Vector	
Average	Durchschnittlich	Tabelle bei "Wie groß ist mein Risiko?" / Attack Vector	
Awareness	Sensibilisierung		
Broken Authentication and Session Management	Fehler in Authentifizierung und Session Management		
Business Impact	Auswirkung auf das Unternehmen	Tabelle bei "Wie groß ist mein Risiko?"	
Business or Organization	Unternehmen oder Organisation		
Common	häufig	Tabelle bei "Wie groß ist mein Risiko?" / Weakness Prevelance	
Control	Maßnahme		
Credentials	Benutzerkennungen und Passwörter	T10	
Cross-Site Request Forgery	Cross-Site Request Forgery		
Cross-Site Scripting	Cross-Site Scripting		
Detectability	Auffindbarkeit	Tabelle bei "Wie groß ist mein Risiko?"	Kein Hit, aber besser als nichts
Developer	Software-Entwickler	+D	
Difficult	Schwierig	Tabelle bei "Wie groß ist mein Risiko?" / Attack Vector	
Difficult	Schwierig	Tabelle bei "Wie groß ist mein Risiko?" / Attack Vector	
Easy	Einfach	Tabelle bei "Wie groß ist mein Risiko?" / Attack Vector	
Easy	Einfach	Tabelle bei "Wie groß ist mein Risiko?" / Attack Vector	
encrypt	verschlüsseln		
escape	durch Kontrollzeichen als Text kodieren		
escape	Entschärfung von Steuerzeichen		
escape	Konvertierung von möglichen Steuerzeichen		
Example Attack Scenarios	Mögliche Angriffsszenarien		
External	Andere	Im Kasten	
Failure to Restrict URL Access	Mangelhafter URL-Zugriffsschutz		
Flaw	Fehler		
free and open	frei zugänglich	O: About OWASP	
Function	Funktionalität	Flow-Chart bei "Technical Impact"	
hashing	Hash-Berechnung		
hashing	hashing		
hashing	Hash-Verfahren		
hijack	kappern		
hijack	übernehmen		
How Do I Prevent This?	Wie kann ich das verhindern?		
Impact	Auswirkung		
Injection	Injection		
Injection	Injection		
Insecure Cryptographic Storage	Kryptografisch unsichere Speicherung		
Insecure Direct Object References	Unsichere direkte Objektreferenzen		
Insufficient Transport Layer Protection	Unzureichende Absicherung der Transportschicht		
Minor	Gering	Tabelle bei "Wie groß ist mein Risiko?" / Technical Impact	
Moderate	Mittel	Tabelle bei "Wie groß ist mein Risiko?" / Technical Impact	
Notes about Risk	Anmerkungen zum Risikobegriff	+R	
Open Source	Open Source		
Organizations	Organisationen	+O	
raising awareness	sensibilisieren	O: About OWASP	
References	Referenzen		
Release Notes	Neuerungen	RN: Release Notes	
Risk	Risiko		
Security Control	Sicherhetismaßnahme		
Security Misconfiguration	Sicherheitsrelevante Fehlkonfiguration		
Session	Session		
Session ID	Session ID		
Severe	Schwerwiegend	Tabelle bei "Wie groß ist mein Risiko?" / Technical Impact	
SSN (social security number)	/* ersetzen durch */ personenbezogene Daten		
Technical Impact	Technische Auswirkung	Tabelle bei "Wie groß ist mein Risiko?"	
Threat	Bedrohung		
Threat Agent	Bedrohungsquelle		Lange Diskussion und letztendlich ein "fauler Kompromiss"
To raise awareness	Bewusstsein verstärken	O: About OWASP	
Top 10	Top 10		Immer mit Leerzeichen zwischen Top und 10
Uncommon	selten	Tabelle bei "Wie groß ist mein Risiko?" / Weakness Prevelance	
Unless their UI Framework …	Soweit dies nicht bereits durch ein eingesetztes Framework sichergestellt …	A2	
untrusted data	???		
Unvalidated Redirects and Forwards	Ungeprüfte Um- und Weiterleitungen		
verification	Überprüfung		
verification 	Verifikation		
Verifiers	Prüfer	+V	
Very Widespread	außergewöhnlich häufig	Tabelle bei "Wie groß ist mein Risiko?" / Weakness Prevelance	Ist in der Tabelle nicht adressiert…. Farbige Markierung und Bemerkung…
Weakness	Schwachstelle		
Weakness Prevelance	Verbreitung	Tabelle bei "Wie groß ist mein Risiko?"	Bewusste Entscheidung, Weakness hier nicht mehr zu adressieren
Web Application	Webanwendung		Web ist inzwischen ein deutsches Wort. Daher bewusste Entscheidung gegen Web-Anwendung
What's next for …	Nächste Schritte für …		
Widespread	sehr häufig	Tabelle bei "Wie groß ist mein Risiko?" / Weakness Prevelance	


```
