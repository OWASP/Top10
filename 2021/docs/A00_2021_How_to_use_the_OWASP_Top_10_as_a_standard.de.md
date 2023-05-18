# Wie man die OWASP Top 10 als Standard verwendet

Die OWASP Top 10 sind in erster Linie ein Sensibilisierungsdokument. Dies hat Unternehmen jedoch nicht davon abgehalten, ihn seit seiner Einführung im Jahr 2003 als De-facto-AppSec-Branchenstandard zu verwenden. Wenn Sie die OWASP Top 10 als Codierungs- oder Teststandard verwenden möchten, sollten Sie wissen, dass es sich dabei um das absolute Minimum und nur um einen Anfang handelt.

Eine der Schwierigkeiten bei der Verwendung der OWASP Top 10 als Standard besteht darin, dass wir AppSec-Risiken dokumentieren und nicht unbedingt leicht testbare Probleme. Beispielsweise liegt A04:2021-Insecure Design außerhalb des Rahmens der meisten Tests. Ein weiteres Beispiel ist das Testen, ob eine wirksame Protokollierung und Überwachung vor Ort, im Einsatz und implementiert ist, was nur durch Befragungen und die Anforderung einer Stichprobe wirksamer Vorfallreaktionen möglich ist. Ein statisches Code-Analysetool kann nach fehlender Protokollierung suchen, es kann jedoch unmöglich festzustellen, ob die Geschäftslogik oder die Zugriffskontrolle Angriffe auf das Sicherheitskonzepts protokolliert. Penetrationstester können möglicherweise nur in einer Testumgebung feststellen, dass sie die Reaktion auf Vorfälle ausgelöst haben, die selten genauso penibel im Produktionseinsatz überwacht wird.

Hier sind unsere Empfehlungen, wann es sinnvoll ist, die OWASP Top 10 zu verwenden:

| Anwendungsfall | OWASP Top 10 2021 | OWASP-Standard zur Anwendungssicherheitsüberprüfung |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| Bewusstsein | Ja | |
| Training | Einstiegsniveau | Umfassend |
| Design und Architektur | Gelegentlich | Ja |
| Programmierstandard | Das absolute Minimum | Ja |
| Überprüfung des sicheren Codes | Das absolute Minimum | Ja |
| Checkliste für Peer-Reviews | Das absolute Minimum | Ja |
| Unit-Tests | Gelegentlich | Ja |
| Integrationstests | Gelegentlich | Ja |
| Penetrationstests | Das absolute Minimum | Ja |
| Werkzeugunterstützung | Das absolute Minimum | Ja |
| Sichere Lieferkette | Gelegentlich | Ja |

Wir empfehlen jedem, der einen Anwendungssicherheitsstandard übernehmen möchte, den [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) zu verwenden, da er so konzipiert ist dass er nachweisbar zu sein und testbar ist, und in allen Teilen eines sicheren Entwicklungslebenszyklus verwendet werden kann.

Für Werkzeuganbieter ist das ASVS die einzig akzeptable Wahl. Tools können die in der OWASP-Top-10 beschriebenen Bedrohungen aufgrund der Art der Risiken nicht umfassend erkennen, darauf testen oder davor schützen, unter Verweis auf A04:2021 – Unsicheres Design. OWASP rät von jeglichen Behauptungen über eine vollständigen Schutz vor den Bedrohungen aus der OWASP Top 10 ab, da diese schlichtweg unwahr sind.
