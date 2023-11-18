# Wie man die OWASP Top 10 als Standard verwendet

Die OWASP Top 10 sind in erster Linie ein Sensibilisierungsdokument. Dies hat Unternehmen jedoch nicht davon abgehalten, ihn seit seiner Einführung im Jahr 2003 als De-facto-Branchen-AppSec-Standard zu verwenden. Wenn Sie die OWASP Top 10 als Codierungs- oder Teststandard verwenden möchten, wissen Sie, dass es sich um das absolute Minimum und nur um einen Anfang handelt Punkt.

Eine der Schwierigkeiten bei der Verwendung der OWASP Top 10 als Standard besteht darin, dass wir AppSec-Risiken dokumentieren und nicht unbedingt leicht testbare Probleme. Beispielsweise liegt A04:2021-Insecure Design außerhalb des Rahmens der meisten Testformen. Ein weiteres Beispiel ist das Testen, ob eine wirksame Protokollierung und Überwachung vor Ort, im Einsatz und implementiert ist, was nur durch Befragungen und die Anforderung einer Stichprobe wirksamer Vorfallreaktionen möglich ist. Ein statisches Code-Analysetool kann nach fehlender Protokollierung suchen, es kann jedoch unmöglich sein, festzustellen, ob die Geschäftslogik oder die Zugriffskontrolle kritische Sicherheitsverstöße protokolliert. Penetrationstester können möglicherweise nur in einer Testumgebung feststellen, dass sie die Reaktion auf Vorfälle ausgelöst haben, die selten auf die gleiche Weise wie die Produktion überwacht wird.

Hier sind unsere Empfehlungen, wann es sinnvoll ist, die OWASP Top 10 zu verwenden:

| Anwendungsfall | OWASP Top 10 2021 | OWASP-Standard zur Anwendungssicherheitsüberprüfung |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| Bewusstsein | Ja | |
| Ausbildung | Einstiegsniveau | Umfassend |
| Design und Architektur | Gelegentlich | Ja |
| Codierungsstandard | Das absolute Minimum | Ja |
| Überprüfung des sicheren Codes | Das absolute Minimum | Ja |
| Checkliste für Peer-Reviews | Das absolute Minimum | Ja |
| Unit-Tests | Gelegentlich | Ja |
| Integrationstests | Gelegentlich | Ja |
| Penetrationstests | Das absolute Minimum | Ja |
| Werkzeugunterstützung | Das absolute Minimum | Ja |
| Sichere Lieferkette | Gelegentlich | Ja |

Wir empfehlen jedem, der einen Anwendungssicherheitsstandard übernehmen möchte, den [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) in seiner konzipierten Form zu verwenden überprüfbar und getestet sein und in allen Teilen eines sicheren Entwicklungslebenszyklus verwendet werden können.

Für Werkzeuganbieter ist das ASVS die einzig akzeptable Wahl. Tools können die OWASP Top 10 aufgrund der Art mehrerer der OWASP Top 10 Risiken nicht umfassend erkennen, testen oder schützen, unter Bezugnahme auf A04:2021 – Unsicheres Design. OWASP rät von jeglichen Behauptungen über eine vollständige Berichterstattung über die OWASP Top 10 ab, da diese schlichtweg unwahr sind.
