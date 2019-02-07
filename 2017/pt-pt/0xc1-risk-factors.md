# +RF Detalhes sobre os Fatores de Risco

## Resumo dos Riscos do Top 10

A tabela seguinte apresenta um resumo do Top 10 de Riscos de Segurança
Aplicacional de 2017 e o fator de risco que lhes foram atribuídos.
Estes fatores foram determinados com base nas estatísticas disponíveis e na
experiência da equipa do OWASP Top 10. Para compreender estes riscos para uma
aplicação ou organização específica, deve considerar os agentes de ameaça e
impactos no negócio específicos para essa aplicação/organização. Até mesmo
fraquezas de segurança graves podem não apresentar um risco sério se não
existirem agentes de ameaça numa posição em que possam realizar um ataque ou se
o impacto no negócio for negligenciável para os ativos envolvidos.

![Risk Factor Table][image-1]

## Riscos adicionais a considerar

O Top 10 é bastante abrangente, mas existem muitos outros riscos a considerar e
avaliar na sua organização. Alguns destes apareceram em versões anteriores do
Top 10, e outros não, incluindo novas técnicas de ataque que estão a ser
identificadas a toda a hora. Outros riscos de segurança aplicacionais (ordenados
por CWE-ID) que devem ser considerados, incluem:

* [CWE-352: Cross-Site Request Forgery (CSRF)][1]
* [CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion',
  'AppDoS')][2]
* [CWE-434: Unrestricted Upload of File with Dangerous Type][3]
* [CWE-451: User Interface (UI) Misrepresentation of Critical Information
  (Clickjacking and others)][4]
* [CWE-601: Unvalidated Forward and Redirects][5]
* [CWE-799: Improper Control of Interaction Frequency (Anti-Automation)][6]
* [CWE-829: Inclusion of Functionality from Untrusted Control Sphere (3rd Party
  Content)][7]
* [CWE-918: Server-Side Request Forgery (SSRF)][8]

[image-1]: images/0xc1-risk-factor-table.png

[1]: https://cwe.mitre.org/data/definitions/352.html
[2]: https://cwe.mitre.org/data/definitions/400.html
[3]: https://cwe.mitre.org/data/definitions/434.html
[4]: https://cwe.mitre.org/data/definitions/451.html
[5]: https://cwe.mitre.org/data/definitions/601.html
[6]: https://cwe.mitre.org/data/definitions/799.html
[7]: https://cwe.mitre.org/data/definitions/829.html
[8]: https://cwe.mitre.org/data/definitions/918.html

