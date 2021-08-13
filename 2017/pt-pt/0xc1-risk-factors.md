# +RF Detalhes sobre os Fatores de Risco

## Resumo dos Riscos do Top 10

A tabela seguinte apresenta um resumo do Top 10 de Riscos de Segurança
Aplicacional de 2017 e o fator de risco que lhes foram atribuídos. Estes fatores
foram determinados com base nas estatísticas disponíveis e na experiência da
equipa do OWASP Top 10. Para compreender estes riscos para uma aplicação ou
organização específica, **deve considerar os agentes de ameaça e impactos no
negócio específicos para essa aplicação/organização**. Até mesmo falhas de
segurança graves podem não apresentar um risco sério se não existirem agentes de
ameaça numa posição em que possam realizar um ataque ou se o impacto no negócio
for negligenciável para os ativos envolvidos.

![Risk Factor Table][0xc11]

## Riscos adicionais a considerar

O Top 10 é bastante abrangente, mas existem muitos outros riscos a considerar e
avaliar na sua organização. Alguns destes apareceram em versões anteriores do
Top 10, e outros não, incluindo novas técnicas de ataque que estão a ser
identificadas a toda a hora. Outros riscos de segurança aplicacionais (ordenados
por CWE-ID) que devem ser considerados, incluem:

- [CWE-352: Cross-Site Request Forgery (CSRF)][0xc12]
- [CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion',
  'AppDoS')][0xc13]
- [CWE-434: Unrestricted Upload of File with Dangerous Type][0xc14]
- [CWE-451: User Interface (UI) Misrepresentation of Critical Information
  (Clickjacking and others)][0xc15]
- [CWE-601: Unvalidated Forward and Redirects][0xc16]
- [CWE-799: Improper Control of Interaction Frequency (Anti-Automation)][0xc17]
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere (3rd Party
  Content)][0xc18]
- [CWE-918: Server-Side Request Forgery (SSRF)][0xc19]

[0xc11]: images/0xc1-risk-factor-table.png
[0xc12]: https://cwe.mitre.org/data/definitions/352.html
[0xc13]: https://cwe.mitre.org/data/definitions/400.html
[0xc14]: https://cwe.mitre.org/data/definitions/434.html
[0xc15]: https://cwe.mitre.org/data/definitions/451.html
[0xc16]: https://cwe.mitre.org/data/definitions/601.html
[0xc17]: https://cwe.mitre.org/data/definitions/799.html
[0xc18]: https://cwe.mitre.org/data/definitions/829.html
[0xc19]: https://cwe.mitre.org/data/definitions/918.html

