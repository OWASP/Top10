# Risco - Riscos Segurança Aplicacional

## O que são Riscos de Segurança Aplicacional?

Os atacantes podem potencialmente usar muitos caminhos diferentes através da sua
aplicação para afetar o seu negócio ou organização. Cada um destes caminhos
representa um risco que pode, ou não, ser suficientemente sério para requerer
atenção.

![App Security Risks][0x101]

Por vezes estes caminhos são triviais de encontrar e abusar mas outras vezes são
extremamente difíceis. De forma semelhante, o dano causado pode não ter
consequências, ou pode destruir o seu negócio. Para determinar o risco para a
sua organização, pode avaliar a probabilidade associada com cada agente de
ameaça, vetor de ataque e falhas de segurança, combinando-os com a estimativa do
impacto técnico e de negócio na organização. Em conjunto, estes fatores
determinam o risco global.

## Qual é o _meu_ Risco

O [Top 10 da OWASP][0x102] foca-se na identificação dos riscos mais sérios para
um conjunto alargado de organizações. Para cada um desses riscos, oferecemos
informação genérica sobre a probabilidade de ocorrência e impacto técnico usando
o seguinte esquema de classificação simples, baseado na [Metodologia de
Classificação de Risco da OWASP][0x103].

| Agente Ameaça | Abuso | Prevalência da Falha | Detetabilidade | Impacto Técnico | Impacto Negócio 
| :-: | :-: | :-: | :-: | :-: | :-: |
| Específico da Aplicação | Fácil: 3 | Predominante: 3 | Fácil: 3 | Grave: 3 | Específico do Negócio|
| Específico da Aplicação | Moderado: 2 | Comum: 2 | Moderado 2 | Moderado: 2 | Específico do Negócio |
| Específico da Aplicação | Difícil: 1 | Incomum: 1 | Difícil: 1 | Reduzido 1 | Específico do Negócio |

Nesta edição do Top 10 atualizámos o sistema de classificação de risco por forma
a ser considerado no cálculo da probabilidade e impacto associado a cada risco.
Para mais detalhes, por favor leia as [Notas Sobre Os Riscos][0x104].

Cada organização é única, assim como os atores de ameaça para cada organização,
os seus objetivos e o impacto de cada falha. Se uma organização de interesse
público usa um software CMS - Content Management System para informações
públicas e um sistema de saúde usa esse mesmo CMS para registos de saúde
sensíveis, os atores de ameaça e os impactos de negócios são muito diferentes
para o mesmo software. É fundamental compreender o risco para a sua organização
com base não só nos agentes de ameaças específicos mas também no impacto para o
negócio.

Sempre que possível, os nomes dos riscos no Top 10 da OWASP estão alinhados com
a [CWE - Common Weakness Enumeration][0x105] por forma a promover uma
nomenclatura consensual e reduzir possível confusão.

## Referências

### OWASP

* [OWASP Risk Rating Methodology][0x106]
* [Artigo sobre Threat/Risk Modeling][0x107]

### Externas

* [ISO 31000: Risk Management Std][0x108]
* [ISO 27001: ISMS][0x109]
* [NIST Cyber Framework (US)][0x1010]
* [ASD Strategic Mitigations (AU)][0x1011]
* [NIST CVSS 3.0][0x1012]
* [Microsoft Threat Modelling Tool][0x1013]

[0x101]: images/0x10-risk-1.png
[0x102]: https://owasp.org/www-project-top-ten/
[0x103]: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
[0x104]: ./0xc0-note-about-risks.md
[0x105]: https://cwe.mitre.org/
[0x106]: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
[0x107]: https://owasp.org/www-community/Threat_Modeling
[0x108]: https://www.iso.org/iso-31000-risk-management.html
[0x109]: https://www.iso.org/isoiec-27001-information-security.html
[0x1010]: https://www.nist.gov/cyberframework
[0x1011]: https://www.asd.gov.au/infosec/mitigationstrategies.htm
[0x1012]: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
[0x1013]: https://www.microsoft.com/en-us/download/details.aspx?id=49168

