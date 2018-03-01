# Risco - Riscos de Segurança Aplicacional

## O que são os riscos de Segurança Aplicacional?

Os atacantes podem potencialmente usar muitos caminhos diferentes através da sua
aplicação para afectar o seu negócio ou organização. Cada um destes caminhos
representa um risco que pode, ou não, ser suficientemente sério para requerer
atenção.

![App Security Risks][image-1]

Por vezes estes caminhos são triviais de encontrar e explorar mas por outras são
extremamente difíceis. De forma semelhante, o dano causado pode não ter
consequências, ou pode destruir o seu negócio. Para determinar o risco para a
sua organização, pode avaliar a probabilidade associada com cada agente de
ameaça, vetor de ataque e falhas de segurança, combinando-os com a estimativa
do impacto técnico e de negócio na organização. Em conjunto, estes fatores
determinam o risco global.

## Qual é o meu Risco

O [Top 10 da OWASP][1] foca-se na identificação dos riscos mais sérios para um
conjunto alargado de organizações. Para cada um desses riscos, oferecemos
informação genérica sobre a probabilidade e impacto técnico usando o seguinte
esquema de classificação simples, baseado na Metodologia de Classificação de
Risco da OWASP.

| Agentes de Ameaça | Complexidade do Abuso | Prevalência da Falha | Detecção da Falha | Impactos Técnicos | Impactos de Negócio |
| :-: | :-: | :-: | :-: | :-: | :-: |
| Específico da Aplicação | Fácil 3 | Generalizada 3 | Fácil 3 | Sevara 3 | Específica da Aplicação/Negócio |
| Específico da Aplicação | Médio 2 | Comum 2 | Médio 2 | Moderado 2 | Específica da Aplicação/Negócio |
| Específico da Aplicação | Difícil 1 | Pouco comum 1 | Difícil 1 | Menor 1 | Específica da Aplicação/Negócio |

Neste edição do Top 10 atualizámos o sistema de classificação de risco por forma
a ser considerado no calculo da probabilidade e impacto associado a cada risco.
Para mais detalhes, por favor leia as [Notas sobre Riscos][2].

Cada organização é única, assim como os atores de ameaça para cada organização,
os seus objectivos e o impacto de cada falha. Se uma organização de interesse
público usa um software CMS - Content Management System para informações
públicas e um sistema de saúde usa esse mesmo CMS para registos de saúde
sensíveis, os atores de ameaça e os impactos de negócios são muito diferentes
para o mesmo software. É fundamental compreender o risco para a sua organização
com base não só nos agentes de ameaças específicos mas também no impacto para o
negócio.

Sempre que possível, os nomes dos riscos no Top 10 da OWASP estão alinhados com
a [CWE - Common Weakness Enumeration][3] por forma a promover uma nomenclatura
consensual e reduzir possível confusão.

## Referências

### OWASP

* [OWASP Risk Rating Methodology][4]
* [Artigo sobre Threat/Risk Modeling][5]

### Externas

* [ISO 31000: Risk Management Std][6]
* [ISO 27001: ISMS][7]
* [NIST Cyber Framework (US)][8]
* [ASD Strategic Mitigations (AU)][9]
* [NIST CVSS 3.0][10]
* [Microsoft Threat Modelling Tool][11]

[1]: https://www.owasp.org/index.php/Top10
[2]: 0xc0-note-about-risks.md
[3]: https://cwe.mitre.org/ 
[4]: https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology
[5]: https://www.owasp.org/index.php/Threat_Risk_Modeling
[6]: https://www.iso.org/iso-31000-risk-management.html
[7]: https://www.iso.org/isoiec-27001-information-security.html
[8]: https://www.nist.gov/cyberframework
[9]: https://www.asd.gov.au/infosec/mitigationstrategies.htm
[10]: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
[11]: https://www.microsoft.com/en-us/download/details.aspx?id=49168

[image-1]: images/0x10-risk-1.png

