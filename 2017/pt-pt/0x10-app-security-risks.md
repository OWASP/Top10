# Risco - Riscos de Segurança Aplicacional

## O que são os riscos de Segurança Aplicacional?

Os atacantes podem usar potencialmente muitos caminhos diferentes através da sua aplicação para afectar o seu negócio ou organização. Cada um destes caminhos representa um risco que pode, ou não, ser suficientemente sério para requerer atenção.

![App Security Risks][image-1]

Por vezes, estes caminhos são triviais de encontrar e explorar e por outras são extremamente difíceis. De forma semelhante, o dano causado pode não ter consequências, ou pode destruir o seu negócio. Para determinar o risco para a sua organização, pode avaliar a probabilidade associada com cada agente de ameaça, vector de ataque, e fraquezas de segurança e combiná-las com a estimativa do impacto técnico e de negócio na organização.  Em conjunto, estes factores determinam o risco global.

## Qual o meu Risco

O [Top 10 da OWASP][1] faca-se na identificação dos riscos mais sérios para um conjunto alargado de organizações. Para cada um desses riscos, oferecemos informação genérica sobre a probabilidade e impacto técnico usando o seguinte esquema de classificação simples, baseado na Metodologia de Classificação de Risco da OWASP.  

| Agentes de Ameaça | Exploração | Prevalência das Fraquezas | Detecção das Fraquezas | Impactos Técnicos | Impactos de Negócio |
| -- | -- | -- | -- | -- | -- |
| Específico da Aplicação | Fácil 3 | Generalizada 3 | Fácil 3 | Sevara 3 | Específica da Aplicação/Negócio |
| Específico da Aplicação | Médio 2 | Comum 2 | Médio 2 | Moderado 2 | Específica da Aplicação/Negócio |
| Específico da Aplicação | Difícil 1 | Pouco comum 1 | Difícil 1 | Menor 1 | Específica da Aplicação/Negócio |

Nesta edição, alteramos o sistema de classificação de riscos, quando comparado com as edições anteriores, para ajudar com a nossa classificação de probabilidades e impactos. Este não é um problema para este documento, mas fica claro na análise publica dos dados (ver '+R').

Cada organização é única, assim como os actores de ameaça para cada organização, os seus objectivos, e o impacto de cada falha. Se uma organização de interesse público usa um software CMS para informações públicas e um sistema de saúde usa esse mesmo CMS para registos de saúde sensíveis, os atores de ameaça e os impactos de negócios são muito diferentes para o mesmo software. É fundamental que aplique os seus agentes de ameaças específicos e impactos de negócio com base na criatividade de ativos de dados.

Quando possível, os nomes dos riscos no Top 10 do OWASP estão alinhados com as fraquezas CWE para promover práticas de segurança comumente aceites e para reduzir a confusão. 

## Referências

### OWASP

* [OWASP Risk Rating Methodology][2]
* [Article on Threat/Risk Modeling][3]

### Externas

* [ISO 31000: Risk Management Std][4]
* [ISO 27001: ISMS][5]
* [NIST Cyber Framework (US)][6]
* [ASD Strategic Mitigations (AU)][7]
* [NIST CVSS 3.0][8]
* [Microsoft Threat Modelling Tool][9]

[1]:	https://www.owasp.org/index.php/Top10
[2]:	https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology
[3]:	https://www.owasp.org/index.php/Threat_Risk_Modeling
[4]:	https://www.iso.org/iso-31000-risk-management.html
[5]:	https://www.iso.org/isoiec-27001-information-security.html
[6]:	https://www.nist.gov/cyberframework
[7]:	https://www.asd.gov.au/infosec/mitigationstrategies.htm
[8]:	https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
[9]:	https://www.microsoft.com/en-us/download/details.aspx?id=49168

[image-1]:	images/0x10-risk-1.png