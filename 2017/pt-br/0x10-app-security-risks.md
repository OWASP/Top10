# Risco - Riscos de Segurança de Aplicações

##  O Que São os Riscos de Segurança de Aplicações?

Os atacantes podem usar potencialmente muitos caminhos diferentes através da sua aplicação para afetar o seu negócio ou organização. Cada um destes caminhos representa um risco que pode, ou não, ser suficientemente sério para requerer atenção.

![App Security Risks](images/0x10-risk-1.png)

Por vezes, estes caminhos são triviais de encontrar e explorar, por outras são extremamente difíceis. De forma semelhante, o dano causado pode não ter consequências, ou pode destruir o seu negócio. Para determinar o risco para a sua organização, você pode avaliar a probabilidade associada com cada agente de ameaça, vetor de ataque, e vulnerabilidades de segurança e combiná-las com a estimativa do impacto técnico e de negócio na organização.  Em conjunto, estes fatores determinam o risco global.

## Qual o meu Risco

The [OWASP Top 10](https://www.owasp.org/index.php/Top10) focuses on identifying the most serious risks for a broad array of organizations. For each of these risks, we provide generic information about likelihood and technical impact using the following simple ratings scheme, which is based on the OWASP Risk Rating Methodology.  

| Agentes de Ameaça | Explorabilidade | Prevalência da Vulnerabilidade | Detectabilidade da Vulnerabilidade | Impactos Técnicos | Impactos de Negócio |
| -- | -- | -- | -- | -- | -- |
| Específico da Aplicação | Fácil 3 | Generalizada 3 | Fácil 3 | Severo 3 | Específicos da Aplicação/Negócio |
| Específico da Aplicação | Médio 2 | Comum 2 | Médio 2 | Moderado 2 | Específicos da Aplicação/Negócio |
| Específico da Aplicação | Difícil 1 | Pouco Comum 1 | Difícil 1 | Menor 1 | Específicos da Aplicação/Negócio |

In this edition, we have updated the risk rating system to assist in calculating the likelihood and impact of any given risk. For more details, please see [Note About Risks](0xc0-note-about-risks.md). 

Each organization is unique, and so are the threat actors for that organization, their goals, and the impact of any breach. If a public interest organization uses a content management system (CMS) for public information and a health system uses that same exact CMS for sensitive health records, the threat actors and business impacts can be very different for the same software. It is critical to understand the risk to your organization based on applicable threat agents and business impacts.

Where possible, the names of the risks in the Top 10 are aligned with [Common Weakness Enumeration](https://cwe.mitre.org/) (CWE) weaknesses to promote generally accepted security practices and to reduce confusion

## References

### OWASP

* [OWASP Risk Rating Methodology](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Article on Threat/Risk Modeling](https://www.owasp.org/index.php/Threat_Risk_Modeling)

### External

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
