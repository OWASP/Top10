# Riesgo - Riesgos de Seguridad en Aplicaciones

## Qué son los riesgos de seguridad en aplicaciones?

Los atacantes potencialmente pueden utilizar distintas rutas a través de su aplicación para perjudicar a su negocio u organización. Cada una de éstas rutas representa un riesgo que podría, o no, ser lo suficientemente grave para atraer su atención. 

![App Security Risks](images/0x10-risk-1.png)

A veces encontrar y explotar éstas rutas es trivial, y a veces es extremadamente difícil. De la misma manera, el perjuicio ocasionado puede no tener consecuencias, o puede dejarlo en la quiebra. A fin de determinar el riesgo para su organización, usted puede evaluar la probabilidad asociada a cada agente de amenaza, vector de ataque, y vulnerabilidad de seguridad y combinarlo con una estimación del impacto técnico y comercial para su organización. Éstos factores juntos determinan el riesgo global.

## Cuál es Mi Riesgo?

El [Top 10 de OWASP](https://www.owasp.org/index.php/Top10) se enfoca en identificar los riesgos más críticos para un amplio espectro de organizaciones. Para cada uno de éstos riesgos, proporcionamos información genérica sobre la probabilidad y el impacto técnico utilizando el siguiente esquema de evaluación, mismo que está basado en la Metodología de Evaluación de Riesgos de OWASP.

| Agente de Amenaza | Explotabilidad | Prevalencia de Vulnerabilidad | Detección de Vulnerabilidad | Impacto Técnico | Impacto de Negocio |
| -- | -- | -- | -- | -- | -- |
| Específico de la Applicación | Fácil | Difundido | Fácil | Severo | Específico de la Aplicación/Negocio |
| Específico de la Aplicación | Promedio | Común | Promedio | Moderado | Específico de la Aplicación/Negocio |
| Específico de la Aplicación | Difícil | Poco Común | Difícil | Mínimo | Específico de la Aplicación/Negocio |

En ésta edición hemos modificado el sistema de evaluación de riesgo en comparación con la versión anterior, para asistir nuestra evaluación de probabilidades e impactos. Esto no es un inconveniente dentro del documento pero está definido en el análisis público de datos.

Cada organización es única, y también lo son las amenazas asociadas a esa organización, sus objetivos, y el impacto de cualquier brecha. Si una organización de interés público utiliza un CMS para información pública y el sistema de salud utiliza el mismo CMS para datos sensibles, las amenazas y los impactos de negocio son muy distintos para el mismo software. Es crucial que ejecute sus agentes de amenazas personalizados y los impactos comerciales basados en la criticidad de los activos de datos.

En lo posible, los nombres de los riesgos en el Top 10 están alineados con las vulnerabilidades CWE para promover prácticas de seguridad generalmente aceptadas y disminuir la confusión.

## Referencias

### OWASP

* [Metodología de Evaluación de Riesgos de OWASP](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Artículo sobre Amenaza/Modelado del Riesgo](https://www.owasp.org/index.php/Threat_Risk_Modeling)

### Externas

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
