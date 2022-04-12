# Cómo utilizar OWASP Top 10 como estándar

El OWASP Top 10 es principalmente un documento de concientización. Sin embargo, esto no ha impedido que organizaciones lo utilicen como estándar de facto de la industria AppSec desde su creación en 2003. Si desea utilizar OWASP Top 10 como un estándar de codificación o pruebas, sepa que es lo mínimo y sólo un punto de partida.

Una de las dificultades de utilizar el OWASP Top 10 como estándar es que documentamos riesgos de AppSec y no necesariamente problemas fácilmente comprobables.
Por ejemplo, A04:2021-Diseño Inseguro está más allá del alcance de la mayoría de las formas de prueba. Otro ejemplo son las pruebas en el lugar y en uso del registro y monitoreo efectivos. Sólo se pueden realizar a través de entrevistas y solicitando un muestreo de respuestas efectivas a incidentes. Una herramienta de análisis estático de código puede detectar la ausencia de registro, pero puede ser imposible determinar si se registran correctamente brechas de seguridad críticas en la lógica de negocio o en el control de acceso. Los testers de penetración sólo pueden determinar que han invocado la respuesta a incidentes en un entorno de prueba, el cual rara vez se monitorea de la misma manera que en un entorno de producción.

Estas son nuestras recomendaciones sobre cuándo es apropiado utilizar el OWASP Top 10:

| Caso de uso                                   | OWASP Top 10 2021   | Estándar de Verificación de Seguridad en Aplicaciones de OWASP (ASVS) |
|-----------------------------------------------|:-------------------:|:---------------------------------------------------------------------:|
| Concientización                               | Sí                  |                                                                       |
| Capacitación                                  | Nivel Introductorio |                               Completo                                |
| Diseño y arquitectura                         | Ocasionalmente      |                                  Sí                                   |
| Estándar de codificación                      | Apenas Mínimo       |                                  Sí                                   |
| Revisión de código seguro                     | Apenas Mínimo       |                                  Sí                                   |
| Lista verificación para la revisión por pares | Apenas Mínimo       |                                  Sí                                   |
| Pruebas unitarias                             | Ocasionalmente      |                                  Sí                                   |
| Pruebas de integración                        | Ocasionalmente      |                                  Sí                                   |
| Pruebas de penetración                        | Apenas Mínimo       |                                  Sí                                   |
| Soporte de herramientas                       | Apenas Mínimo       |                                  Sí                                   |
| Cadena de suministro segura                   | Ocasionalmente      |                                  Sí                                   |

Alentamos a cualquiera que desee adoptar un estándar de seguridad de aplicaciones a usar el [Estándar de Verificación de Seguridad de Aplicaciones](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) de OWASP, ya que fue diseñado para ser verificable, testeble, y puede usarse en todas las etapas de un ciclo de desarrollo seguro.

El ASVS es la única opción aceptable para los proveedores de herramientas. Las herramientas no pueden detectar, probar o proteger de manera integral contra los riesgos descriptos en OWASP Top 10, tomando como referencia el A04:2021-Diseño Inseguro. OWASP disuade el uso cualquier afirmación pretensiosa de cobertura completa del OWASP Top 10, porque simplemente no es cierto.
