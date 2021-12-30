# Cómo utilizar OWASP Top 10 como un estándar

El OWASP Top 10 es principalmente un documento de concientización. Sin embargo, esto no ha impedido que las organizaciones lo utilicen como estándar de facto de la industria AppSec desde su creación en 2003. Si desea utilizar OWASP Top 10 como un estándar de codificación o prueba, sepa que es lo mínimo y apenas un punto de partida.

Una de las dificultades de utilizar OWASP Top 10 como estándar es que documentamos riesgos de appsec y no necesariamente problemas fácilmente comprobables.
Por ejemplo, A04: 2021-Diseño inseguro está más allá del alcance de la mayoría de las formas de prueba. Otro ejemplo son las pruebas en el lugar, en uso, y el registro y el monitoreo efectivos solo se pueden realizar con entrevistas y solicitando un muestreo de respuestas efectivas a incidentes. Una herramienta de análisis de código estático puede buscar la ausencia de registro, pero puede ser imposible determinar si la lógica de negocios o el control de acceso están registrando brechas de seguridad críticas. Los testers de penetración solo pueden determinar que han invocado la respuesta a incidentes en un entorno de prueba, el cual rara vez se monitorea de la misma manera que en un entorno de producción.

Aquí están nuestras recomendaciones sobre cuándo es apropiado utilizar OWASP Top 10:

| Caso de uso                                 | OWASP Top 10 2021   | Estándar de verificación de seguridad de aplicaciones OWASP |
|---------------------------------------------|:-------------------:|:-----------------------------------------------------------:|
| Conocimiento                                | Sí                  |                                                             |
| Capacitación                                | Nivel Básico        | Exhaustivo                                                  |
| Diseño y arquitectura                       | Ocasionalmente      | Sí                                                          |
| Estándar de codificación                    | Mínimo              | Sí                                                          |
| Revisión de código seguro                   | Mínimo              | Sí                                                          |
| Lista de verificación de revisión por pares | Mínimo              | Sí                                                          |
| Pruebas de Unidad                           | Ocasionalmente      | Sí                                                          |
| Pruebas de integración                      | Ocasionalmente      | Sí                                                          |
| Pruebas de penetración                      | Mínimo              | Sí                                                          |
| Soporte de herramientas                     | Mínimo              | Sí                                                          |
| Cadena de suministro segura                 | Ocasionalmente      | Sí                                                          |

Alentamos a cualquiera que desee adoptar un estándar de seguridad de aplicaciones a usar el [Estándar de verificación de seguridad de aplicaciones](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) de OWASP, ya que está diseñado para ser verificable y testeado, y puede usarse en todas las partes del ciclo de vida de desarrollo seguro.

El ASVS es la única opción aceptable para los proveedores de herramientas. Las herramientas no pueden detectar, probar o proteger de manera integral contra el OWASP Top 10 debido a la naturaleza de varios de los riesgos OWASP Top 10, con referencia a A04: 2021-Diseño Inseguro. OWASP desaconseja cualquier afirmación pretensiosa de cobertura completa de OWASP Top 10, porque simplemente no es cierto.
