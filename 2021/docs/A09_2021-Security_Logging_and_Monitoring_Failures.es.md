# A09:2021 – Fallos de monitoreo y registros de seguridad    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Exploit ponderado prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Resumen

Monitoreo y registro de seguridad provienen de la encuesta de la comunidad TOP 10, subió levemente desde la décima posición en el OWASP Top 10 2017. El registro y monitoreo pueden ser desafiantes para ser testeados, a menudo implica entrevistas o preguntas si los ataques fueron detectados durante una prueba de penetración. No hay muchos datos CVE para esta categoría, pero detectar y responder a las brechas es crítico. Aun así, puede tener un gran impacto para la responsabilidad, visibilidad, alertas de incidentes y forense. Esta categoría se expande más allá de *CWE-117 Neutralización de salida incorrecta para registros*, *CWE-223 Omisión de información relevante para la seguridad*, y
*CWE-532 Inserción de información sensible en el archivo de registro*.

## Descripción

Volviendo al OWASP Top 10 2021, la intención es detectar, escalar y responder ante brechas activas. Sin registros y monitoreo, las brechas no pueden ser detectadas. Registros, detecciones, monitoreo y respuestas activas insuficientes pueden ocurrir en cualquier momento:

-   Eventos auditables, tales como los inicios de sesión, fallas en el inicio de sesión y transacciones de alto valor, no son registradas.

-   Advertencias y errores generan registros poco claros, inadecuados y en algunos casos ni se generan.

-   Registros en aplicaciones y API no son monitoreados para detectar actividades sospechosas.

-   Los registros son únicamente almacenados en forma local..

-   Los umbrales de alerta y procesos de escalamiento no están correctamente implementados o no son efectivos.

-   Las pruebas de penetración y los escaneos utilizando herramientas de pruebas dinámicas de seguridad en aplicaciones (como ser OWASP ZAP) no generan alertas.

-   Las aplicaciones no logran detectar, escalar, o alertar sobre ataques activos en tiempo real ni cercanos al tiempo real.

Se es vulnerable a la fuga de información haciendo registros y eventos de alertas que sean visibles para un usuario o un atacante (see [A01:2021-Pérdida de control de acceso](A01_2021-Broken_Access_Control.es.md)).

## Como se previene

Los desarrolladores deberían implementar algunos o todos los siguientes controles, dependiendo del riesgo de la aplicación:

-   Asegúrese de que todos los errores de inicio de sesión, de control de acceso y de validación de entradas de datos del lado del servidor se pueden registrar con suficiente  contexto como para identificar cuentas sospechosas o maliciosas y mantenerlo durante el tiempo suficiente para
permitir un posterior análisis forense.

-   Asegúrese de que los registros se generen en un formato fácil de procesar por las herramientas de gestión de registros.

-   Asegúrese de que los datos de registros estén codificados correctamente para prevenir inyecciones o ataques en el sistema de monitoreo o registros.

-   Asegúrese de que las transacciones de alto valor poseen una traza de auditoria con controles de integridad para evitar la modificación o el borrado, tales como permitir únicamente la inserción en las tablas de base de datos o similares.

-   El equipo de DevSecOps debe establecer alertas y monitoreo efectivo tal que se detecte actividades sospechosas y responderlas rápidamente.

-   Establecer o adoptar un plan de respuesta y recuperación, tal como NIST 800-61r2 o posterior.

Existen frameworks de protección de aplicaciones comerciales y de código abierto, tales como el conjunto de reglas de ModSecurity de OWASP y el conjunto de programas de correlación de registros de código abierto como ser ELK (Elasticsearch, Logstash, Kibana) con paneles personalizados y alertas

## Ejemplos de escenarios de ataque

**Escenario #1:** Un operador de salud que provea un plan de salud para niños no pudieron detectar una brecha debido a la falta de monitoreo y registro. Alguien externo informo al proveedor de salud que un atacante había accedido y modificados miles de registros médicos sensibles de mas de 3.5 millones de niños. Una revisión post incidente encontró que los desarrolladores del sitio web no habían encontrado vulnerabilidades significativas. Como no hubo ni registro ni monitores del sistema, la brecha de datos pudo haber estado en proceso desde el 2013, un periodo de mas de 7 años.

**Escenario #2:** Una gran aerolínea India tuvo una brecha de seguridad que involucro a la perdida de datos personales de millones de pasajeros por mas de 10 años, incluyendo pasaportes y tarjetas de crédito. La brecha se produjo por un proveedor de servicios de almacenamiento en la nube, quien notifico a la aerolínea después de un cierto tiempo.

**Escenario #3:** Una gran aerolínea Europea sufrió un incumplimiento de la GRPD. Se reporta que la causa de la brecha se debió a que un atacante exploto una vulnerabilidad en una aplicación de pago, obteniendo mas de 400,000 registros de pagos de usuarios. La aerolínea fue multada con 20 millones de libras como resultado del regulador de privacidad.

## Referencias

-   [Controles proactivos de OWASP: Implementar registros de seguridad y monitoreo](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [Estándar de verificación de seguridad de aplicaciones de OWASP: V8 Registro y monitoreo](https://owasp.org/www-project-application-security-verification-standard)

-   [Guía de prueba de OWASP: Prueba de código de error detallado](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [Hoja de referencia de OWASP:Vocabulario de registro de aplicaciones](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [Hoja de referencia de OWASP:Registros](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html))   

-   [Integridad de datos: Recuperación de ransomware y otros eventos destructivos](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Integridad de datos: Identificación y protección de activos contra ransomware y otros eventos destructivos](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Integridad de datos: Detección y respuesta al ransomware y otros eventos destructivos](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Lista de CWEs mapeadas

[CWE-117 Neutralización de salida incorrecta para registros](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omision de información relevante para la seguridad](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Inserción de información sensible en el archivo de registros](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Registro insuficiente](https://cwe.mitre.org/data/definitions/778.html)