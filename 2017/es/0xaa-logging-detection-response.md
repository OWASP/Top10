# A10:2017 Registro y Monitoreo Insuficientes

| Agentes de Amenazas/Vectores de Ataque | Debilidades de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de Acceso : Exploitabilidad 2 | Prevalencia 3 : Detectabilidad 1 | Técnico 2 : Negocio |
| El registro y monitoreo insuficientes es la base de casi todos los mayores incidentes. Los atacantes dependen de la falta de monitoreo y respuesta oportuna para lograr sus objetivos sin ser detectados. |  Este punto se incluye en el Top 10 basado en una [encuesta a la industria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Una estrategia para determinar si usted no posee suficiente monitoreo es examinar los registros después de las pruebas de penetración. Las acciones de los evaluadores deben registrarse suficientemente para comprender los daños que pueden haber causado. | Los ataques más exitosos comienzan con la exploración de vulnerabilidades. Permitir que el sondeo de vulnerabilidades continúe puede aumentar la probabilidad de una explotación exitosa a casi el 100%. En 2016, la identificación de una brecha tardó una [media de 191 días](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) - este tiempo es mas que suficiente para infligir daño. |

## ¿La aplicación es vulnerable?

Registro y monitoreo insuficientes ocurre en cualquier instante:

* Eventos auditables, tales como los inicios de sesión, fallos en el inicio de sesión, y transacciones de alto valor no son registrados.
* Advertencias y errores generan registros poco claros, inadecuados o ninguno en absoluto.
* Registros en aplicaciones o APIs no son monitoreados por actividad sospechosa.
* Registros son almacenados únicamente de forma local.
* Los umbrales de alerta y de escalamiento de respuesta no están implementados o no son eficaces.
* Pruebas de penetración y escaneos utilizando herramientas [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) (tales como [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)) no generan alertas.
* La aplicación no logra detectar, escalar o alertar sobre ataques en tiempo real o cerca de estar en tiempo real.

También es vulnerable a la fuga de información si registra y alerta eventos visibles para un usuario o un atacante (consulte A3:2017 Exposición sensible a la información).

## ¿Como prevenirlo?

Según el riesgo de los datos almacenados o procesados por la aplicación:

* Asegúrese de que todos los errores de inicio de sesión, de control de acceso y de validación de entradas de dato del lado del servidor se pueden registrar con el contexto de usuario suficiente para identificar cuentas sospechosas o maliciosas, y mantenerlo durante el tiempo suficiente para permitir un eventual análisis forense.
* Asegúrese de que las transacciones de alto impacto tengan una pista de auditoría con controles de integridad para prevenir alteraciones o eliminaciones, tales como añadir únicamente tablas de bases de datos o similares.
* Asegúrese que todas las transacciones de alto valor poseen una traza de auditoría con controles de integridad que permitan detectar su modificación o borrado, tales como una base de datos con permisos únicamente de inserción u otro.
* Establezca una monitorización y alerta efectivos de tal manera que las actividades sospechosas sean detectadas y respondidas dentro de periodos de tiempo aceptables.
* Establezca o adopte un plan de respuesta o recuperación de incidentes, tales como [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) o posterior.

Existen frameworks de protección de aplicaciones comerciales y de código abierto tales como [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), firewalls de aplicaciones web como [ModSecurity utilizando el Core Rule Set de OWASP](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), y software de correlación de registros con paneles personalizados y alertas.

## Ejemplo de Escenarios de Ataque

**Escenario #1**: El software de un foro de código abierto es operado por un pequeño equipo que fue hackeado utilizando una falla de seguridad en su software. Los atacantes lograron eliminar el repositorio del código fuente interno que contiene la próxima versión, y todos los contenidos del foro. Aunque el código fuente pueda ser recuperado, la falta de monitorización, registro y alerta condujo a una brecha de seguridad aún peor. El proyecto de software de éste foro ya no está activo debido a éste problema.

**Escenario #2**: Un atacante escanea usuarios utilizando la contraseña por defecto, pudiendo tomar el control de todas las cuentas utilizando ésta contraseña. Para todos los demás usuarios, éste proceso deja únicamente 1 solo registro de fallo de inicio de sesión. Luego de algunos días, esto puede repetirse con una contraseña distinta.

**Escenario #3**: De acuerdo a reportes, un importante minorista de los Estados Unidos tenía un sandbox de análisis de malware interno para el análisis de archivos adjuntos de correos electrónicos. El sandbox había detectado software potencialmente indeseable, pero nadie respondió a esta detección. El sandbox había estado generando advertencias por algún tiempo antes de que la brecha de seguridad fuera detectada debido a transacciones de tarjeta fraudulentas por un banco externo.

## Referencias (en Inglés)

### OWASP

* [Controles Proactivos de OWASP: Implementar Registros y Detección de Intrusos](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V7 Registro y Monitorización](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Guía de Pruebas de OWASP: Prueba de Error de Código Detallado](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Hojas de ayuda de OWASP: Registros](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### Externas

* [CWE-223: Omisión de información relevante de seguridad](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Registro insuficiente](https://cwe.mitre.org/data/definitions/778.html)
