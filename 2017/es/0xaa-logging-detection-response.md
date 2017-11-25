# A10:2017 Deficiencia de Registros, Detección y Respuesta Activa

| Agentes de amenaza/Vectores de Ataque | Vulnerabilidad de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de Acceso \| Explotabilidad 2 | Prevalencia 3 \| Detección 1 | Técnico 2 \| Negocio |
| La explotación de la monitorización y deficiencia de registros es la base de casi todos los incidentes importantes. Los atacantes dependen de la falta de: monitorización y de la respuesta oportuna para conseguir sus objetivos sin ser detectados. | Éste inconveniente está incluido en el Top 10 basado en una [encuesta de la industria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Una estrategia pata determinar si usted tiene un monitoreo suficiente es examinar sus registros seguido del test de penetración. Las acciones de los evaluadores deben registrarse lo suficiente para entender qué daños pueden haber sido infligidos. | La mayoría de los ataques que tienen éxito, empiezan con la exploración de una vulnerabilidad. El efecto de permitir que ésta exploración continúe puede elevar la probabilidad de éxito de la explotación a casi el 100%. |

## ¿Soy vulnerable?

La deficiencia de registros, detección, monitorización y respuesta activa ocurre en cualquier instante:

* Eventos auditables, tales como los inicios de sesión, fallos en el inicio de sesión, y transacciones de alta importancia no son registrados.
* Los registros de las aplicaciones y API, no son monitorizados en busca de actividad sospechosa.
* Los umbrales de alerta y de escalamiento de respuesta según el riesgo de la información almacenada por la aplicación no están implementados o no son eficaces.

Para grandes organizaciones y de alto rendimiento, la falta de respuesta activa como: las actividades de respuesta y alerta en tiempo real, el bloqueo de ataques automatizados en aplicaciones web y en particular en las API, colocarían a la organización en un proceso de riesgo de compromiso prolongado. La respuesta no necesariamente debe ser visible para el atacante, únicamente la aplicación y la infraestructura asociada a ella, los frameworks, las capas de servicio, etc. pueden detectar y alertar a los seres humanos o herramientas para responder casi en tiempo real.

## ¿Cómo prevenirlo?

Según el riesgo de la información almacenada o procesada por la aplicación:

* Asegúrese que todos los inicios de sesión, fallas de control de acceso, las fallas en la validación de campos de entrada pueden ser registrados con el contexto de usuario suficiente para identificar cuentas sospechosas o maliciosas, y que se almacenen durante el tiempo suficiente para permitir el análisis forense retrasado.
* Asegúrese de que las transacciones de alto impacto tengan una pista de auditoría con controles de integridad para prevenir alteraciones o eliminaciones, tales como añadir únicamente tablas de bases de datos o similares.
* Establezca una monitorización y alerta efectivos de tal manera que las actividades sospechosas sean detectadas y respondidas dentro de periodos de tiempo aceptables.
* Establezca o adopte un plan de respuesta o recuperación de incidentes, tales como [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) o posterior.

Existen frameworks de protección de aplicaciones comerciales y de código abierto tales como [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), firewalls de aplicaciones web como [mod_security con OWASP Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), y software de correlación de registros como [ELK](https://www.elastic.co/products) con paneles personalizados y alertas. Los test de penetración y los escaneos realizados por herramientas DAST (como OWASP ZAP) deben siempre accionar alertas.

## Ejemplo de Escenarios de Ataque

**Escenario 1**: El software de un foro de código abierto es operado por un pequeño equipo que fue hackeado utilizando una falla de seguridad en su software. Los atacantes lograron eliminar el repositorio del código fuente interno que contiene la próxima versión, y todos los contenidos del foro. Aunque el código fuente pueda ser recuperado, la falta de monitorización, registro y alerta condujo a una brecha de seguridad aún peor. El proyecto de software de éste foro ya no está activo debido a éste problema.

**Escenario 2**: Un atacante escanea usuarios utilizando la contraseña por defecto. Él puede tomar el control de todas las cuentas utilizando ésta contraseña. Para todos los demás usuarios, éste proceso deja únicamente 1 solo fallo de inicio de sesión. Luego de algunos días, esto puede repetirse con una contraseña distinta.

**Escenario 3**: De acuerdo a reportes, un importante minorista de los Estados Unidos tenía un sandbox de análisis de malware interno analizando archivos adjuntos. El sandbox había detectado software potencialmente indeseable, pero nadie respondió a esta detección. El sandbox había estado generando advertencias por algún tiempo antes de que la brecha de seguridad fue detectada debido a transacciones de tarjeta fraudulentas por un banco externo.

## Referencias

### OWASP

* [OWASP Controles Proactivos - Implementar Registros y Detección de Intrusos](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Estándar de Verificación de Seguridad en Aplicaciones - V7 Registro y Monitorización](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Guía de Pruebas - Prueba de Error de Código Detallado](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Hoja de Trucos - Registros](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### Externas

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
