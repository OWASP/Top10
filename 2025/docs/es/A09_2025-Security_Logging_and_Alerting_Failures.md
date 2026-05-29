# A09:2025 Fallas en el Registro, Alerta y Monitoreo de Seguridad ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## Antecedentes

Las fallas en el Registro, Alerta y Monitoreo de Seguridad mantienen su posición en el puesto #9. Esta categoría tiene un ligero cambio de nombre para enfatizar la función de alerta necesaria para inducir la acción ante eventos de registro relevantes. Esta categoría siempre estará infrarrepresentada en los datos y, por tercera vez, fue votada en una posición de la lista por los participantes de la encuesta de la comunidad. Esta categoría es increíblemente difícil de probar y tiene una representación mínima en los datos de CVE/CVSS (solo 723 CVE); pero puede tener un gran impacto en la visibilidad, las alertas de incidentes y la informática forense. Esta categoría incluye problemas con el *manejo adecuado de la codificación de salida hacia los archivos de registro (CWE-117), la inserción de datos sensibles en los archivos de registro (CWE-532) y el registro insuficiente (CWE-778).*


## Tabla de puntuación


<table>
  <tr>
   <td>CWEs Mapeadas
   </td>
   <td>Tasa Máxima de Incidencia
   </td>
   <td>Tasa Promedio de Incidencia
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Promedio
   </td>
   <td>Promedio Ponderado de Explotación
   </td>
   <td>Promedio Ponderado de Impacto
   </td>
   <td>Ocurrencias Totales
   </td>
   <td>CVEs Totales
   </td>
  </tr>
  <tr>
   <td>5
   </td>
   <td>11.33%
   </td>
   <td>3.91%
   </td>
   <td>85.96%
   </td>
   <td>46.48%
   </td>
   <td>7.19
   </td>
   <td>2.65
   </td>
   <td>260,288
   </td>
   <td>723
   </td>
  </tr>
</table>



## Descripción

Sin registro (logging) y monitoreo (monitoring), los ataques y las brechas de seguridad no pueden detectarse, y sin alertas (alerting) es muy difícil responder de forma rápida y eficaz durante un incidente de seguridad. Las fallas por registro, monitoreo continuo, detección y alertas insuficientes para iniciar respuestas activas se producen siempre que:


* No se registran eventos auditables, como los inicios de sesión, las fallas de inicio de sesión y las transacciones de alto valor, o se registran de forma incoherente (por ejemplo, registrando solo los inicios de sesión correctos, pero no los intentos fallidos).
* Las advertencias y los errores no generan mensajes de registro, o estos son inadecuados o poco claros.
* La integridad de los registros no está debidamente protegida contra la manipulación.
* Los registros de las aplicaciones y las API no se monitorean para detectar actividades sospechosas.
* Los registros solo se almacenan localmente y no se dispone de las copias de seguridad adecuadas.
* No existen o no son efectivos los umbrales de alerta y los procesos de escalado de respuesta adecuados. Las alertas no se reciben o no se revisan en un tiempo razonable.
* Las pruebas de penetración (pentesting) y los escaneos mediante herramientas de pruebas de seguridad de aplicaciones dinámicas (DAST) (como Burp Suite o ZAP) no activan alertas.
* La aplicación no puede detectar, escalar o alertar sobre ataques activos en tiempo real o casi en tiempo real.
* Se es vulnerable a la filtración de información sensible al hacer visibles los eventos de registro y alerta para un usuario o un atacante (ver [A01:2025-Pérdida de Control de Acceso](A01_2025-Broken_Access_Control.md)), o al registrar información sensible que no debería registrarse (como PII o PHI).
* Se es vulnerable a inyecciones o ataques a los sistemas de registro o monitoreo si los datos de los registros no están correctamente codificados.
* La aplicación carece de errores u otras condiciones excepcionales, o los gestiona de forma inadecuada, de modo que el sistema no es consciente de que se ha producido un error y, por tanto, no puede registrar que ha habido un problema.
* Faltan "casos de uso" adecuados para la emisión de alertas o estos están desactualizados para reconocer una situación especial.
* Demasiadas alertas de falsos positivos hacen imposible distinguir las alertas importantes de las que no lo son, lo que provoca que se reconozcan demasiado tarde o no se reconozcan en absoluto (sobrecarga física del equipo del SOC).
* Las alertas detectadas no pueden procesarse correctamente porque el manual de procedimientos (playbook) para el caso de uso es incompleto, está desactualizado o no existe.


## Cómo prevenir

Los desarrolladores deben implementar algunos o todos los controles siguientes, dependiendo del riesgo de la aplicación:


* Asegurarse de que todas las fallas de inicio de sesión, control de acceso y validación de entradas del lado del servidor puedan registrarse con suficiente contexto de usuario para identificar cuentas sospechosas o maliciosas, y conservarse durante el tiempo suficiente para permitir un análisis forense retardado.
* Asegurarse de que se registre cada parte de la aplicación que contenga un control de seguridad, tanto si tiene éxito como si falla.
* Asegurarse de que los registros se generen en un formato que las soluciones de gestión de registros puedan consumir fácilmente.
* Asegurarse de que los datos de registro estén codificados correctamente para evitar inyecciones o ataques a los sistemas de registro o monitoreo.
* Asegurarse de que todas las transacciones tengan un rastro de auditoría con controles de integridad para evitar su manipulación o eliminación, como tablas de bases de datos de solo adición (append-only) o similares.
* Asegurarse de que todas las transacciones que arrojen un error se reviertan (roll back) y se inicien de nuevo. Fallar siempre de forma segura (fail closed).
* Si su aplicación o sus usuarios se comportan de forma sospechosa, emita una alerta. Elabore directrices para sus desarrolladores sobre este tema para que puedan programar en consecuencia o adquiera un sistema para ello.
* Los equipos de DevSecOps y de seguridad deben establecer casos de uso de monitoreo y alerta eficaces, incluidos manuales de procedimientos (playbooks), de modo que las actividades sospechosas sean detectadas y respondidas rápidamente por el equipo del Centro de Operaciones de Seguridad (SOC).
* Añada 'honeytokens' (tokens trampa) como trampas para atacantes en su aplicación; por ejemplo, en la base de datos, en los datos, como identidades de usuario reales y/o técnicas. Al no utilizarse en la actividad normal del negocio, cualquier acceso genera datos de registro que pueden activar una alerta casi sin falsos positivos.
* El análisis del comportamiento y el apoyo de la IA podrían ser, opcionalmente, una técnica adicional para ayudar a conseguir bajas tasas de falsos positivos en las alertas.
* Establecer o adoptar un plan de respuesta y recuperación de incidentes, como el del Instituto Nacional de Estándares y Tecnología (NIST) 800-61r2 o posterior. Enseñe a sus desarrolladores de software cómo son los ataques e incidentes en las aplicaciones para que puedan informarlos.

Existen productos comerciales y de código abierto para la protección de aplicaciones, como el OWASP ModSecurity Core Rule Set, y software de correlación de registros de código abierto, como el stack de Elasticsearch, Logstash, Kibana (ELK), que cuentan con cuadros de mando personalizados y alertas que pueden ayudarle a combatir estos problemas. También existen herramientas comerciales de observabilidad que pueden ayudarle a responder a los ataques o a bloquearlos casi en tiempo real.


## Ejemplos de escenarios de ataque

**Escenario #1:** El operador del sitio web de un proveedor de planes de salud infantil no pudo detectar una brecha de seguridad debido a la falta de monitoreo y registro. Un tercero informó al proveedor del plan de salud que un atacante había accedido y modificado miles de registros sanitarios sensibles de más de 3.5 millones de niños. Una revisión posterior al incidente determinó que los desarrolladores del sitio web no habían subsanado vulnerabilidades importantes. Al no haber registro ni monitoreo del sistema, la brecha de datos podría haber estado en curso desde 2013, un periodo de más de siete años.

**Escenario #2:** Una importante compañía aérea india sufrió una filtración de datos que afectó a más de diez años de datos personales de millones de pasajeros, incluidos datos de pasaportes y tarjetas de crédito. La filtración de datos se produjo en un proveedor externo de alojamiento en la nube, que notificó a la aerolínea la filtración después de algún tiempo.

**Escenario #3:** Una importante aerolínea europea sufrió una brecha de seguridad notificable según el GDPR. Al parecer, la brecha fue causada por vulnerabilidades de seguridad en la aplicación de pagos explotadas por atacantes, que recolectaron más de 400,000 registros de pagos de clientes. Como consecuencia, el regulador de la privacidad multó a la aerolínea con 20 millones de libras.


## Referencias

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## Lista de CWEs Mapeadas

* [CWE-117 Neutralización Inadecuada de la Salida para Registros (Improper Output Neutralization for Logs)](https://cwe.mitre.org/data/definitions/117.html)

* [CWE-221 Pérdida de Información por Omisión (Information Loss or Omission)](https://cwe.mitre.org/data/definitions/221.html)

* [CWE-223 Omisión de Información Relevante para la Seguridad (Omission of Security-relevant Information)](https://cwe.mitre.org/data/definitions/223.html)

* [CWE-532 Inserción de Información Sensible en un Archivo de Registro (Insertion of Sensitive Information into Log File)](https://cwe.mitre.org/data/definitions/532.html)

* [CWE-778 Registro Insuficiente (Insufficient Logging)](https://cwe.mitre.org/data/definitions/778.html)
