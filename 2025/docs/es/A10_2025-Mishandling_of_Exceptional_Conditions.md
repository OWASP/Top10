# A10:2025 Manejo Inadecuado de Condiciones Excepcionales ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}


## Antecedentes

El Manejo Inadecuado de Condiciones Excepcionales es una categoría nueva para 2025. Esta categoría contiene 24 CWE y se centra en el manejo inadecuado de errores, errores lógicos, fallas de forma abierta (failing open) y otros escenarios relacionados derivados de condiciones anormales que los sistemas pueden encontrar. Esta categoría incluye algunas CWE que anteriormente se asociaban con una mala calidad del código. Aquello era demasiado general para nosotros; en nuestra opinión, esta categoría más específica proporciona una mejor orientación.

CWE notables incluidas en esta categoría: *CWE-209: Generación de mensajes de error que contienen información sensible, CWE-234: Omisión del manejo de parámetros faltantes, CWE-274: Manejo inadecuado de privilegios insuficientes, CWE-476: Desreferencia de puntero NULL,* y *CWE-636: No fallar de forma segura ('Fallar de forma abierta' / 'Failing Open')*.


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
   <td>24
   </td>
   <td>20.67%
   </td>
   <td>2.95%
   </td>
   <td>100.00%
   </td>
   <td>37.95%
   </td>
   <td>7.11
   </td>
   <td>3.81
   </td>
   <td>769,581
   </td>
   <td>3,416
   </td>
  </tr>
</table>



## Descripción

El manejo inadecuado de condiciones excepcionales en el software ocurre cuando los programas no logran prevenir, detectar y responder a situaciones inusuales e impredecibles, lo que provoca caídas (crashes), comportamientos inesperados y, a veces, vulnerabilidades. Esto puede implicar uno o más de los siguientes tres fallas: la aplicación no previene que ocurra una situación inusual, no identifica la situación mientras está ocurriendo y/o responde de forma deficiente o no responde en absoluto a la situación posteriormente.

 

Las condiciones excepcionales pueden ser causadas por una validación de entradas ausente, deficiente o incompleta; por un manejo de errores de alto nivel tardío en lugar de realizarse en las funciones donde ocurren; por estados ambientales inesperados como problemas de memoria, privilegios o red; por un manejo de excepciones inconsistente o por excepciones que no se manejan en absoluto, permitiendo que el sistema caiga en un estado desconocido e impredecible. Cada vez que una aplicación no está segura de su siguiente instrucción, se ha manejado inadecuadamente una condición excepcional. Los errores y excepciones difíciles de encontrar pueden amenazar la seguridad de toda la aplicación durante mucho tiempo.

 

Pueden ocurrir muchas vulnerabilidades de seguridad diferentes cuando manejamos inadecuadamente las condiciones excepcionales, como errores de lógica, desbordamientos (overflows), condiciones de carrera (race conditions), transacciones fraudulentas o problemas de memoria, estado, recursos, tiempos (timing), autenticación y autorización. Estos tipos de vulnerabilidades pueden afectar negativamente la confidencialidad, disponibilidad y/o integridad de un sistema o de sus datos. Los atacantes manipulan el manejo de errores defectuoso de una aplicación para atacar esta vulnerabilidad.


## Cómo prevenir

Para manejar adecuadamente una condición excepcional, debemos planificar para tales situaciones (esperar lo peor). Debemos "capturar" (catch) cada posible error del sistema directamente en el lugar donde ocurre y luego manejarlo (lo que significa hacer algo significativo para resolver el problema y asegurar que nos recuperamos del mismo). Como parte del manejo, debemos incluir el lanzamiento de un error (para informar al usuario de forma comprensible), el registro (logging) del evento, así como la emisión de una alerta (alerting) si consideramos que está justificado. También deberíamos tener un manejador de excepciones global por si acaso algo se nos ha pasado por alto. Idealmente, también tendríamos herramientas o funcionalidades de monitoreo y/u observabilidad que vigilen errores repetidos o patrones que indiquen un ataque en curso, que pudieran emitir una respuesta, defensa o bloqueo de algún tipo. Esto puede ayudarnos a bloquear y responder a scripts y bots que se centran en nuestras debilidades de manejo de errores.

 

Capturar y manejar las condiciones excepcionales garantiza que la infraestructura subyacente de nuestros programas no se deje a merced de situaciones impredecibles. Si se encuentra a mitad de una transacción de cualquier tipo, es extremadamente importante que revierta (roll back) cada parte de la transacción y comience de nuevo (lo que también se conoce como fallar de forma segura o "fail closed"). Intentar recuperar una transacción a medias es a menudo donde creamos errores irrecuperables.

 

Siempre que sea posible, añada limitación de tasa (rate limiting), cuotas de recursos, regulación (throttling) y otros límites para prevenir las condiciones excepcionales en primer lugar. Nada en la tecnología de la información debería ser ilimitado, ya que esto conduce a una falta de resiliencia de la aplicación, denegación de servicio, ataques exitosos de fuerza bruta y facturas extraordinarias en la nube.

Considere si errores idénticos repetidos, por encima de una cierta tasa, deberían mostrarse únicamente como estadísticas que indiquen con qué frecuencia han ocurrido y en qué intervalo de tiempo. Esta información debería añadirse al mensaje original para no interferir con el registro y monitoreo automatizados, consulte [A09:2025-Fallas en el Registro, Alerta y Monitoreo de Seguridad](A09_2025-Fallas_en_el_Registro_y_Monitoreo.md).

Además de esto, querríamos incluir una validación de entradas estricta (con saneamiento o escape para los caracteres potencialmente peligrosos que debamos aceptar), un manejo de errores, registro, monitoreo y alertas *centralizados*, y un manejador de excepciones global. Una aplicación no debería tener múltiples funciones para manejar condiciones excepcionales; debería realizarse en un solo lugar, de la misma manera cada vez. También deberíamos crear requisitos de seguridad del proyecto para todos los consejos de esta sección, realizar actividades de modelado de amenazas y/o revisión de diseño seguro en la fase de diseño de nuestros proyectos, realizar revisiones de código o análisis estático, así como ejecutar pruebas de estrés, rendimiento y penetración del sistema final.

 

Si es posible, toda su organización debería manejar las condiciones excepcionales de la misma manera, ya que esto facilita la revisión y auditoría del código en busca de errores en este importante control de seguridad.


## Ejemplos de escenarios de ataque

**Escenario #1:** El agotamiento de recursos mediante el manejo inadecuado de condiciones excepcionales (Denegación de Servicio) podría producirse si la aplicación captura excepciones cuando se suben archivos, pero no libera adecuadamente los recursos después. Cada nueva excepción deja los recursos bloqueados o no disponibles de otro modo, hasta que se agotan todos los recursos.

**Escenario #2:** Exposición de datos sensibles mediante un manejo inadecuado o errores de base de datos que revelan el error completo del sistema al usuario. El atacante continúa forzando errores para utilizar la información sensible del sistema para crear un mejor ataque de inyección SQL. Los datos sensibles en los mensajes de error del usuario sirven de reconocimiento (reconnaissance).

**Escenario #3:** La corrupción de estado en transacciones financieras podría ser causada por un atacante que interrumpe una transacción de varios pasos mediante interrupciones de red. Imagine que el orden de la transacción fuera: debitar la cuenta del usuario, acreditar la cuenta de destino, registrar la transacción. Si el sistema no revierte adecuadamente toda la transacción (fallar de forma segura o "fail closed") cuando hay un error a mitad del proceso, el atacante podría potencialmente vaciar la cuenta del usuario, o posiblemente una condición de carrera podría permitir al atacante enviar dinero al destino varias veces.


## Referencias

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/) 


## Lista de CWEs Mapeadas
* [CWE-209 Generación de Mensajes de Error que Contienen Información Sensible (Generation of Error Message Containing Sensitive Information)](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215 Inserción de Información Sensible en el Código de Depuración (Insertion of Sensitive Information Into Debugging Code)](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234 Omisión del Manejo de Parámetros Faltantes (Failure to Handle Missing Parameter)](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235 Manejo Inadecuado de Parámetros Extra (Improper Handling of Extra Parameters)](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248 Excepción No Capturada (Uncaught Exception)](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252 Valor de Retorno No Verificado (Unchecked Return Value)](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274 Manejo Inadecuado de Privilegios Insuficientes (Improper Handling of Insufficient Privileges)](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280 Manejo Inadecuado de Permisos o Privilegios Insuficientes (Improper Handling of Insufficient Permissions or Privileges)](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369 División por Cero (Divide By Zero)](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390 Detección de Condición de Error sin Acción (Detection of Error Condition Without Action)](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391 Condición de Error No Verificada (Unchecked Error Condition)](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394 Código de Estado o Valor de Retorno Inesperado (Unexpected Status Code or Return Value)](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396 Declaración de Catch para Excepción Genérica (Declaration of Catch for Generic Exception)](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397 Declaración de Throws para Excepción Genérica (Declaration of Throws for Generic Exception)](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460 Limpieza Inadecuada al Lanzar una Excepción (Improper Cleanup on Thrown Exception)](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476 Desreferencia de Puntero NULL (NULL Pointer Dereference)](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478 Falta de Caso por Defecto en una Expresión de Condición Múltiple (Missing Default Case in Multiple Condition Expression)](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484 Sentencia Break Omitida en un Switch (Omitted Break Statement in Switch)](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550 Mensaje de Error Generado por el Servidor que Contiene Información Sensible (Server-generated Error Message Containing Sensitive Information)](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636 No Fallar de Forma Segura ('Fallar de Forma Abierta' / 'Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703 Verificación o Manejo Inadecuado de Condiciones Excepcionales (Improper Check or Handling of Exceptional Conditions)](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754 Verificación Inadecuada de Condiciones Inusuales o Excepcionales (Improper Check for Unusual or Exceptional Conditions)](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755 Manejo Inadecuado de Condiciones Excepcionales (Improper Handling of Exceptional Conditions)](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756 Falta de Página de Error Personalizada (Missing Custom Error Page)](https://cwe.mitre.org/data/definitions/756.html)
