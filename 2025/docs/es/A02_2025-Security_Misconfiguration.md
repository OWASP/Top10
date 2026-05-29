# A02:2025 Configuración de Seguridad Incorrecta (Security Misconfiguration) ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## Antecedentes

Subiendo desde el #5 en la edición anterior, se encontró que el 100% de las aplicaciones probadas tenían alguna forma de desconfiguración, con una tasa de incidencia promedio del 3.00% y más de 719k ocurrencias de CWE (Common Weakness Enumeration) (enumeración de Debilidades Comunes)  en esta categoría de riesgo. Con el aumento del software altamente configurable, no es sorprendente ver que esta categoría ascienda. Los CWE notables incluidos son *CWE-16: Configuración* y *CWE-611: Restricción Inadecuada de Referencias a Entidades Externas XML (XML External Entity, XXE)*.


## Tabla de puntuación


<table>
  <tr>
   <td>CWE Mapeados 
   </td>
   <td>Tasa de Incidencia Máx.
   </td>
   <td>Tasa de Incidencia Prom.
   </td>
   <td>Cobertura Máx.
   </td>
   <td>Cobertura Prom.
   </td>
   <td>Explotación Ponderada Prom.
   </td>
   <td>Impacto Ponderado Prom.
   </td>
   <td>Ocurrencias Totales
   </td>
   <td>CVE Totales
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>27.70%
   </td>
   <td>3.00%
   </td>
   <td>100.00%
   </td>
   <td>52.35%
   </td>
   <td>7.96
   </td>
   <td>3.97
   </td>
   <td>719,084
   </td>
   <td>1,375
   </td>
  </tr>
</table>



## Descripción

La configuración de seguridad incorrecta ocurre cuando un sistema, aplicación o servicio en la nube se configura incorrectamente desde una perspectiva de seguridad, creando vulnerabilidades.

La aplicación podría ser vulnerable si:



* Carece de un bastionado (hardening) de seguridad adecuado en cualquier parte de la pila de la aplicación o tiene permisos configurados incorrectamente en los servicios en la nube.
* Hay funciones innecesarias habilitadas o instaladas (por ejemplo, puertos, servicios, páginas, cuentas, marcos de prueba o privilegios innecesarios).
* Las cuentas predeterminadas y sus contraseñas siguen habilitadas y sin cambios.
* Falta una configuración central para interceptar mensajes de error excesivos. El manejo de errores revela trazas de la pila (stack traces) u otros mensajes de error demasiado informativos a los usuarios.
* Para los sistemas actualizados, las últimas funciones de seguridad están desactivadas o no están configuradas de forma segura.
* Existe una priorización excesiva de la compatibilidad hacia atrás que conduce a una configuración insegura.
* Los ajustes de seguridad en los servidores de aplicaciones, frameworks de aplicaciones (por ejemplo, Struts, Spring, ASP.NET), bibliotecas, bases de datos, etc., no están establecidos en valores seguros.
* El servidor no envía cabeceras o directivas de seguridad, o estas no están establecidas en valores seguros.

Sin un proceso de bastionado (hardening) de la configuración de seguridad de las aplicaciones que sea concertado y repetible, los sistemas corren un mayor riesgo.


## Cómo prevenir

Deben implementarse procesos de instalación seguros, que incluyan:



* Un proceso de bastionado (hardening) repetible que permita el despliegue rápido y sencillo de otro entorno que esté bloqueado adecuadamente. Los entornos de desarrollo, QA y producción deben estar configurados de forma idéntica, con credenciales diferentes en cada uno. Este proceso debe estar automatizado para minimizar el esfuerzo requerido para configurar un nuevo entorno seguro.
* Una plataforma mínima sin funciones, componentes, documentación o ejemplos innecesarios. Elimine o no instale funciones y frameworks que no utilice.
* Una tarea para revisar y actualizar las configuraciones de acuerdo con todas las notas de seguridad, actualizaciones y parches como parte del proceso de gestión de parches (consulte [A03 Fallas en la Cadena de Suministro de Software](A03_2025-Fallas_en_la_Cadena_de_Suministro_de_Software.md)(Software Supply Chain Failures)). Revise los permisos de almacenamiento en la nube (por ejemplo, los permisos de los cubos S3).
* Una arquitectura de aplicación segmentada que proporcione una separación efectiva y segura entre componentes o inquilinos (tenants), con segmentación, contenedorización o grupos de seguridad en la nube (ACLs).
* Envío de directivas de seguridad a los clientes, por ejemplo, Cabeceras de Seguridad (Security Headers).
* Un proceso automatizado para verificar la eficacia de las configuraciones y ajustes en todos los entornos.
* Añadir proactivamente una configuración central para interceptar mensajes de error excesivos como medida de respaldo.
* Si estas verificaciones no están automatizadas, deben verificarse manualmente al menos una vez al año.
* Utilizar federación de identidades, credenciales de corta duración o mecanismos de acceso basados en roles proporcionados por la plataforma subyacente en lugar de incrustar claves estáticas o secretos en el código, los archivos de configuración o los flujos de trabajo (pipelines).


## Escenarios de ejemplo de ataque

**Escenario #1:** El servidor de aplicaciones viene con aplicaciones de ejemplo que no se eliminaron del servidor de producción. Estas aplicaciones de ejemplo tienen fallas de seguridad conocidas que los atacantes utilizan para comprometer el servidor. Supongamos que una de estas aplicaciones es la consola de administración y las cuentas predeterminadas no se cambiaron. En ese caso, el atacante inicia sesión con la contraseña predeterminada y toma el control.

**Escenario #2:** El listado de directorios no está desactivado en el servidor. Un atacante descubre que puede simplemente listar los directorios. El atacante encuentra y descarga las clases Java compiladas, las cuales descompila y les aplica ingeniería inversa para ver el código. El atacante encuentra entonces una falla grave de control de acceso en la aplicación.

**Escenario #3:** La configuración del servidor de aplicaciones permite que se devuelvan mensajes de error detallados, como trazas de la pila, a los usuarios. Esto expone potencialmente información sensible o fallas subyacentes, como versiones de componentes que se sabe que son vulnerables.

**Escenario #4:** Un proveedor de servicios en la nube (CSP) tiene por defecto permisos de compartición abiertos a Internet. Esto permite el acceso a datos sensibles almacenados en el almacenamiento en la nube.


## Referencias

* [Guía de Pruebas de OWASP: Gestión de la Configuración](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [Guía de Pruebas de OWASP: Pruebas de Códigos de Error](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Estándar de Verificación de Seguridad en Aplicaciones V13 Configuración] (OWASP Application Security Verification Standard (ASVS)) (https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [Guía de NIST para el Bastionado General de Servidores](Guide to General Server Security)(https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [Guías/Benchmarks de Configuración de Seguridad de CIS] (CIS Benchmarks List)(https://www.cisecurity.org/cis-benchmarks/)
* [Descubrimiento y Enumeración de Cubos Amazon S3](AWS S3 Bucket Discovery)(https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration

## Lista de CWE Mapeados

* [CWE-5 Configuración Incorrecta de J2EE: Transmisión de Datos Sin Cifrado (J2EE Misconfiguration: Data Transmission Without Encryption)](https://cwe.mitre.org/data/definitions/5.html)

* [CWE-11 Configuración Incorrecta de ASP.NET: Creación de Binario de Depuración (ASP.NET Misconfiguration: Creating Debug Binary)](https://cwe.mitre.org/data/definitions/11.html)

* [CWE-13 Configuración Incorrecta de ASP.NET: Contraseña en Archivo de Configuración (ASP.NET Misconfiguration: Password in Configuration File)](https://cwe.mitre.org/data/definitions/13.html)

* [CWE-15 Control Externo del Sistema o del Ajuste de la Configuración (External Control of System or Configuration Setting)](https://cwe.mitre.org/data/definitions/15.html)

* [CWE-16 Configuración (Configuration)](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-260 Contraseña en Archivo de Configuración (Password in Configuration File)](https://cwe.mitre.org/data/definitions/260.html)

* [CWE-315 Almacenamiento en Texto Plano de Información Sensible en una Cookie (Cleartext Storage of Sensitive Information in a Cookie)](https://cwe.mitre.org/data/definitions/315.html)

* [CWE-489 Código de Depuración Activo (Active Debug Code)](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-526 Exposición de Información Sensible a Través de Variables de Entorno (Exposure of Sensitive Information Through Environmental Variables)](https://cwe.mitre.org/data/definitions/526.html)

* [CWE-547 Uso de Constantes Relevantes para la Seguridad quemadas en el código (harcodeadas)
 (Use of Hard-coded, Security-relevant Constants)](https://cwe.mitre.org/data/definitions/547.html)

* [CWE-611 Restricción Inadecuada de Referencias a Entidades Externas XML (Improper Restriction of XML External Entity Reference)](https://cwe.mitre.org/data/definitions/611.html)

* [CWE-614 Cookie Sensible en Sesión HTTPS sin el Atributo 'Secure' (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)](https://cwe.mitre.org/data/definitions/614.html)

* [CWE-776 Restricción Inadecuada de Referencias a Entidades Recursivas en DTDs ('Expansión de Entidades XML') (Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion'))](https://cwe.mitre.org/data/definitions/776.html)

* [CWE-942 Política de Seguridad entre Dominios Permisiva con Dominios No Confiables (Permissive Cross-domain Policy with Untrusted Domains)](https://cwe.mitre.org/data/definitions/942.html)

* [CWE-1004 Cookie Confidencial sin el Indicador 'HttpOnly' (Sensitive Cookie Without 'HttpOnly' Flag)](https://cwe.mitre.org/data/definitions/1004.html)

* [CWE-1174 Configuración Incorrecta de ASP.NET: Validación de Modelo Inadecuada (ASP.NET Misconfiguration: Improper Model Validation)](https://cwe.mitre.org/data/definitions/1174.html)
