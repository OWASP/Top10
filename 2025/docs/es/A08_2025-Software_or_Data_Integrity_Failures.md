# A08:2025 Fallas en la Integridad del Software o de los Datos ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Antecedentes

Las fallas en la Integridad del Software o de los Datos continúan en el puesto #8, con un ligero cambio de nombre aclaratorio de "Fallas de Integridad de Software *o* Datos" (anteriormente "Fallas de Integridad de Software *y* Datos"). Esta categoría se centra en la falla de mantener los límites de confianza y verificar la integridad del software, el código y los artefactos de datos a un nivel inferior al de las fallas en la Cadena de Suministro de Software. Esta categoría se enfoca en hacer suposiciones relacionadas con las actualizaciones de software y los datos críticos, sin verificar su integridad. Las Enumeraciones de Debilidades Comunes (CWEs) notables incluyen *CWE-829: Inclusión de funcionalidad de una esfera de control no confiable, CWE-915: Modificación controlada incorrectamente de atributos de objetos determinados dinámicamente y CWE-502: Deserialización de datos no confiables*.


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
   <td>14
   </td>
   <td>8.98%
   </td>
   <td>2.75%
   </td>
   <td>78.52%
   </td>
   <td>45.49%
   </td>
   <td>7.11
   </td>
   <td>4.79
   </td>
   <td>501,327
   </td>
   <td>3,331
   </td>
  </tr>
</table>



## Descripción

Las fallas de integridad de software y datos se relacionan con el código y la infraestructura que no protege contra el hecho de que el código o los datos inválidos o no confiables sean tratados como confiables y válidos. Un ejemplo de esto es cuando una aplicación confía en complementos (plugins), bibliotecas o módulos de fuentes, repositorios y redes de entrega de contenidos (CDN) no confiables. Una canalización (pipeline) CI/CD insegura, sin el uso y la provisión de comprobaciones de integridad del software, puede dar lugar a la posibilidad de acceso no autorizado, código inseguro o malicioso, o compromiso del sistema. Otro ejemplo de esto es un CI/CD que extrae código o artefactos de lugares no confiables y/o no los verifica antes de su uso (mediante la comprobación de la firma o un mecanismo similar). Por último, muchas aplicaciones incluyen ahora una funcionalidad de actualización automática, en la que las actualizaciones se descargan sin una verificación de integridad suficiente y se aplican a la aplicación previamente confiable. Los atacantes podrían subir sus propias actualizaciones para que se distribuyan y ejecuten en todas las instalaciones. Otro ejemplo es cuando los objetos o datos se codifican o serializan en una estructura que un atacante puede ver y modificar, lo cual es vulnerable a la deserialización insegura.


## Cómo prevenir

* Utilizar firmas digitales o mecanismos similares para verificar que el software o los datos proceden de la fuente esperada y no han sido alterados.
* Asegurarse de que las bibliotecas y dependencias, como npm o Maven, solo consuman repositorios de confianza. Si se tiene un perfil de riesgo elevado, se debe considerar la posibilidad de alojar un repositorio interno con versiones de confianza que haya sido verificado.
* Garantizar que exista un proceso de revisión de los cambios de código y configuración para minimizar la posibilidad de que se introduzca código o configuración maliciosa en su flujo de software.
* Asegurarse de que su canalización CI/CD tenga la segregación, configuración y control de acceso adecuados para garantizar la integridad del código que fluye a través de los procesos de construcción y despliegue.
* Garantizar que no se reciban datos serializados sin firmar o sin cifrar de clientes no confiables y que se utilicen posteriormente sin algún tipo de comprobación de integridad o firma digital para detectar la manipulación o el reenvío (replay) de los datos serializados.


## Ejemplos de escenarios de ataque

**Escenario #1: Inclusión de funcionalidad web de una fuente no confiable:** Una empresa utiliza un proveedor de servicios externo para proporcionar una funcionalidad de soporte. Por conveniencia, tiene un mapeo de DNS de `miEmpresa.ProveedorSoporte.com` a `soporte.miEmpresa.com`. Esto significa que todas las cookies, incluidas las de autenticación, establecidas en el dominio `miEmpresa.com` se enviarán ahora al proveedor de soporte. Cualquier persona con acceso a la infraestructura del proveedor de soporte puede robar las cookies de todos sus usuarios que hayan visitado `soporte.miEmpresa.com` y realizar un ataque de secuestro de sesión (session hijacking).

**Escenario #2: Actualización sin firma:** Muchos routers domésticos, decodificadores, firmware de dispositivos y otros, no verifican las actualizaciones mediante firmware firmado. El firmware no firmado es un objetivo creciente para los atacantes y se espera que la situación empeore. Esto es una gran preocupación, ya que muchas veces no hay más mecanismo de remediación que corregirlo en una versión futura y esperar a que las versiones anteriores dejen de utilizarse.

**Escenario #3: Uso de un paquete de una fuente no confiable:** Un desarrollador tiene problemas para encontrar la versión actualizada de un paquete que está buscando, por lo que lo descarga no del gestor de paquetes habitual y de confianza, sino de un sitio web en internet. El paquete no está firmado y, por lo tanto, no hay oportunidad de garantizar su integridad. El paquete incluye código malicioso.

**Escenario #4: Deserialización insegura:** Una aplicación React llama a un conjunto de microservicios de Spring Boot. Al ser programadores funcionales, trataron de asegurar que su código fuera inmutable. La solución que se les ocurrió es serializar el estado del usuario y pasarlo de un lado a otro con cada solicitud. Un atacante observa la firma del objeto Java "rO0" (en base64) y utiliza el [Escáner de Deserialización de Java](https://github.com/federicodotta/Java-Deserialization-Scanner) para obtener la ejecución remota de código en el servidor de la aplicación.


## Referencias

* [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
* [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
* [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)


## Lista de CWEs Mapeadas

* [CWE-345 Verificación Insuficiente de la Autenticidad de los Datos (Insufficient Verification of Data Authenticity)](https://cwe.mitre.org/data/definitions/345.html)

* [CWE-353 Falta de Soporte para la Verificación de Integridad (Missing Support for Integrity Check)](https://cwe.mitre.org/data/definitions/353.html)

* [CWE-426 Ruta de Búsqueda No Confiable (Untrusted Search Path)](https://cwe.mitre.org/data/definitions/426.html)

* [CWE-427 Elemento de Ruta de Búsqueda No Controlado (Uncontrolled Search Path Element)](https://cwe.mitre.org/data/definitions/427.html)

* [CWE-494 Descarga de Código sin Verificación de Integridad (Download of Code Without Integrity Check)](https://cwe.mitre.org/data/definitions/494.html)

* [CWE-502 Deserialización de Datos No Confiables (Deserialization of Untrusted Data)](https://cwe.mitre.org/data/definitions/502.html)

* [CWE-506 Código Malicioso Incrustado (Embedded Malicious Code)](https://cwe.mitre.org/data/definitions/506.html)

* [CWE-509 Código Malicioso que se Replica (Virus o Gusano) (Replicating Malicious Code (Virus or Worm))](https://cwe.mitre.org/data/definitions/509.html)

* [CWE-565 Dependencia de Cookies sin Validación ni Verificación de Integridad (Reliance on Cookies without Validation and Integrity Checking)](https://cwe.mitre.org/data/definitions/565.html)

* [CWE-784 Dependencia de Cookies sin Validación ni Verificación de Integridad en una Decisión de Seguridad (Reliance on Cookies without Validation and Integrity Checking in a Security Decision)](https://cwe.mitre.org/data/definitions/784.html)

* [CWE-829 Inclusión de Funcionalidad desde una Esfera de Control No Confiable (Inclusion of Functionality from Untrusted Control Sphere)](https://cwe.mitre.org/data/definitions/829.html)

* [CWE-830 Inclusión de Funcionalidad Web desde una Fuente No Confiable (Inclusion of Web Functionality from an Untrusted Source)](https://cwe.mitre.org/data/definitions/830.html)

* [CWE-915 Modificación Controlada de Forma Inadecuada de Atributos de Objetos Determinados Dinámicamente (Improperly Controlled Modification of Dynamically-Determined Object Attributes)](https://cwe.mitre.org/data/definitions/915.html)

* [CWE-926 Exportación Inadecuada de Componentes de Aplicaciones Android (Improper Export of Android Application Components)](https://cwe.mitre.org/data/definitions/926.html)
