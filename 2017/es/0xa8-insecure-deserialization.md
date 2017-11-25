# A8:2017 Deserialización Insegura

| Agentes de Amenazas/Vectores de Ataque | Debilidad de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de Acceso \| Exploitabilidad 1 | Prevalencia 2 \| Detectabilidad 2 | Técnico 3 \| Negocio |
| La explotación de deserialización es de algún modo difícil, ya que los exploits prefabricados raramente funcionan sin cambios o mejoras al código subyacente del exploit. | Este tema es incluído en el Top 10 basado en una [encuesta de la industria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) y no en datos cuantificables. Algunas herramientas pueden descubrir errores de deserialización, pero la asistencia humana es frecuentemente necesaria para validar el problema. Se espera que los datos de prevalencia para los errores de deserialización aumentarán en la medida que se desarrollen las herramientas para ayudar a identificarlos. | El impacto de los errores de deserialización no puede ser subestimado. Ellos pueden conducir a ataques de ejecución remota de código, uno de los mas serios ataques posibles. |

## ¿Soy Vulnerable a la Deserialización Insegura?

Las aplicaciones distribuidas o aquellas que necesitan almacenar un estado en los clientes o en el sistema de archivos pueden estar usando serialización de objetos. Las aplicaciones distribuidas con listeners públicos o aplicaciones que confían en el estado mantenido por el cliente, probablemente permiten la manipulación de datos serializados. Este ataque es posible con formatos binarios como la Serialización Java o formatos basados en texto como Json.Net. Las aplicaciones y las APIs serán vulnerables cuando:
* Los mecanismos de serialización permiten la creación de tipos de datos arbitrarios, Y
* Existen clases disponibles a la aplicación que pueden ser encadenadas para permitir cambios a la conducta de la aplicación durante o después de la deserialización, o contenido no esperado puede ser usado para influenciar la conducta de la aplicación, Y
* La aplicación o la API acepta y deserializa objetos hostiles suministrados por un atacante, o una aplicación usa un estado del lado del cliente serializado opaco sin los apropiados controles de resistencia a la manipulación. O
* El estado de seguridad enviado a un cliente no confiable sin alguna forma de control de integridad es probablemente vulnerable a la deserialización.

## ¿Como Prevenirlo?

El único patrón de arquitectura seguro es no aceptar objetos serializados de fuentes no confiables o usar medios de serialización que solo permitan tipos de datos primitivos.

Si eso no es posible:
* Implementar chequeos de integridad o encriptación de los objetos serializados para prevenir la creación de objetos hostiles o la manipulación de datos.
* Reforzar la restricción a tipos de datos estrictos durante la deserialización antes de la creación del objeto; típicamente el código espera un conjunto de clases definible. Métodos para burlar esta técnica han sido demostrados.
* Aislar el código que deserializa, de modo que corra en entornos de muy bajo privilegio, como contenedores temporales.
* Registrar excepciones y fallas en la deserialización, como cuando el tipo recibido no es el tipo esperado, o la deserialización arroja excepciones.
* Restringir o monitorear las conexiones entrantes y salientes de la red desde contenedores o servidores que deserializan.
* Monitorear deserialización, alertando si un usuario deserializa constantemente.

## Ejemplos de Escenarios de Ataque

**Escenario #1**: Una React app llama a un conjunto de microservicios Spring Boot. Siendo programadores funcionales, ellos intentaron asegurar que su código sea inmutable. La solución a la que llegaron es serializar el estado del usuario y pasarlo en ambos sentidos con cada solicitud. Un atacante advierte la firma "R00" del objeto Java, y usa la herramienta Java Serial Killer para obtener ejecución de código remoto en el servidor de la aplicación.

**Escenario #2**: Un foro PHP usa serialización de objetos PHP para almacenar una "super" cookie, conteniendo el ID, rol, hash de la contraseña y otros estados del usuario:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Un atacante cambia el objeto serializado para darse a si mismo los privilegios de administrador:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Referencias

### OWASP

* [Hoja de Trucos de Deserialización OWASP](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [Controles Proactivos OWASP - Validar Todas las Entradas](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [Estándar de Verificación de Seguridad de Aplicación de OWASP - TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Sobreviviendo al Apocalipsis de la Deserialización Java](https://www.slideshare.net/cschneider4711/surviving-the-java-deserialization-apocalypse-owasp-appseceu-2016)

### Externas

* [CWE-502 Deserialización de Datos No Confiables](https://cwe.mitre.org/data/definitions/502.html)
* https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf
* https://github.com/mbechler/marshalsec
