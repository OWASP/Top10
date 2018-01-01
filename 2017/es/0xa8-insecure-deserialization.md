# A8:2017 Deserialización Insegura

| Agentes de Amenazas/Vectores de Ataque | Debilidad de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de Acceso : Exploitabilidad 1 | Prevalencia 2 : Detectabilidad 2 | Técnico 3 : Negocio |
| La explotación de la deserialización es algo difícil, ya que los exploits cómo son distribuidos raramente funcionan sin cambios o ajustes en el código de exploit subyacente. | Este ítem se incluye en el Top 10 basado en una [encuesta de la industria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) y no en datos cuantificables. Algunas herramientas pueden descubrir defectos de deserialización, pero con frecuencia se necesita ayuda humana para validar el problema. Se espera que los datos de prevalencia de las deficiencias en la deserialización aumenten a medida que se desarrollen las herramientas para ayudar a identificarlas y abordarlas. | No se puede exagerar el impacto de los defectos de deserialización. Estos defectos pueden llevar a la ejecución remota de código, uno de los ataques más serios posibles. El impacto al negocio depende de las necesidades de protección de la aplicación y los datos. |

## ¿La aplicación es vulnerable?

Aplicaciones y APIs serán vulnerables si deserializan objetos hostiles o manipulados por un atacante.

Esto da como resultado dos tipos primarios de ataques:

* Ataques relacionados con la estructura de datos y objetos donde el atacante modifica la lógica de la aplicación o logra una ejecución remota de código si existen clases disponibles para la aplicación que pueden cambiar el comportamiento durante o después de la deserialización.
* Ataques típicos de manipulación de datos, como ataques relacionados con el control de acceso en los que se utilizan estructuras de datos existentes pero se modifica su contenido.

Serialización puede ser utilizada en aplicaciones para:

* Comunicación remota e inter-procesos (RPC/IPC
* Protocolo de comunicaciones, Web Services y Brokers de mensajes
* Caching/Persistencia
* Bases de datos, servidores de cache y sistemas de archivos

## ¿Como prevenirlo?

El único patron de arquitectura seguro es no aceptar objetos serializados de fuentes no confiables o utilizar medios de serialización que sólo permitan tipos de datos primitivos.

Si esto no es posible, considere uno o mas de los siguientes puntos:

* Implementar verificaciones de integridad tales como firmas digitales en cualquier objeto serializado con el fin de detectar modificaciones no autorizadas.
* Cumplimiento estricto de verificaciones de tipo de dato durante la deserialización y antes de la creación del objeto, ya que el código normalmente espera un conjunto de clases definibles. Se ha demostrado que se puede pasar por alto esta técnica, por lo que no es aconsejable confiar únicamente en ella.
* Aislar el código que realiza la deserialización, de modo que ejecute en un entorno con los mínomos provilegios posibles.
* Registrar excepciones y fallas en la deserialización, tales como cuando el tipo recibido no es el tipo esperado, o la deserialización lanza excepciones.
* Restringir o monitorear las conexiones de red entrantes y salientes desde contenedores o servidores que utilizan funcionalidades de deserialización.
* Monitorear deserialización, alertando si un usuario deserializa constantemente.

## Ejemplos de Escenarios de Ataque

**Escenario #1**: Una aplicación React invoca a un conjunto de microservicios Spring Boot. Siendo programadores funcionales, intentaron asegurar que su código sea inmutable. La solución a la que llegaron es serializar el estado del usuario y pasarlo en ambos sentidos con cada solicitud. Un atacante advierte la firma "R00" del objeto Java, y usa la herramienta Java Serial Killer para obtener ejecución de código remoto en el servidor de la aplicación.

**Escenario #2**: Un foro PHP utiliza serialización de objetos PHP para almacenar una "super" cookie, conteniendo el ID, rol, hash de la contraseña y otros estados del usuario:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Un atacante modifica el objeto serializado para darse a si mismo los privilegios de administrador:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Referencias (en Inglés)

### OWASP

* [Hoja de ayuda de OWASP - Deserialización](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [Controles Proactivos de OWASP - Validar Todas las Entradas](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP - TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### Externas

* [CWE-502 Deserialización de Datos No Confiables](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
