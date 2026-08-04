#  A01:2025 Pérdida de Control de Acceso (Broken Access Control) ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}



## Antecedentes

Manteniendo su posición en el #1 del Top Ten, se encontró que el 100% de las aplicaciones probadas tenían alguna forma de pérdida de control de acceso. Los CWE notables incluidos son *CWE-200: Exposición de Información Sensible a un Actor no Autorizado*, *CWE-201: Exposición de Información Sensible a Través de Datos Enviados*, *CWE-918: Falsificación de Solicitud del Lado del Servidor (SSRF)*, y *CWE-352: Falsificación de Solicitud en Sitios Cruzados (CSRF)*. Esta categoría tiene el mayor número de ocurrencias en los datos aportados y el segundo número más alto de CVE relacionados.


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
   <td>40
   </td>
   <td>20.15%
   </td>
   <td>3.74%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.04
   </td>
   <td>3.84
   </td>
   <td>1,839,701
   </td>
   <td>32,654
   </td>
  </tr>
</table>



## Descripción

El control de acceso aplica políticas de tal manera que los usuarios no puedan actuar fuera de sus permisos previstos. Las fallas suelen conducir a la divulgación no autorizada de información, la modificación o destrucción de todos los datos, o la ejecución de una función de negocio fuera de los límites del usuario. Las vulnerabilidades comunes de control de acceso incluyen:



* Violación del principio de mínimo privilegio, comúnmente conocido como denegar por defecto, donde el acceso solo debe otorgarse para capacidades, roles o usuarios específicos, pero está disponible para cualquier persona.
* Elusión de los controles de acceso mediante la modificación de la URL (manipulación de parámetros o navegación forzada), el estado interno de la aplicación o la página HTML, o mediante el uso de una herramienta de ataque que modifique las solicitudes a la API.
* Permitir ver o editar la cuenta de otra persona proporcionando su identificador único (referencias directas inseguras a objetos o Insecure Direct Object References, IDOR).
* Una API accesible con falta de controles de acceso para POST, PUT y DELETE.
* Elevación de privilegio. Actuar como un usuario sin haber iniciado sesión o ganar privilegios más allá de los esperados para el usuario autenticado (por ejemplo, acceso de administrador).
* Manipulación de metadatos, como la repetición o manipulación de un token de control de acceso JSON Web Token (JWT), una cookie o un campo oculto manipulado para elevar privilegios, o el abuso de la invalidación de JWT.
* La desconfiguración de CORS permite el acceso a la API desde orígenes no autorizados o no confiables.
* Navegación forzada (adivinar URLs) hacia páginas autenticadas como un usuario no autenticado o hacia páginas privilegiadas como un usuario estándar.


## Cómo prevenir

El control de acceso solo es efectivo cuando se implementa en código del lado del servidor de confianza o en APIs sin servidor (serverless), donde el atacante no puede modificar la comprobación del control de acceso o los metadatos.



* Excepto para recursos públicos, denegar por defecto.
* Implementar mecanismos de control de acceso una sola vez y reutilizarlos en toda la aplicación, incluyendo la minimización del uso del Intercambio de Recursos de Origen Cruzado (Cross-Origin Resource Sharing, CORS).
* Los controles de acceso del modelo deben imponer la propiedad de los registros en lugar de permitir que los usuarios creen, lean, actualicen o eliminen cualquier registro.
* Los requisitos únicos de límites de negocio de la aplicación deben ser aplicados por los modelos de dominio.
* Desactivar el listado de directorios del servidor web y asegurarse de que los metadatos de los archivos (por ejemplo, .git) y los archivos de respaldo no estén presentes dentro de las raíces web.
* Registrar las fallas de control de acceso, alertar a los administradores cuando sea apropiado (por ejemplo: fallas repetidas).
* Implementar límites de tasa (límites de velocidad - rate limits) en el acceso a la API y a los controladores para minimizar el daño de las herramientas de ataque automatizadas.
* Los identificadores de sesión con estado deben invalidarse en el servidor tras el cierre de sesión. Los tokens JWT sin estado deben ser de corta duración para minimizar la ventana de oportunidad de un atacante. Para JWT de mayor duración, considere el uso de tokens de actualización (refresh tokens) y siga los estándares de OAuth para revocar el acceso.
* Utilizar kits de herramientas o patrones bien establecidos que proporcionen controles de acceso sencillos y declarativos.

Los desarrolladores y el personal de control de calidad (QA) deben incluir el control de acceso funcional en sus pruebas unitarias y de integración.


## Escenarios de ejemplo de ataque

**Escenario #1:** La aplicación utiliza datos no verificados en una llamada SQL que accede a la información de la cuenta:


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```


Un atacante puede simplemente modificar el parámetro 'acct' del navegador para enviar cualquier número de cuenta deseado. Si no se verifica correctamente, el atacante puede acceder a la cuenta de cualquier usuario.


```
https://example.com/app/accountInfo?acct=notmyacct
```


**Escenario #2:** Un atacante simplemente fuerza a los navegadores a dirigirse a URLs específicas. Se requieren derechos de administrador para acceder a la página de administración.


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


Si un usuario no autenticado puede acceder a cualquiera de las páginas, es una falla. Si un usuario que no es administrador puede acceder a la página de administración, esto es una falla.

**Escenario #3:** Una aplicación pone todo su control de acceso en su front-end. Aunque el atacante no puede llegar a `https://example.com/app/admin_getappInfo` debido al código JavaScript que se ejecuta en el navegador, simplemente puede ejecutar:


```
$ curl https://example.com/app/admin_getappInfo
```


desde la línea de comandos.


## Referencias

* [Controles Proactivos de OWASP: C1: Implementar Control de Acceso](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V8 Autorización](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [Guía de Pruebas de OWASP: Pruebas de Autorización](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [Guía de referencia rápida de OWASP: Autorización](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Explotación de la desconfiguración de CORS](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revocación de Acceso](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## Lista de CWE Mapeados

* [CWE-22 Limitación Inadecuada de un Nombre de Ruta a un Directorio Restringido ('Salto de Directorio' / 'Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

* [CWE-23 Salto de Directorio Relativo (Relative Path Traversal)](https://cwe.mitre.org/data/definitions/23.html)

* [CWE-36 Salto de Directorio Absoluto (Absolute Path Traversal)](https://cwe.mitre.org/data/definitions/36.html)

* [CWE-59 Resolución de Enlace Inadecuada Antes del Acceso al Archivo ('Seguimiento de Enlaces') (Improper Link Resolution Before File Access ('Link Following'))](https://cwe.mitre.org/data/definitions/59.html)

* [CWE-61 Seguimiento de Enlaces Simbólicos (Symlink) en UNIX (UNIX Symbolic Link (Symlink) Following)](https://cwe.mitre.org/data/definitions/61.html)

* [CWE-65 Enlace Rígido en Windows (Windows Hard Link)](https://cwe.mitre.org/data/definitions/65.html)

* [CWE-200 Exposición de Información Sensible a un Actor no Autorizado (Exposure of Sensitive Information to an Unauthorized Actor)](https://cwe.mitre.org/data/definitions/200.html)

* [CWE-201 Exposición de Información Sensible a Través de Datos Enviados (Insertion of Sensitive Information Into Sent Data)](https://cwe.mitre.org/data/definitions/201.html)

* [CWE-219 Almacenamiento de Archivo con Datos Sensibles Bajo la Raíz Web (Storage of File with Sensitive Data Under Web Root)](https://cwe.mitre.org/data/definitions/219.html)

* [CWE-276 Permisos por Defecto Incorrectos (Incorrect Default Permissions)](https://cwe.mitre.org/data/definitions/276.html)

* [CWE-281 Preservación Inadecuada de Permisos (Improper Preservation of Permissions)](https://cwe.mitre.org/data/definitions/281.html)

* [CWE-282 Gestión Inadecuada de la Propiedad (Improper Ownership Management)](https://cwe.mitre.org/data/definitions/282.html)

* [CWE-283 Propiedad no Verificada (Unverified Ownership)](https://cwe.mitre.org/data/definitions/283.html)

* [CWE-284 Control de Acceso Inadecuado (Improper Access Control)](https://cwe.mitre.org/data/definitions/284.html)

* [CWE-285 Autorización Inadecuada (Improper Authorization)](https://cwe.mitre.org/data/definitions/285.html)

* [CWE-352 Falsificación de Solicitud en Sitios Cruzados (Cross-Site Request Forgery (CSRF))](https://cwe.mitre.org/data/definitions/352.html)

* [CWE-359 Exposición de Información Personal Privada a un Actor no Autorizado (Exposure of Private Personal Information to an Unauthorized Actor)](https://cwe.mitre.org/data/definitions/359.html)

* [CWE-377 Archivo Temporal Inseguro (Insecure Temporary File)](https://cwe.mitre.org/data/definitions/377.html)

* [CWE-379 Creación de Archivo Temporal en Directorio con Permisos Inseguros (Creation of Temporary File in Directory with Insecure Permissions)](https://cwe.mitre.org/data/definitions/379.html)

* [CWE-402 Transmisión de Recursos Privados a una Nueva Esfera ('Fuga de Recursos') (Transmission of Private Resources into a New Sphere ('Resource Leak'))](https://cwe.mitre.org/data/definitions/402.html)

* [CWE-424 Protección Inadecuada de Ruta Alternativa (Improper Protection of Alternate Path)](https://cwe.mitre.org/data/definitions/424.html)

* [CWE-425 Solicitud Directa ('Navegación Forzada' o 'Forced Browsing') (Direct Request ('Forced Browsing'))](https://cwe.mitre.org/data/definitions/425.html)

* [CWE-441 Proxy o Intermediario no Intencionado ('Confused Deputy') (Unintended Proxy or Intermediary ('Confused Deputy'))](https://cwe.mitre.org/data/definitions/441.html)

* [CWE-497 Exposición de Información Sensible del Sistema a una Esfera de Control no Autorizada (Exposure of Sensitive System Information to an Unauthorized Control Sphere)](https://cwe.mitre.org/data/definitions/497.html)

* [CWE-538 Inserción de Información Sensible en un Archivo o Directorio Accesible Externamente (Insertion of Sensitive Information into Externally-Accessible File or Directory)](https://cwe.mitre.org/data/definitions/538.html)

* [CWE-540 Inclusión de Información Sensible en el Código Fuente (Inclusion of Sensitive Information in Source Code)](https://cwe.mitre.org/data/definitions/540.html)

* [CWE-548 Exposición de Información a Través del Listado de Directorios (Exposure of Information Through Directory Listing)](https://cwe.mitre.org/data/definitions/548.html)

* [CWE-552 Archivos o Directorios Accesibles a Partes Externas (Files or Directories Accessible to External Parties)](https://cwe.mitre.org/data/definitions/552.html)

* [CWE-566 Elusión de Autorización a Través de una Clave Primaria SQL Controlada por el Usuario (Authorization Bypass Through User-Controlled SQL Primary Key)](https://cwe.mitre.org/data/definitions/566.html)

* [CWE-601 Redirección de URL a un Sitio no Confiable ('Redirección Abierta' u 'Open Redirect') (URL Redirection to Untrusted Site ('Open Redirect'))](https://cwe.mitre.org/data/definitions/601.html)

* [CWE-615 Inclusión de Información Sensible en los Comentarios del Código Fuente (Inclusion of Sensitive Information in Source Code Comments)](https://cwe.mitre.org/data/definitions/615.html)

* [CWE-639 Elusión de Autorización a Través de una Clave Controlada por el Usuario (Authorization Bypass Through User-Controlled Key)](https://cwe.mitre.org/data/definitions/639.html)

* [CWE-668 Exposición de un Recurso a la Esfera Equivocada (Exposure of Resource to Wrong Sphere)](https://cwe.mitre.org/data/definitions/668.html)

* [CWE-732 Asignación Incorrecta de Permisos para un Recurso Crítico (Incorrect Permission Assignment for Critical Resource)](https://cwe.mitre.org/data/definitions/732.html)

* [CWE-749 Método o Función Peligrosa Expuesta (Exposed Dangerous Method or Function)](https://cwe.mitre.org/data/definitions/749.html)

* [CWE-862 Falta de Autorización (Missing Authorization)](https://cwe.mitre.org/data/definitions/862.html)

* [CWE-863 Autorización Incorrecta (Incorrect Authorization)](https://cwe.mitre.org/data/definitions/863.html)

* [CWE-918 Falsificación de Solicitud del Lado del Servidor (Server-Side Request Forgery (SSRF))](https://cwe.mitre.org/data/definitions/918.html)

* [CWE-922 Almacenamiento Inseguro de Información Sensible (Insecure Storage of Sensitive Information)](https://cwe.mitre.org/data/definitions/922.html)

* [CWE-1275 Cookie Sensible con Atributo SameSite Incorrecto (Sensitive Cookie with Improper SameSite Attribute)](https://cwe.mitre.org/data/definitions/1275.html)
