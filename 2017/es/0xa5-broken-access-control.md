# A5:2017 Pérdida de Control de Acceso

| Agentes de Amenaza/Vectores de ataque | Debilidades de Seguridad           | Impacto               |
| -- | -- | -- |
| Acceso Lvl \| Explotabilidad 2 | Prevalencia 2 \| Detección 2 | Técnico 3 \| Negocio |
|La explotación del Control de Acceso es una habilidad central de los analistas de seguridad de aplicaciones. Las herramientas SAST y DAST pueden detectar la ausencia de control de acceso, pero no verificar si es funcional. El control de acceso es detectable utilizando medios manuales, o posiblemente a través de la automatización por la ausencia de controles de acceso en ciertos frameworks.|Las debilidades del control de acceso son comunes debido a la falta de detección automática y a la falta de pruebas funcionales efectivas por parte de los desarrolladores de aplicaciones. La detección de fallas en el control de acceso no suele ser susceptible de pruebas automáticas estáticas o dinámicas. | El impacto técnico son los atacantes anónimos actuando como usuarios o administradores, los usuarios que utilizan funciones privilegiadas o crean, acceden, actualizan o eliminan cualquier registro. | 

## ¿Soy vulnerable?

El control de acceso aplica la política de modo que los usuarios no puedan actuar fuera de los permisos previstos. Las fallas típicamente conducen a la divulgación, modificación o destrucción de información no autorizada de todos los datos, o al realizar una función de negocio fuera de los límites del usuario. Las vulnerabilidades comunes de control de acceso incluyen:

* Pasar por alto las comprobaciones de control de acceso modificando la URL, el estado de la aplicación interna o la página HTML, o simplemente utilizando una herramienta de ataque de API personalizada.
* Permitir que la clave primaria se cambie a la de otro usuario, como ver o editar la cuenta de otra persona.
* Elevación de privilegios. Actuar como un usuario sin iniciar sesión, o actuar como  un administrador cuando inicia sesión como usuario.
* Manipulación de metadatos, como reproducir o manipular un token de control de acceso JWT (JSON Web Token) o una cookie o un campo oculto manipulado para elevar los privilegios.
* La configuración incorrecta de CORS permite el acceso no autorizado a la API
* Fuerza a buscar páginas autenticadas como usuario no autenticado, o a páginas con privilegios como usuario estándar o API que no aplica controles de acceso para los métodos POST, PUT y DELETE.

## ¿Cómo prevenirlo?

El control de acceso solo es efectivo si se aplica en un código confiable del lado del servidor o en una API sin servidor, donde el atacante no puede modificar la verificación o los metadatos del control de acceso.

* Con la excepción de los recursos públicos, denegar de forma predeterminada.
Implemente los mecanismos de control de acceso una vez y vuelva a utilizarlos en toda la aplicación.
* Los controles de acceso del modelo debe exigir la propiedad del registro, en lugar de aceptar que el usuario pueda crear, leer, actualizar o borrar cualquier registro.
* Los controles de acceso de dominio son únicos para cada aplicación, pero los requisitos de límite de negocio deben ser aplicados por los modelos de dominio.
* Deshabilitar listar directorios del servidor web y asegurarse de que los metadatos de los archivos (por ejemplo, .git) no estén presentes en las raíces web.
* Registrar errores de control de acceso, alertas administrativas cuando corresponda (por ejemplo, fallas reiteradas).
* Tasa de limitación API y acceso de controlador para minimizar el daño de herramientas de ataque automatizadas.
* Los desarrolladores y el personal de control de calidad deben incluir una unidad de control de acceso funcional y pruebas de integración.

## Ejemplo de Escenarios de ataque

**Escenario #1**:  La aplicación utiliza danos no validados en una llamada SQL que accede a información de cuenta:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery( );
```

Un atacante simplemente modificando el parámetro 'acct' en el navegador para enviar el número de cuenta que desee. Si no se verifica correctamente, el atacante puede acceder a la cuenta de cualquier usuario.

* `http://example.com/app/accountInfo?acct=notmyacct`

**Escenario #2**: Un atacante simplemente fuerza las búsquedas a las URL de destino. Los privilegios de administrador son necesarios para acceder a la página de administración.

* `http://example.com/app/getappInfo`
* `http://example.com/app/admin_getappInfo`

Si un usuario no autenticado puede acceder a cualquiera de las páginas, es un error. Si un usuario no administrador puede acceder a la página de administración, esto es un defecto.

## Referencias

### OWASP

* [OWASP Proactive Controls - Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard - V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide - Access Control](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet - Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Externas

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')]()
* [CWE-284 Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [Exploiting CORS misconfiguration](https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
