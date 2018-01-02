# A5:2017 Pérdida de Control de Acceso

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad         |      Impactos       |
| -- | -- | -- |
| Nivel de acceso : Explotabilidad 2    | Prevalencia 2 : Detectabilidad 2 | Técnico 3 : Negocio |
|La explotación del Control de Acceso es una habilidad central de los atacantes. Las herramientas [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) y [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) pueden detectar la ausencia de control de acceso, pero no verificar si es correcto en el caso de estar presente. El control de acceso es detectable utilizando medios manuales, o posiblemente a través de la automatización por la ausencia de controles de acceso en ciertos frameworks.|Las debilidades del control de acceso son comunes debido a la falta de detección automática y a la falta de pruebas funcionales efectivas por parte de los desarrolladores de aplicaciones. La detección de fallas en el control de acceso no suele ser cubierto por pruebas automatizadas, tanto estáticas o dinámicas. | El impacto técnico son los atacantes anónimos actuando como usuarios o administradores, los usuarios que utilizan funciones privilegiadas o crean, acceden, actualizan o eliminan cualquier registro. El impacto al negocio depende de la protección necesaria por la aplicación o sus datos. | 

## ¿La aplicación es vulnerable?

El control de acceso aplica la política de modo que los usuarios no puedan actuar fuera de los permisos previstos. Las fallas típicamente conducen a la divulgación, modificación o destrucción de información no autorizada de todos los datos, o al realizar una función de negocio fuera de los límites del usuario. Las vulnerabilidades comunes de control de acceso incluyen:

* Pasar por alto las comprobaciones de control de acceso modificando la URL, el estado interno de la aplicación o página HTML, o utilizando una herramienta personalizada de ataques a API.
* Permitir que la clave primaria se cambie a la de otro usuario, pudiendo ver o editar la cuenta de otra persona.
* Elevación de privilegios. Actuar como un usuario sin iniciar sesión, o actuar como  un administrador cuando inicia sesión como usuario.
* Manipulación de metadatos, como reproducir o manipular un token de control de acceso JWT (JSON Web Token), una cookie o un campo oculto para elevar los privilegios, o abusar de la invalidación de tokens JWT.
* La configuración incorrecta de CORS permite el acceso no autorizado a la API.
* Forzar la navegación  a páginas autenticadas como un usuario no autenticado o a páginas privilegiadas como usuario estándar. Acceder a API con controles de acceso ausentes para verbos POST, PUT y DELETE.

## Cómo se previene

El control de acceso solo es efectivo si es aplicado del lado del servidor o en la API sin servidor, donde el atacante no puede modificar la verificación o los metadatos del control de acceso.

* Con la excepción de los recursos públicos, denegar de forma predeterminada.
* Implemente los mecanismos de control de acceso una vez y reutilícelo en toda la aplicación, incluyendo minimizar el control de acceso HTTP (CORS).
* Los controles de acceso al modelo deben imponer la propiedad de los registros, en lugar de aceptar que el usuario puede crear, leer, actualizar o eliminar cualquier registro.
* Los modelos de dominio deben hacer cumplir los requisitos exclusivos de los límites de negocio de las aplicaciones.
* Deshabilitar el listado de directorios del servidor web y asegurar que los metadatos de archivos (por ejemplo de git) y archivos de copia de seguridad no estén presentes en las carpetas web.
* Registrar errores de control de acceso, alertar a los administradores cuando corresponda (por ejemplo, fallas reiteradas).
* Limite la tasa de acceso a APIs y al control de acceso para minimizar el daño de herramientas de ataque automatizadas.
* Los tokens JWT deben ser invalidados luego de la finalización de la sesión por parte del usuario.
* Los desarrolladores y el personal de control de calidad deben incluir pruebas de control de acceso en sus pruebas unitarias y de integración.

## Ejemplos de escenarios de ataque

**Escenario #1**:  La aplicación utiliza datos no validados en una llamada SQL que accede a información de cuenta:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

Un atacante simplemente modificando el parámetro 'acct' en el navegador para enviar el número de cuenta que desee. Si no se verifica correctamente, el atacante puede acceder a la cuenta de cualquier usuario.

`http://example.com/app/accountInfo?acct=notmyacct`

**Escenario #2**: Un atacante simplemente fuerza las búsquedas a las URL de destino. Los privilegios de administrador son necesarios para acceder a la página de administración.

```
  http://example.com/app/getappInfo
  http://example.com/app/admin_getappInfo
```

Si un usuario no autenticado puede acceder a cualquiera de las páginas, es un error. Si un usuario no administrador puede acceder a la página de administración, esto es una falla.

## Referencias (en inglés)

### OWASP

* [Controles Proactivos de OWASP: Control de Acceso](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V4 Control de Acceso](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Guía de Pruebas de OWASP: Control de Acceso](https://www.owasp.org/index.php/Testing_for_Authorization)
* [Hojas de ayuda de OWASP: Control de Acceso](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Externas

* [CWE-22 Limitación indebida de un nombre de ruta a un directorio restringido ('Path Traversal')]()
* [CWE-284 Control de Acceso inadecuado (Autorización)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285 Inadecuada Autorización](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639 Desviación de la autorización Bypass a través del claves controladas por el usuario](https://cwe.mitre.org/data/definitions/639.html)
* [Explotando fallas en las configuraciones de CORS](https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
