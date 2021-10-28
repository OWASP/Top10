# A01:2021 – Pérdida de Control de Acceso    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Factores

| CWEs mapeados | Tasa de incidencia máx | Tasa de incidencia prom | Exploit ponderado prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 34          | 55.97%             | 3.81%              | 6.92                 | 5.93                | 94.55%       | 47.72%       | 318,487           | 19,013     |

## Resumen

Subiendo desde la quinta posición, el 94% de las aplicaciones se probaron para detectar algún tipo de pérdida de control de acceso con una tasa de incidencia promedio del 3,81%, y tuvo la mayor cantidad de ocurrencias en el conjunto de datos contribuido con más de 318k. Las enumeraciones de debilidades comunes (CWE) más importantes  incluidas son *CWE-200: Exposición de información sensible a un actor no autorizado*, *CWE-201:
Exposición de información confidencial a través de datos enviados*, y *CWE-352: Falsificación de solicitudes entre sitios*.

## Descripción

El control de acceso hace cumplir la política de modo que los usuarios no pueden actuar fuera de sus permisos previstos. Las fallas generalmente conducen a la divulgación de información no autorizada, la modificación o la destrucción de todos los datos o la realización de una función comercial fuera de los límites del usuario. Las vulnerabilidades comunes de control de acceso incluyen:

-   Violación del principio de privilegio mínimo o denegación por defecto, donde el acceso solo debería otorgarse para capacidades, roles o usuarios particulares, pero está disponible para cualquier persona.

-   Eludir las comprobaciones de control de acceso modificando la URL (alteración de parámetros o navegación forzada), el estado interno de la aplicación o la página HTML, o mediante el uso de una herramienta de ataque que modifique las solicitudes de API.

-   Permitir ver o editar la cuenta de otra persona, proporcionando su identificador único (referencias de objeto directo inseguras)

-   Acceso a API con controles de acceso inexistentes para POST, PUT y DELETE.

-   Elevación de privilegios. Actuar como usuario sin haber iniciado sesión o actuar como administrador cuando se inició sesión sólamente como usuario.

-   Manipulación de metadatos, como reproducir o alterar un token de control de acceso JSON Web Token (JWT), o una cookie o un campo oculto manipulado para elevar privilegios o abusar de la invalidación de JWT.

-   La configuración incorrecta de CORS(Uso compartido de recursos de origen cruzado) permite el acceso a la API desde orígenes no autorizados o no confiables.

-   Forzar la navegación a páginas autenticadas siendo usuario no autenticado o páginas privilegiadas siendo usuario estándar.

## Cómo se previene

El control de acceso solo es efectivo en código del lado del servidor confiable o API sin servidor, donde el atacante no puede modificar la verificación de control de acceso o los metadatos.

-   A excepción de los recursos públicos, denegar por defecto.

-   Implemente mecanismos de control de acceso una vez y reutilícelos en toda la aplicación, incluida la minimización del uso del intercambio de recursos entre orígenes (CORS).

-   Los controles de acceso del modelo deben hacer respetar la propiedad de los registros en lugar de aceptar que el usuario pueda crear, leer, actualizar o eliminar cualquier registro.

-   Los modelos de dominio deben hacer cumplir los requisitos únicos de límite de negocio de aplicaciones.

-   Deshabilite la lista de directorios del servidor web y asegúrese de que los metadatos de archivos (por ejemplo, .git) y archivos de respaldo no estén presentes dentro de los directorios raiz del sitio web

-   Registrar en un log las fallas de control de acceso, alertar a los administradores cuando sea apropiado (por ejemplo, fallas repetidas).

-   Ponga límites al número de accesos permitidos a la API y al controlador para minimizar el daño de las herramientas de ataque automatizadas.

-   Los identificadores de sesión con estado deben invalidarse en el servidor después de cerrar la sesión.
    Los tokens JWT sin estado deberían ser preferiblemente de corta duración para minimizar la ventana de oportunidad para un atacante. Para los JWT de mayor duración, es sumamente recomendable seguir los estándares de OAuth para revocar el acceso.

Tanto desarrolladores como personal de control de calidad deberían incluír una unidad de control de acceso funcional y pruebas de integración.

## Ejemplos de escenarios de ataque

**Escenario #1:** La aplicación utiliza datos no verificados en una llamada SQL que accede a información de una cuenta:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

Un atacante simplemente modifica el parámetro 'acct' del navegador para enviar el número de cuenta que desee. Si no es verificado correctamente, el atacante puede acceder a la cuenta de cualquier usuario.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Escenario #2:** Un atacante simplemente obliga a los navegadores a apuntar a una URL específica. Se requieren derechos de administrador para acceder a la página de administración.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```
Si un usuario no autenticado puede acceder a cualquiera de las páginas, es una falla. Si una persona que no es administrador puede acceder a la página de administración, esto es también una falla.

## Referencias

-   [Controles proactivos de OWASP: hacer cumplir los controles de acceso](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [Estándar de verificación de seguridad de aplicaciones OWASP: Control de acceso V4](https://owasp.org/www-project-application-security-verification-standard)

-   [Guía de prueba de OWASP: Testeo de autorización](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [Hoja de referencia de OWASP: Control de acceso](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [Hoja de referencia de OWASP: Autorización](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Explotación de la configuración incorrecta de CORS](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revocación de acceso](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## Lista de CWEs mapeadas

[CWE-22 Limitación incorrecta de nombre de ruta a un directorio restringido ('Traspaso de ruta')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Traspaso de ruta relativa](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Traspaso de ruta: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Resolución de enlace incorrecta antes del acceso al archivo ('Seguimiento de enlace')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposición de información confidencial a un actor no autorizado](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposición de información confidencial a través de datos enviados](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Almacenamiento de archivos con datos confidenciales en el directorio raíz del sitio web](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permisos, privilegios y controles de acceso (ya no deben usarse)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Problemas de permisos](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Permisos predeterminados incorrectos](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Control de acceso inadecuado](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Autorización incorrecta](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Falsificación de petición en sitios cruzados (Cross-Site Request Forgery - CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposición de información personal privada a un actor no autorizado](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Archivo temporal inseguro](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmisión de recursos privados a una nueva esfera ('Fuga de recursos')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Solicitud directa ('Navegación forzada')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Apoderado o intermediario involuntario ('Delegado por confusión')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposición de información sensible del sistema a una esfera de control no autorizada](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Inserción de información confidencial en un archivo o directorio de acceso externo](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusión de información sensible en el código fuente](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposición de información a través de la lista de directorios](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Archivos o directorios accesibles a terceros](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Vulneración de autorización a través de llave primaria SQL controlada por el usuario](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 Redirección de URL a un sitio que no es de confianza ('Redireccionamiento abierto')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Vulneración de autorización a través de una clave controlada por el usuario](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposición de archivos WSDL que contienen información confidencial](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposición de recursos a una esfera incorrecta](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Uso de nombre o referencia resueltos incorrectamente](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Falta de controles de autorización](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Autorización incorrecta](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Control inadecuado de los recursos de código administrados dinámicamente](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Almacenamiento inseguro de información confidencial](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Cookie sensible con atributo de SameSite incorrecto](https://cwe.mitre.org/data/definitions/1275.html)
