# A6:2017 Configuración de Seguridad Incorrecta

| Agentes de Amenaza	/Vectores de Ataque | Debilidades en Seguridad | Impactos               |
| -- | -- | -- |
| Nivel de Acceso \| Exploitabilidad 3 | Prevalencia 3 \| Detección 3 | Técnico 2 \| Negocio |
Incluso atacantes anónimos pueden intentar acceder a cuentas predeterminadas, páginas no utilizadas, defectos sin parchear, archivos y directorios desprotegidos, etc. para obtener acceso o conocimiento del sistema. | Configuraciones de seguridad incorrectas pueden ocurrir en cualquier nivel del stack tecnológico, incluyendo la plataforma base, servidor web, servidor de aplicaciones, base de datos, frameworks y código propio. Los escáners automatizados son útiles para detectar configuraciones incorrectas, el uso de cuentas o configuraciones predeterminadas, servicios innecesarios, opciones heredadas, etc. | Estos defectos suelen dar a los atacantes acceso no autorizado a algunos datos o funciones del sistema. Ocasionalmente, tales defectos resultan en un completo compromiso del sistema. El impacto en el negocio depende de las necesidades de protección de su aplicación y datos. |

## ¿La aplicación es vulnerable?

¿Su aplicación posee el hardening de seguridad apropiado a través de los distintos componentes del stack tecnológico? Incluyendo: 

* ¿Se encuentra instalada o habilitada algunas característica innecesarias (ej. puertos, servicios, páginas, cuentas, permisos)?
* ¿Se encuentra alguna cuenta y su respectiva contraseña por defecto aún habilitadas y sin cambios?
* ¿El manejo de errores revela trazas de la aplicación u otros mensajes de error demasiado informativos a los usuarios?
* ¿Utiliza configuraciones legadas con software actualizado? ¿Mantiene una compatibilidad obsoleta retroactiva?
* ¿Posee configuraciones con valores inseguros en servidores de aplicación o frameworks (ej., Struts, Spring, ASP.NET), librerias, bases de datos, etc.?
* En aplicaciones web, ¿el servidor no envía directrices de seguridad a los clientes (por ejemplo, [HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)) o no se encuentran configurados con valores seguros?
* ¿Posee software desactualizado? (ver A9: 2017 Uso de componentes con vulnerabilidades conocidas)

Sin un proceso de configuración de seguridad de aplicación concertado y repetible, los sistemas corren un mayor riesgo.

## Cómo se previene

Las principales recomendaciones son establecer todo lo siguiente:

* Un proceso de fortalecimiento reproducible que agilite y facilite la implementación de otro entorno que esté asegurado de manera apropiada. Los entornos de desarrollo, de control de calidad (QA)  y de Producción deben configurarse de manera idéntica (con diferentes credenciales utilizadas en cada entorno). Este proceso puede automatizarse para minimizar el esfuerzo requerido para configurar un nuevo entorno seguro.
* Elimine o desinstale funciones, componentes, documentación y ejemplos innecesarios. Elimine dependencias y frameworks innecesarios.
* Un proceso para priorizar e implementar todas las actualizaciones y parches de manera oportuna para cada entorno desplegado. Este proceso debe incluir todos los frameworks, dependencias, componentes y librerias (consulte A9: 2017 Uso de componentes con vulnerabilidades conocidas).
* Una arquitectura sólida de la aplicación que proporcione una separación efectiva y segura entre componentes, con segmentación, contenedorización o grupos de seguridad en la nube (ACL).
* Un proceso automatizado para verificar la efectividad de los ajustes y configuraciones en todos los ambientes.

## Ejemplos de escenarios de ataque

**Escenario #1**: La consola de administración del servidor de aplicaciones se ha instalado automáticamente y no ha sido eliminada. Las cuentas por defecto no han sido modificadas. El atacante descubre que las páginas de administración por defecto están en su servidor, inicia sesión con contraseñas predeterminadas y se toma el control de la misma.

**Escenario #2**: El listado de directorios no está deshabilitada en su servidor. Un atacante descubre que simplemente pueden enumerar directorios para encontrar los archivos. El atacante encuentra y descarga las clases compiladas de Java, las cuales descompila y realiza ingeniería inviersa para obtener el código fuente personalizado. Entonces el atacante encuentra una falla grave de control de acceso en su aplicación.

**Escenario #3**: La configuración del servidor de aplicación permite el retorno de los rastreos de pila a los usuarios, exponiendo potencialmente fallas subyacentes, como las versiones del framework que son conocidas por ser vulnerables.

**Escenario #4**: El servidor de aplicaciones incluye aplicaciones de ejemplo que han sido eliminadas de su servidor de producción. Estas aplicaciones de ejemplo tienen fallas de seguridad conocidas que los atacantes usan para comprometer su servidor.

**Escenario #5**: La configuración predeterminada o una copiada antigua activa las versiones antiguas de protocolos vulnerables, o las opciones que pueden ser mal utilizadas por un atacante o un malware.


## Referencias (en inglés)

### OWASP

* [Guía de Pruebas de OWASP - Gestión de la Configuración](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [Guía de Pruebas de OWASP - Prueba de Error de Código](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))

Para conocer más sobre requisitos adicionales en esta área, consulte las secciones [V11 y V19 de requisitos del ASVS](https://www.owasp.org/index.php/ASVS).

### Externos

* [Guía general del NIST para el hardening de servidores](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf)
* [Entrada 2 del CWE sobre defectos en la seguridad del ambiente](http://cwe.mitre.org/data/definitions/2.html)
* [Guías de configuración del CIS/Comparativas](http://benchmarks.cisecurity.org/downloads/benchmarks/)