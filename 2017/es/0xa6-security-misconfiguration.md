# A6:2017 Configuración de Seguridad Incorrecta

| Agentes de Amenaza	/Vectores de Ataque | Debilidades en Seguridad | Impactos               |
| -- | -- | -- |
| Nivel de Acceso \| Exploitabilidad 3 | Prevalencia 3 \| Detección 3 | Técnico 2 \| Negocio |
| Los atacantes anónimos pueden intentar acceder a cuentas por defecto, páginas sin uso, fallas sin parche, archivos y directorios sin protección, etc., para obtener acceso no autorizado o conocimiento del sistema. | Las configuraciones de seguridad incorrectas pueden surgir a cualquier nivel de la aplicación, incluyendo la plataforma, el servidor web, el servidor de aplicación, base de datos, frameworks, y código personalizado. | Las herramientas automatizadas son de utilidad para detectar: configuraciones de seguridad incorrectas, uso de usuarios o configuraciones por defecto, servicios innecesarios, opciones heredadas. | Éstas vulnerabilidades de seguridad frecuentemente permiten a los atacantes acceso a algunos datos del sistema o funcionalidades. Ocasionalmente éstas vulnerabilidades dan lugar a que el sistema sea comprometido en sus totalidad.  El impacto del negocio depende de las necesidades de protección de su aplicación y datos. |

## ¿Soy vulnerable?

Su aplicación no tiene el fortalecimiento de seguridad apropiado en alguna de las capas que la componen? Incluye: 

* ¿Están habilitadas o instaladas algunas caracteríscas innecesarias (ej. puertos, servicios, páginas, cuentas, permisos)?
* ¿Están las cuentas por defecto y sus contraseñas aún habilitadas y sin cambios?
* ¿Su manejo de errores revela pistas de las capas de la aplicación u otros mensajes de error demasiado informativos a los usuarios?
* ¿Todavía utiliza configuraciones antiguas con software actualizado? ¿Mantiene una compatibilidad obsoleta retroactiva?
* ¿Las configuraciones de seguridad en sus servidores de aplicación, frameworks de aplicación (ej., Struts, Spring, ASP.NET), librerias, bases de datos, etc., no tienen configuraciones en valores seguros?
* En aplicaciones web, ¿el servidor no envía directrices de seguridad a los clientes (por ejemplo, [HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)) o no están configurados para valores seguros?
* ¿Tiene software desactualizado? (ver A9: 2017 Uso de componentes con vulnerabilidades conocidas)

Sin un proceso de configuración de seguridad de aplicación concertada y repetible, los sistemas corren un mayor riesgo.

## ¿Cómo prevenirlo?

Establecer las siguientes principales recomendaciones:

* Un proceso de fortalecimiento reproducible que agilite y facilite la implementación de otro entorno que esté asegurado de manera apropiada. Los entornos de desarrollo, el control de calidad (QA)  y de Producción deben configurarse de manera idéntica (con diferentes credenciales utilizadas en cada entorno). Este proceso debe automatizarse para minimizar el esfuerzo requerido para configurar un nuevo entorno seguro.
* Elimine o desinstale funciones, componentes, documentación y ejemplos innecesarios. Elimine las dependencias y frameworks no utilizados.
* Un proceso para priorizar e implementar todas las actualizaciones y parches de manera oportuna para cada entorno desplegado. Este proceso debe incluir todos los frameworks, dependencias, componentes y librerias (consulte A9: 2017 Uso de componentes con vulnerabilidades conocidas).
* Una arquitectura sólida de la aplicación que proporcione una separación efectiva y segura entre componentes, con segmentación, contenedorización o grupos de seguridad en la nube (ACL).
* Un proceso automatizado para verificar la efectividad de los ajustes y configuraciones en todos los ambientes.

## Ejemplos de Escenarios de Ataque

**Escenario #1**: La consola de administración del servidor de aplicaciones se ha instalado automáticamente y no ha sido eliminada. Las cuentas por defecto no han sido modificadas. El atacante descubre que las páginas de administración por defecto están en su servidor, inicia sesión con contraseñas predeterminadas y se toma el control de la misma.

**Escenario #2**: El listado de directorios no está deshabilitada en su servidor. Un atacante descubre que simplemente pueden enumerar directorios para encontrar los archivos. El atacante encuentra y descarga las clases compiladas de Java, las cuales descompila y realiza ingeniería inviersa para obtener el código fuente personalizado. Entonces el atacante encuentra una falla grave de control de acceso en su aplicación.

**Escenario #3**: La configuración del servidor de aplicación permite el retorno de los rastreos de pila a los usuarios, exponiendo potencialmente fallas subyacentes, como las versiones del framework que son conocidas por ser vulnerables.

**Escenario #4**: El servidor de aplicaciones incluye aplicaciones de ejemplo que han sido eliminadas de su servidor de producción. Estas aplicaciones de ejemplo tienen fallas de seguridad conocidas que los atacantes usan para comprometer su servidor.

**Escenario #5**: La configuración predeterminada o una copiada antigua activa las versiones antiguas de protocolos vulnerables, o las opciones que pueden ser mal utilizadas por un atacante o un malware.


## Referencias

### OWASP

* [Guía de prueba de OWASP: Gestión de la Configuración](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [Guía de prueba de OWASP: Prueba de Error de Código](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))

Para conocer más sobre requisitos adicionales en esta área, consulte la sección de requisitos de [ASVS para Configuración de seguridad (V11 y V19)](https://www.owasp.org/index.php/ASVS).

### Externos

* [NIST Guide to General Server Hardening](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf)
* [CWE Entry 2 on Environmental Security Flaws](http://cwe.mitre.org/data/definitions/2.html)
* [CIS Security Configuration Guides/Benchmarks](http://benchmarks.cisecurity.org/downloads/benchmarks/)
