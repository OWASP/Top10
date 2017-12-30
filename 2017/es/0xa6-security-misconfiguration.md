# A6:2017 Configuración de Seguridad Incorrecta

| Agentes de Amenaza	/Vectores de Ataque | Debilidades en Seguridad | Impactos               |
| -- | -- | -- |
| Nivel de Acceso \| Exploitabilidad 3 | Prevalencia 3 \| Detección 3 | Técnico 2 \| Negocio |
Los atacantes a menudo intentarán explotar defectos sin parchear o acceder a cuentas predeterminadas, páginas no utilizadas, archivos y directorios desprotegidos, etc. para obtener acceso o conocimiento no autorizado del sistema. | Configuraciones incorrectas de seguridad puede nocurrir en cualquier nivel del stack tecnológico, incluidos los servicios de red, la plataforma, el servidor web, el servidor de aplicaciones, la base de datos, frameworks, el código personalizado y máquinas virtuales preinstaladas, contenedores o almacenamiento. Los escáneres automatizados son útiles para detectar configuraciones erróneas, el uso de cuentas o configuraciones predeterminadas, servicios innecesarios, opciones heredadas, etc. | Tales defectos frecuentemente dan a los atacantes acceso no autorizado a algunos datos o funciones del sistema. Ocasionalmente, tales defectos resultan en un completo compromiso del sistema. El impacto de negocio depende de las necesidades de protección de la aplicación y los datos. |

## ¿La aplicación es vulnerable?

La aplicación puede ser vulnerable si:

* Falta de hardening adecuado en cualquier parte del stack tecnológico, o permisos mal configurados en los servicios de la nube.
* Se encuentran instaladas o habilitadas característica innecesarias (ej. puertos, servicios, páginas, cuentas o permisos)
* Las cuentas predeterminadas y sus contraseñas siguen activas y sin cambios.
* El manejo de errores revela trazas de la aplicación u otros mensajes de error demasiado informativos a los usuarios
* Para los sistemas actualizados, las nuevas funciones de seguridad se encuentran desactivadas o no se encuentran configuradas de forma segura.
* Las configuraciones de seguridad en el servidor de aplicaciones, en el framework de aplicación (ej., Struts, Spring, ASP.NET), bibliotecas, bases de datos no se encuentran especificados en valores seguros.
* El servidor no envía directrices o cabezales de seguridad a los clientes o no se encuentran configurados con valores seguros
* El software se encuentra desactualizado o posee vulnerabilidades (ver A9: 2017 Uso de componentes con vulnerabilidades conocidas)

Sin un proceso de configuración de seguridad de aplicación concertado y repetible, los sistemas corren un mayor riesgo.

## Cómo se previene

Deben implementarse procesos seguros de instalación, incluyendo:

* Un proceso de fortalecimiento reproducible que agilite y facilite la implementación de otro entorno que esté asegurado de manera apropiada. Los entornos de desarrollo, de control de calidad (QA)  y de Producción deben configurarse de manera idéntica (con diferentes credenciales utilizadas en cada entorno). Este proceso puede automatizarse para minimizar el esfuerzo requerido para configurar un nuevo entorno seguro.
* Una plataforma minimalista sin funcionalidades innecesarias, componentes, documentación o ejemplos. Elimine o no instale frameworks y funcionalidades no utilizadas.
* Un proceso para revisar y actualizar las configuraciones apropiadas para todas las advertencias de seguridad, actualizaciones y parches como parte del proceso de gestión de parches (ver **A9:2017-Uso de Componentes con vulnerabilidades conocidas**). En particular, revise los permisos de almacenamiento en la nube (por ejemplo, los permisos de buckets de S3).
* Una arquitectura de la aplicación segmentada que proporcione una separación efectiva y segura entre componentes o arrendatarios, utilizando segmentación, contenedorización o grupos de seguridad en la nube (ACL).
* Enviando directivas de seguridad a clientes, p. ej.[Cabezales de seguridad](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project).
* Un proceso automatizado para verificar la efectividad de los ajustes y configuraciones en todos los ambientes.

## Ejemplos de escenarios de ataque

**Escenario #1**: El servidor de aplicaciones viene con aplicaciones de ejemplo que no se eliminan del servidor de producción. Estas aplicaciones  poseen defectos de seguridad conocidos que los atacantes usan para comprometer el servidor. Si una de estas aplicaciones es la consola de administración, y las cuentas predeterminadas no se han cambiado, el atacante inicia sesión con contraseñas predeterminadas tomando control del mismo.

**Escenario #2**: El listado de directorios se encuentra activado en el servidor. Un atacante descubre que puede listar los archivos. El atacante encuentra y descarga las clases de Java compiladas, las descompila y realiza ingeniería inversa para ver el código. Encuentra un grave defecto en el control de acceso de la aplicación.

**Escenario #3**: La configuración del servidor de aplicaciones permite retornar mensajes de error detallados a los usuarios, por ejemplo, las trazas de pila. Esto expone potencialmente información sensible o fallas subyacentes tales como versiones de componentes que se sabe que son vulnerables.

**Escenario #4**: Un proveedor de servicios en la nube (CSP) por defecto permite a otros usuarios del CSP acceder a sus archivos desde internet. Esto permite el acceso a datos sensibles almacenados en la nube.


## Referencias (en inglés)

### OWASP

* [Guía de Pruebas de OWASP - Gestión de la Configuración](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [Guía de Pruebas de OWASP - Prueba de Error de Código](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))
* [Proyecto de Cabezalez de Seguridad de OWASP](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

Para conocer más sobre requisitos adicionales en esta área, consulte el Estándar de Verificación de Seguridad en Aplicaciones [V19 Configuración](https://www.owasp.org/index.php/ASVS_V19_Configuration).

### Externos

* [Guía general del NIST para el hardening de servidores]((https://csrc.nist.gov/publications/detail/sp/800-123/final))
* [CWE 2: Defectos en la seguridad del ambiente](https://cwe.mitre.org/data/definitions/2.html)
* [CWE-16: Configuración](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-388: Manejo de Errores](https://cwe.mitre.org/data/definitions/388.html)
* [Guías de configuración del CIS/Comparativas](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Descubribilidad y Enumeración](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)








