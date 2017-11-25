# +A: ¿Que sigue para los Administradores de Aplicaciones?

## Administrar el Ciclo de Vida Completo de la Aplicación

Las aplicaciones son algunos de los sistemas más complejos que los humanos crean y mantienen regularmente. La administración TI (Tecnología de la Información) para una aplicación debería ser ejecutada por especialistas en TI que sean responsables por el completo ciclo de vida de la misma.

Sugerimos la designación de propietarios y administradores para cada aplicación a los efectos de proveer una Matriz de Asignación de Responsabilidades, con sus correspondientes roles: Encargado, Responsable, Consultado, Informado (RACI por sus siglas en inglés). El administrador de la aplicación es la contraparte técnica del propietario de la aplicación desde la perspectiva del negocio y administra el ciclo de vida completo de la aplicación, incluyendo la seguridad de una aplicación, activos de datos asociados, y documentación. Esto puede ayudar a entender quién puede aceptar los riesgos, y quién es responsable de incluir la seguridad.

## Administración de Requerimientos y Recursos

* Recolectar y negociar los requerimientos de negocios para una aplicación, incluyendo la recepción de los requerimientos de protección en vista a la confidencialidad, integridad y disponibilidad de todos los activos de datos.
* Compilar los requerimientos técnicos incluyendo requerimientos de seguridad funcionales y no funcionales.
* Planear y negociar el presupuesto que cubre todos los aspectos de diseño, construcción, testeo y operación, incluyendo actividades de seguridad.

## Solicitud de Propuestas (RFP por sus siglas en inglés) y su Adopción

* Negociar los requerimientos con desarrolladores internos y externos, incluyendo lineamientos y requerimientos de seguridad con respecto a su programa de seguridad, p.ej. SDLC, mejores prácticas.
* Evaluar el cumplimiento de todos los requerimientos técnicos incluyendo un borrador de planeamiento y diseño.
* Negociar todos los requerimientos técnicos incluyendo diseño, seguridad y acuerdos de nivel de servicio (SLA por sus siglas en inglés).
* Considere usar plantillas y listas de comprobación, tal como el [Anexo de Contrato de Software Seguro de OWASP](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex) **NB**: El Anexo es un ejemplo específico a las leyes de contrato de EUA, y probablemente necesitará de revisión legale en su jurisdicción. Por favor obtenga consejo legal calificado antes de usar el Anexo.

## Planeamiento y Diseño

* Negociar el planeamiento y diseño con los desarrolladores e interesados internos, p. ej. especialistas de securidad.
* Definir una arquitectura de seguridad, controles, y contramedidas de acuerdo a las necesidades de protección y el nivel planeado de seguridad ambiental. Esto debería contar con el soporte de especialistas en seguridad.
* Haga que el propietario de la aplicación asuma los riesgos remanentes o bien que provea recursos adicionales.
* En cada etapa, asegúrese de que se crean historiales de seguridad para requerimientos funcionales, y se agreguen restricciones para requerimientos no funcionales.

## Desarrollo

* Por favor revise +D "¿Qué sigue para desarrolladores" para guía.

## Despliegue, Testeo y Puesta en Producción

* Es crítico que las tareas de seguridad automatizen la segura puesta en marcha de la aplicación, interfaces y todo otro componente necesario, incluyendo las autorizaciones requeridas.
* Testear las funciones técnicas y la integración a la arquitectura TI, y coordinar pruebas de las necesidades de negocio. Tenga en cuenta testear los casos de uso y abuso desde la perspectiva técnica y de negocio.
* Administrar testeos de seguridad de acuerdo a los procesos internos, las necesidades de protección y el nivel de seguridad existente donde la aplicación va a ser implementada.
* Poner la aplicación en operación y migrar de las aplicaciones usadas previamente.
* Finalizar toda la documentación, incluyendo la Base de Datos de Gestión de la Seguridad (CMDB por sus siglas en inglés) y la arquitectura de seguridad.

## Operación y Cambios

* Operar incluyendo la administración de seguridad de la aplicación (p.ej. administración de parches).
* Reportar regularmente todos los ususarios y autorizaciones al propietario de la aplicación y obtener su acuse de recibo.
* Aumentar la conciencia de seguridad de los ususarios y administrar conflictos de usabilidad vs seguridad.
* Planear y administrar cambios, p.ej. la migración a nuevas versiones de la aplicación u otros componentes como SO, interfaces de software y bibliotecas.
* Actualizar toda la documentación, incluyendo en la CMDB y la arquitectura de seguridad, controles, y contramedidas, incluyendo cualquier manual de procedimientos o documentación del proyecto.

## Retiro de Sistemas

* Implementar requerimientos de negocio para las políticas de retención, borrado y archivado seguro de datos.
* Cerrar la aplicación en forma segura, incluyendo el borrado de cuentas, roles y permisos no usados.
* Establecer el estado de su aplicación a retirada en la CMDB.
