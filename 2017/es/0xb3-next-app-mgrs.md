# +A: Próximos pasos para los Administradores de Aplicaciones

## Administrar el Ciclo de Vida Completo de la Aplicación

Las aplicaciones son algunos de los sistemas más complejos que los humanos crean y mantienen. La administración TI (Tecnología de la Información) para una aplicación debería ser ejecutada por especialistas en TI que sean responsables por el completo ciclo de vida de la misma. Sugerimos la creación del administrador para cada aplicación a los efectos de proveer una contraparte técnica al dueño de la aplicación. El administrador de la aplicación se encarga de todo el ciclo de vida de la aplicación desde el punto de vista de TI, desde la recopilación de los requisitos hasta el proceso de retirada de los sistemas, que a menudo se pasa por alto. 

## Administración de Requisitos y Recursos

* Recolectar y negociar los requisitos de negocios para una aplicación, incluyendo los requisitos confidencialidad, autenticidad, integridad y disponibilidad de todos los activos de datos y de las funciones de negocio.
* Recopilar los requerimientos técnicos incluyendo requerimientos de seguridad funcionales y no funcionales.
* Planear y negociar el presupuesto que cubre todos los aspectos de diseño, construcción, testeo y operación, incluyendo actividades de seguridad.

## Solicitud de Propuestas (RFP) y Contrataciones

* Negociar requisitos con desarrolladores internos y externos, incluyendo lineamientos y requerimientos de seguridad con respecto a su programa de seguridad, p.ej. SDLC, mejores prácticas.
* Evaluar el cumplimiento de todos los requerimientos técnicos, incluyendo las fases de planificación y diseño.
* Negociar todos los requerimientos técnicos incluyendo diseño, seguridad y acuerdos de nivel de servicio (SLA).
* Considere usar plantillas y listas de comprobación, tal como el [Anexo de Contrato de Software Seguro de OWASP](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex) **Nota**: El Anexo es un ejemplo específico a las leyes de contrato de EUA, y probablemente necesitará de revisión legale en su jurisdicción. Por favor obtenga consejo legal calificado antes de usar el Anexo.

## Planificación y Diseño

* Negociar la planificación y diseño con los desarrolladores e interesados internos, p. ej. especialistas de securidad.
* Definir la arquitectura de seguridad, controles, y contramedidas adecuadas a las necesidades de protección y el nivel de amenazas planificado. Esto debería contar con el apoyo de especialistas en seguridad.
* Asegurar que el propietario de la aplicación acepta los riesgos remanentes o bien que provea recursos adicionales.
* En cada etapa, asegurar de que se crean historias de seguridad para requerimientos funcionales, y se agreguen restricciones para requerimientos no funcionales.

## Desarrollo

* Por favor revise +D "¿Qué sigue para desarrolladores" para guía.

## Despliegue, Pruebas y Puesta en Producción

* Automatizar el despliegue seguro de la aplicación, interfaces y todo componente, incluyendo las autorizaciones requeridas.
* Probar las funciones técnicas y la integración a la arquitectura de TI, y coordinar pruebas de las funciones de negocio.
* Crear casos de "uso" y de "abuso" tanto desde el punto de vista netamente técnico como del negocio.
* Administrar pruebas de seguridad de acuerdo a los procesos internos, las necesidades de protección y el nivel de amenazas asumido para la aplicación.
* Poner la aplicación en operación y migrar de las aplicaciones usadas previamente en caso de ser necesario.
* Finalizar toda la documentación, incluyendo la Base de Datos de Gestión de la Seguridad (CMDB) y la arquitectura de seguridad.

## Operación y Gestión del cambio

* Operar incluyendo la administración de seguridad de la aplicación (p.ej. administración de parches).
* Aumentar la conciencia de seguridad de los usuarios y administrar conflictos de usabilidad vs seguridad.
* Panificar y gestionar cambios, por ejemplo la migración a nuevas versiones de la aplicación u otros componentes como Sistema Operativo, interfaces de software y bibliotecas.
* Actualizar toda la documentación, incluyendo en la CMDB y la arquitectura de seguridad.

## Retiro de Sistemas

* Cualquier dato requerido debe ser almacenado. Otros datos deben ser eliminados de forma segura.
* Retirar la aplicación en forma segura, incluyendo el borrado de cuentas, roles y permisos no usados.
* Establecer el estado de su aplicación a retirada en la CMDB.