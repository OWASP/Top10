# Establecimiento de un Programa Moderno de Seguridad de Aplicaciones

Las listas del OWASP Top Ten son documentos de concienciación, destinados a llamar la atención sobre los riesgos más críticos de cualquier tema que cubran. No pretenden ser una lista completa, sino solo un punto de partida. En versiones anteriores de esta lista, hemos prescrito el inicio de un programa de seguridad de aplicaciones como la mejor manera de evitar estos riesgos, y más. En esta sección cubriremos cómo iniciar y construir un programa moderno de seguridad de aplicaciones.

Si ya dispone de un programa de seguridad de aplicaciones, considere realizar una evaluación de madurez del mismo utilizando [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) o DSOMM (DevSecOps Maturity Model). Estos modelos de madurez son integrales y exhaustivos, y pueden utilizarse para ayudarle a determinar dónde debe centrar mejor sus esfuerzos para ampliar y madurar su programa. Tenga en cuenta que no es necesario hacer todo lo que figura en OWASP SAMM o DSOMM para realizar un buen trabajo; su propósito es guiarle y ofrecerle muchas opciones. No pretenden ofrecer estándares inalcanzables ni describir programas inasumibles. Son amplios para ofrecerle muchas ideas y opciones.

Si está iniciando un programa desde cero, o si considera que OWASP SAMM o DSOMM son "demasiado" para su equipo en este momento, por favor revise los siguientes consejos.


### 1. Establecer un enfoque de cartera basado en el riesgo:

* Identifique las necesidades de protección de su cartera de aplicaciones desde una perspectiva de negocio. Esto debe estar impulsado, en parte, por las leyes de privacidad y otras regulaciones relevantes para el activo de datos que se protege.

* Establezca un [modelo común de calificación de riesgos](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) con un conjunto consistente de factores de probabilidad e impacto que reflejen la tolerancia al riesgo de su organización.


* Mida y priorice en consecuencia todas sus aplicaciones y API. Añada los resultados a su [Base de Datos de Gestión de Configuración (CMDB, *Configuration Management Database*)](https://es.wikipedia.org/wiki/Base_de_datos_de_gesti%C3%B3n_de_configuraci%C3%B3n).

* Establezca pautas de aseguramiento para definir adecuadamente la cobertura y el nivel de rigor requeridos.


### 2. Habilitar con una base sólida:

* Establezca un conjunto de políticas y estándares enfocados que proporcionen una línea base de seguridad de aplicaciones a la que deban adherirse todos los equipos de desarrollo.

* Defina un conjunto común de controles de seguridad reutilizables que complementen estas políticas y estándares, y proporcione orientación de diseño y desarrollo sobre su uso.

* Establezca un plan de estudios de formación en seguridad de aplicaciones que sea obligatorio y esté dirigido a diferentes roles y temas de desarrollo.


### 3. Integrar la seguridad en los procesos existentes:

* Defina e integre actividades de implementación y verificación seguras en los procesos de desarrollo y operativos existentes.

* Las actividades incluyen el modelado de amenazas, el diseño seguro y la revisión del diseño, la codificación segura y la revisión de código, las pruebas de penetración (*penetration testing*) y la remediación.

* Proporcione expertos en la materia y servicios de apoyo para que los equipos de desarrollo y de proyectos tengan éxito.

* Revise su ciclo de vida de desarrollo de sistemas (SDLC, *System Development Life Cycle*) actual y todas las actividades, herramientas, políticas y procesos de seguridad del software, y documéntelos.

* Para el nuevo software, añada una o más actividades de seguridad a cada fase del ciclo de vida de desarrollo de sistemas. A continuación ofrecemos muchas sugerencias de lo que puede hacer. Asegúrese de realizar estas nuevas actividades en cada nuevo proyecto o iniciativa de software; de esta manera, sabrá que cada nueva pieza de software se entregará con una postura de seguridad aceptable para su organización.

* Seleccione sus actividades para garantizar que su producto final cumpla con un nivel de riesgo aceptable para su organización.

* Para el software existente (a veces llamado *legacy*), querrá tener un plan de mantenimiento formal; por favor, busque ideas sobre cómo mantener aplicaciones seguras en la sección llamada "Operaciones y Gestión de Cambios".


### 4. Educación en Seguridad de Aplicaciones:

* Considere iniciar un programa de "campeones de seguridad" (*security champions*), o un programa general de educación en seguridad para sus desarrolladores (a veces llamado programa de promoción o de concienciación sobre seguridad), para enseñarles todo lo que desearía que supieran. Esto los mantendrá actualizados, les ayudará a saber cómo realizar su trabajo de forma segura y hará que la cultura de seguridad en su lugar de trabajo sea más positiva. A menudo, también mejora la confianza entre los equipos y facilita una relación de trabajo más satisfactoria. OWASP le apoya en esto con la [Guía de Campeones de Seguridad de OWASP](https://securitychampions.owasp.org/), que se está ampliando paso a paso.

* El Proyecto de Educación de OWASP proporciona materiales de formación para ayudar a educar a los desarrolladores en la seguridad de las aplicaciones web. Para un aprendizaje práctico sobre vulnerabilidades, pruebe el [Proyecto OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) o [OWASP WebGoat](https://owasp.org/www-project-webgoat/). Para mantenerse al día, asista a una [Conferencia OWASP AppSec](https://owasp.org/events/), a una [Formación en Conferencias OWASP](https://owasp.org/events/) o a las reuniones de su [Capítulo OWASP](https://owasp.org/chapters/) local.


### 5. Proporcionar visibilidad a la dirección:

* Gestione con métricas. Impulse la mejora y las decisiones de financiación basándose en las métricas y los datos de análisis capturados. Las métricas incluyen la adherencia a las prácticas y actividades de seguridad, las vulnerabilidades introducidas, las vulnerabilidades mitigadas, la cobertura de aplicaciones, la densidad de defectos por tipo y recuento de instancias, etc.

* Analice los datos de las actividades de implementación y verificación para buscar la causa raíz y patrones de vulnerabilidad para impulsar mejoras estratégicas y sistémicas en toda la empresa. Aprenda de los errores y ofrezca incentivos positivos para promover mejoras.



## Establecer y utilizar procesos de seguridad repetibles y controles de seguridad estándar

### Fase de Gestión de Recursos y Requisitos:

* Recopile y negocie los requisitos de negocio para una aplicación con el área de negocio, incluidos los requisitos de protección con respecto a la confidencialidad, autenticidad, integridad y disponibilidad de todos los activos de datos, y la lógica de negocio esperada.

* Recopile los requisitos técnicos, incluidos los requisitos de seguridad funcionales y no funcionales. OWASP recomienda utilizar el [Estándar de Verificación de Seguridad de Aplicaciones (ASVS, *Application Security Verification Standard*) de OWASP](https://owasp.org/www-project-application-security-verification-standard/) como guía para establecer los requisitos de seguridad de su(s) aplicación(es).

* Planifique y negocie el presupuesto que cubra todos los aspectos de diseño, construcción, pruebas y operación, incluidas las actividades de seguridad.

* Añada actividades de seguridad al cronograma de su proyecto.

* Preséntese como el representante de seguridad en el inicio del proyecto (*kick off*), para que sepan con quién hablar.


### Solicitud de Propuestas (RFP) y Contratación:

* Negocie los requisitos con desarrolladores internos o externos, incluyendo directrices y requisitos de seguridad con respecto a su programa de seguridad, por ejemplo, SDLC, mejores prácticas.

* Evalúe el cumplimiento de todos los requisitos técnicos, incluyendo una fase de planificación y diseño.

* Negocie todos los requisitos técnicos, incluyendo el diseño, la seguridad y los acuerdos de nivel de servicio (SLA).

* Adopte plantillas y listas de verificación (*checklists*), como el [Anexo de Contrato de Software Seguro de OWASP](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex).<br>**Nota:** *El anexo es para el derecho contractual de EE. UU., por lo que le rogamos que consulte con un asesor legal cualificado antes de utilizar el anexo de muestra.*


### Fase de Planificación y Diseño:

* Negocie la planificación y el diseño con los desarrolladores y las partes interesadas internas, por ejemplo, especialistas en seguridad.

* Defina la arquitectura de seguridad, los controles, las contramedidas y las revisiones de diseño apropiadas para las necesidades de protección y el nivel de amenaza esperado. Esto debe contar con el apoyo de especialistas en seguridad.

* En lugar de adaptar la seguridad a sus aplicaciones y API a posteriori, es mucho más rentable diseñar la seguridad desde el principio. OWASP recomienda las [Guías de referencia rápida de OWASP (*Cheat Sheets*)](https://cheatsheetseries.owasp.org/index.html) y los [Controles Proactivos de OWASP](https://top10proactive.owasp.org/) como un buen punto de partida para orientarse sobre cómo diseñar la seguridad incluida desde el inicio.

* Realice el modelado de amenazas, consulte la [Guía de referencia rápida de OWASP: Modelado de Amenazas](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

* Enseñe a sus arquitectos de software conceptos y patrones de diseño seguro y pídales que los añadan a sus diseños siempre que sea posible.

* Examine los flujos de datos con sus desarrolladores.

* Añada historias de usuario de seguridad junto con todas sus otras historias de usuario.


### Ciclo de Vida de Desarrollo Seguro:


* Para mejorar el proceso que sigue su organización al construir aplicaciones y API, OWASP recomienda el [Modelo de Madurez de Aseguramiento de Software (SAMM, *Software Assurance Maturity Model*) de OWASP](https://owasp.org/www-project-samm/). Este modelo ayuda a las organizaciones a formular e implementar una estrategia de seguridad de software adaptada a los riesgos específicos a los que se enfrenta su organización.

* Proporcione formación en codificación segura a sus desarrolladores de software, y cualquier otra formación que considere que les ayudará a crear aplicaciones más robustas y seguras.

* Revisión de código, consulte la [Guía de referencia rápida de OWASP: Revisión de Código Seguro](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).

* Entregue a sus desarrolladores herramientas de seguridad y enséñeles a utilizarlas, especialmente los escáneres de análisis estático (SAST), análisis de composición de software (SCA), secretos e [Infraestructura como Código (IaC, *Infrastructure-as-Code*)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html).

* Cree "barreras de protección" (*guardrails*) para sus desarrolladores, si es posible (salvaguardas técnicas para orientarlos hacia opciones más seguras).

* Construir controles de seguridad fuertes y usables es difícil. Ofrezca valores predeterminados seguros siempre que sea posible, y cree "caminos pavimentados" (*paved roads* — hacer que la forma más fácil sea también la más segura de hacer algo, la opción preferida obvia) siempre que sea posible. Las [Guías de referencia rápida de OWASP (*Cheat Sheets*)](https://cheatsheetseries.owasp.org/index.html) son un buen punto de partida para los desarrolladores, y muchos marcos de trabajo modernos vienen ahora con controles de seguridad estándar y efectivos para la autorización, validación, prevención de CSRF, etc.

* Entregue a sus desarrolladores complementos (*plugins*) de IDE relacionados con la seguridad y anímelos a usarlos.

* Proporcióneles una herramienta de gestión de secretos, licencias y documentación sobre cómo utilizarla.

* Proporcióneles una IA privada para su uso, idealmente configurada con un servidor RAG lleno de documentación de seguridad útil, *prompts* que su equipo haya escrito para obtener mejores resultados y un servidor MCP que llame a las herramientas de seguridad preferidas de su organización. Enséñeles a utilizar la IA de forma segura, porque lo van a hacer tanto si le gusta como si no.


### Establecer Pruebas Continuas de Seguridad de Aplicaciones:

* Pruebe las funciones técnicas y la integración con la arquitectura de TI y coordine las pruebas de negocio.

* Cree casos de prueba de "uso" y "abuso" desde las perspectivas técnica y de negocio.

* Gestione las pruebas de seguridad de acuerdo con los procesos internos, las necesidades de protección y el nivel de amenaza asumido por la aplicación.

* Proporcione herramientas de pruebas de seguridad (*fuzzers*, DAST, etc.), un lugar seguro para realizar las pruebas y formación sobre cómo usarlas, O realice las pruebas por ellos, O contrate a un evaluador.

* Si requiere un alto nivel de aseguramiento, considere una prueba de penetración formal, así como pruebas de estrés y de rendimiento.

* Trabaje con sus desarrolladores para ayudarles a decidir qué deben corregir de los informes de errores, y asegúrese de que sus gerentes les den tiempo para hacerlo.


### Despliegue:

* Ponga la aplicación en funcionamiento y migre desde aplicaciones utilizadas anteriormente si es necesario.

* Finalice toda la documentación, incluida la base de datos de gestión de cambios (CMDB) y la arquitectura de seguridad.


### Operaciones y Gestión de Cambios:

* Las operaciones deben incluir directrices para la gestión de la seguridad de la aplicación (por ejemplo, gestión de parches).

* Aumente la concienciación sobre seguridad de los usuarios y gestione los conflictos entre usabilidad y seguridad.

* Planifique y gestione los cambios, por ejemplo, la migración a nuevas versiones de la aplicación u otros componentes como el sistema operativo, el *middleware* y las bibliotecas.

* Asegúrese de que todas las aplicaciones estén en su inventario, con todos los detalles importantes documentados. Actualice toda la documentación, incluyendo la de la CMDB y la arquitectura de seguridad, los controles y las contramedidas, así como cualquier manual de procedimientos (*runbook*) o documentación del proyecto.

* Realice el registro, el monitoreo y las alertas para todas las aplicaciones. Añádalo si falta.

* Cree procesos para una actualización y aplicación de parches eficaces y eficientes.

* Establezca programas de escaneo regulares (idealmente dinámico, estático, de secretos, IaC y de análisis de composición de software).

* Acuerdos de Nivel de Servicio (SLA) para la corrección de errores de seguridad.

* Proporcione una forma para que los empleados (e idealmente también sus clientes) informen sobre errores.

* Establezca un equipo de respuesta a incidentes capacitado que comprenda cómo son los ataques de software y que cuente con herramientas de observabilidad.

* Ejecute herramientas de bloqueo o protección para detener ataques automatizados.

* Refuerzo de configuraciones (*hardening*) anual (o más frecuente).

* Pruebas de penetración al menos anuales (dependiendo del nivel de aseguramiento requerido para su aplicación).

* Establezca procesos y herramientas para reforzar y proteger su cadena de suministro de software.

* Establezca y actualice la planificación de la continuidad del negocio y la recuperación ante desastres que incluya sus aplicaciones más importantes y las herramientas que utiliza para mantenerlas.


### Retirada de Sistemas:

* Cualquier dato requerido debe ser archivado. Todos los demás datos deben ser borrados de forma segura.

* Retire la aplicación de forma segura, incluyendo la eliminación de cuentas, roles y permisos no utilizados.

* Establezca el estado de su aplicación como retirado en la CMDB.


## Uso del OWASP Top 10 como estándar

El OWASP Top 10 es principalmente un documento de concienciación. Sin embargo, esto no ha impedido que las organizaciones lo utilicen como un estándar de AppSec de facto en la industria desde su creación en 2003. Si desea utilizar el OWASP Top 10 como un estándar de codificación o de pruebas, sepa que es el mínimo indispensable y solo un punto de partida.

Una de las dificultades de utilizar el OWASP Top 10 como estándar es que documentamos riesgos de AppSec, y no necesariamente problemas fácilmente comprobables. Por ejemplo, [A06:2025 - Diseño Inseguro](A06_2025-Insecure_Design.md) está fuera del alcance de la mayoría de las formas de prueba. Otro ejemplo es comprobar si se han implementado registros y monitoreo eficaces en el lugar de uso, lo cual solo puede hacerse mediante entrevistas y solicitando un muestreo de respuestas a incidentes efectivas. Una herramienta de análisis de código estático puede buscar la ausencia de registros, pero puede ser imposible determinar si la lógica de negocio o el control de acceso están registrando brechas de seguridad críticas. Los evaluadores de penetración solo pueden determinar que han invocado la respuesta a incidentes en un entorno de prueba, que rara vez se monitorea de la misma manera que el de producción.

He aquí nuestras recomendaciones sobre cuándo es apropiado utilizar el OWASP Top 10:


<table>
  <tr>
   <td><strong>Caso de Uso</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>Estándar de Verificación de Seguridad de Aplicaciones de OWASP (ASVS)</strong>
   </td>
  </tr>
  <tr>
   <td>Concienciación
   </td>
   <td>Sí
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Formación
   </td>
   <td>Nivel de entrada
   </td>
   <td>Integral
   </td>
  </tr>
  <tr>
   <td>Diseño y arquitectura
   </td>
   <td>Ocasionalmente
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Estándar de codificación
   </td>
   <td>Mínimo indispensable
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Revisión de Código Seguro
   </td>
   <td>Mínimo indispensable
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Lista de comprobación de revisión por pares
   </td>
   <td>Mínimo indispensable
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Pruebas unitarias
   </td>
   <td>Ocasionalmente
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Pruebas de integración
   </td>
   <td>Ocasionalmente
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Pruebas de penetración
   </td>
   <td>Mínimo indispensable
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Soporte de herramientas
   </td>
   <td>Mínimo indispensable
   </td>
   <td>Sí
   </td>
  </tr>
  <tr>
   <td>Cadena de Suministro Segura
   </td>
   <td>Ocasionalmente
   </td>
   <td>Sí
   </td>
  </tr>
</table>


Alentamos a cualquiera que desee adoptar un estándar de seguridad de aplicaciones a utilizar el [Estándar de Verificación de Seguridad de Aplicaciones (ASVS) de OWASP](https://owasp.org/www-project-application-security-verification-standard/), ya que está diseñado para ser verificable y probado, y puede utilizarse en todas las partes de un ciclo de vida de desarrollo seguro.

El ASVS es la única opción aceptable para los proveedores de herramientas. Las herramientas no pueden detectar, probar o proteger de forma integral contra el OWASP Top 10 debido a la naturaleza de varios de sus riesgos, con referencia a [A06:2025 - Diseño Inseguro](A06_2025-Insecure_Design.md). OWASP desaconseja cualquier afirmación de cobertura total del OWASP Top 10, porque es sencillamente falsa.
