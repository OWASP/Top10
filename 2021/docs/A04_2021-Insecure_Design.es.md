# A04:2021 – Diseño Inseguro   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png)

## Factores

| CWEs Mapeados | Tasa de Incidencia Máxima | Tasa de Incidencia Promeedia | Explotación Ponderada Promedio | Impacto Ponderado Promedio | Covertura Màxima | Coverturra Promedia | Incidencias Totales| CVEs Totales |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## Resumen

Una nueva categoría para 2021 se centra en los riesgos relacionados con el diseño y las fallas arquitectónicas, con un llamado a un mayor uso del modelado de amenazas, patrones de diseño seguros y arquitecturas de referencia. Como comunidad, debemos ir más allá del "desplazamiento a la izquierda" en el espacio de codificación para precodificar actividades que son críticas para los principios de Secure by Design. NLos CWE notables incluidos son *CWE-209: Generación de mensaje de error que contiene información confidencial*, *CWE-256: Almacenamiento desprotegido de credenciales*, *CWE-501: Infracción de límites de confianza* y *CWE-522: Insuficiente Credenciales protegidas*.

## Descripción

El diseño inseguro es una categoría amplia que representa diferentes debilidades, expresadas como "diseño de control faltante o ineficaz". El diseño inseguro no es la fuente de todas las otras 10 categorías de riesgo principales. Existe una diferencia entre un diseño inseguro y una implementación insegura. Distinguimos entre fallas de diseño y defectos de implementación por una razón, tienen diferentes causas y soluciones. Un diseño seguro aún puede tener defectos de implementación que conduzcan a vulnerabilidades que pueden explotarse. Un diseño inseguro no se puede arreglar con una implementación perfecta ya que, por definición, los controles de seguridad necesarios nunca se crearon para defenderse de ataques específicos. Uno de los factores que contribuyen al diseño inseguro es la falta de perfiles de riesgo empresarial inherentes al software o sistema que se está desarrollando y, por lo tanto, la falta de determinación del nivel de diseño de seguridad que se requiere.

### Gestión de requerimientos y recursos

Recopile y negocie los requerimientos comerciales para una aplicación con la empresa, incluidos los requisitos de protección relacionados con la confidencialidad, integridad, disponibilidad y autenticidad de todos los activos de datos y la lógica de negocio esperada. Tenga en cuenta qué tan expuesta estará su aplicación y si necesita segregación de tenants (además del control de acceso). Compile los requisitos técnicos, incluidos los requerimientos de seguridad funcionales y no funcionales. Planifique y negocie el presupuesto que cubra todo el diseño, construcción, prueba y operación, incluidas las actividades de seguridad.

### Secure Design

Secure design is a culture and methodology that constantly evaluates threats and ensures that code is robustly designed and tested to prevent known attack methods. Threat modeling should be integrated into refinement sessions (or similar activities); look for changes in data flows and access control or other security controls. In the user story development determine the correct flow and failure states, ensure they are well understood and agreed upon by responsible and impacted parties. Analyze assumptions and conditions for expected and failure flows, ensure they are still accurate and desirable. Determine how to validate the assumptions and enforce conditions needed for proper behaviors. Ensure the results are documented in the user story. Learn from mistakes and offer positive incentives to promote improvements. Secure design is neither an add-on nor a tool that you can add to software.

### Ciclo de Vida de Desarrollo Seguro (S-SDLC)

El software seguro requiere un ciclo de vida de desarrollo seguro, alguna forma de patrón de diseño seguro, metodologías "Paved Road", biblioteca de componentes seguros, herramientas y modelado de amenazas. Comuníquese con sus especialistas en seguridad al comienzo de un proyecto de software durante todo el proyecto y el mantenimiento de su software. Considere aprovechar el [Modelo de madurez de garantía de software de OWASP (SAMM)](https://owaspsamm.org) para ayudar a estructurar sus esfuerzos de desarrollo de software seguro.

## Cómo prevenir

- Establezca y use un ciclo de vida de desarrollo seguro con Aplicaciones de Seguridad profesionales para ayudar a evaluar y diseñar la seguridad y controles relacionados con la privacidad.

- Establecer y utilizar una biblioteca de patrones de diseño seguros o componentes de "Paved Road"

- Utilice el modelado de amenazas para autenticación crítica, control de acceso, lógica empresarial y flujos clave.

- Integre el lenguaje y los controles de seguridad en las "historias de usuario".

- Integre verificaciones de plausibilidad en cada nivel de su aplicación (de frontend a backend)

- Escribir pruebas de integración y pruebas unitarias para validar que todos los flujos críticos son resistentes al modelo de amenazas. Compilar casos de uso *y* casos de uso indebido para cada nivel de su aplicación.

- Separe las capas de niveles en el sistema y las capas de red según las necesidades de exposición y protección.

- Separe a los tenants de manera robusta por diseño en todos los niveles.

- Limitar el consumo de recursos por usuario o servicio.

## Ejemplos de Escenarios de Ataque

**Escenario N° 1:**

Un flujo de trabajo de recuperación de credenciales puede incluir "preguntas y respuestas", lo cual está prohibido por NIST 800-63b, OWASP ASVS y OWASP Top 10. No se puede confiar en preguntas y respuestas como evidencia de identidad como más de una persona puede conocer las respuestas, por lo que están prohibidas. Dicho código debe eliminarse y reemplazarse por un diseño más seguro.

**Escenario N° 2:** 

Una cadena de cines permite descuentos en la reserva de grupos y tiene un máximo de quince asistentes antes de solicitar un depósito. Los atacantes podrían modelar este flujo y probar si podían reservar seiscientos asientos y todos los cines a la vez en unas pocas solicitudes, lo que provocaría una pérdida masiva de ingresos.

**Escenario N° 3:** 

El sitio web de comercio electrónico de una cadena minorista no tiene protección contra bots administrados por revendedores que compran tarjetas de video de alta gama para revender sitios web de subastas. Esto crea una publicidad terrible para los fabricantes de tarjetas de video y los propietarios de cadenas minoristas y una mala sangre duradera con
entusiastas que no pueden obtener estas tarjetas a ningún precio. El diseño cuidadoso de anti-bot y las reglas de lógica de dominio, como las compras realizadas a los pocos segundos de disponibilidad, pueden identificar compras no auténticas y rechazar dichas transacciones.

## Referencias

- Hoja de referencia de OWASP: Principios de diseño seguro (Próximamente)

- [OWASP SAMM: Diseño: Arquitectura de seguridad](https://owaspsamm.org/model/design/security-architecture/)

- [OWASP SAMM: Diseño: Evaluación de amenazas](https://owaspsamm.org/model/design/threat-assessment/)

- [NIST - Directrices sobre estándares mínimos para la verificación de software por parte de desarrolladores](https://www.nist.gov/system/files/documents/2021/07/13/Developer%20Verification%20of%20Software.pdf)

- [El manifiesto de modelado de amenazas](https://threatmodelingmanifesto.org)

- [Increíble modelado de amenazas](https://github.com/hysnsec/awesome-threat-modelling)

## Lista de CWE mapeadas

[CWE-73 Control externo de nombre de archivo o ruta](https://cwe.mitre.org/data/definitions/73.html)

[Lista permisiva de entradas permitidas CWE-183](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generación de mensaje de error que contiene información confidencial](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposición de información confidencial debido a políticas incompatibles](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Manejo inadecuado de parámetros adicionales](https://cwe.mitre.org/data/definitions/235.html)

[Almacenamiento de credenciales sin protección CWE-256](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Almacenamiento de contraseñas en un formato recuperable](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Asignación de privilegios incorrecta](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Gestión inadecuada de privilegios](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Manejo inadecuado de permisos o privilegios insuficientes](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Falta encriptación de datos confidenciales](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Almacenamiento de texto sin cifrar de información confidencial](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Almacenamiento de texto sin cifrar en un archivo o en un disco](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Almacenamiento de texto sin cifrar de información confidencial en la memoria](https://cwe.mitre.org/data/definitions/316.html)

[Canal principal desprotegido CWE-419](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Implementación de un controlador incorrecto](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Carga sin restricciones de archivo con tipo peligroso](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Interpretación inconsistente de solicitudes HTTP ('Contrabando de solicitudes HTTP')](https://cwe.mitre.org/data/definitions/444.html)

[Interfaz de usuario (UI) CWE-451 Tergiversación de información crítica](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 Control externo de parámetro web supuestamente inmutable](https://cwe.mitre.org/data/definitions/472.html)

[Violación de los límites de confianza de CWE-501](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Credenciales insuficientemente protegidas](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Uso de la caché del navegador web que contiene información confidencial](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Uso de cookies persistentes que contienen información confidencial](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Objeto no serializable almacenado en la sesión](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Uso del método de solicitud GET con cadenas de consulta sensibles](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Cumplimiento de la seguridad del lado del servidor en el lado del cliente](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 Control externo de datos de estado crítico](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Dependencia del nombre del archivo o la extensión del archivo suministrado externamente](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Confianza en los métodos de permisos HTTP en el lado del servidor](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Compartimentación insuficiente](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Confianza en la seguridad a través de la oscuridad](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violación de los principios de diseño seguro](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Control inadecuado de la frecuencia de interacción](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Dependencia de entradas no confiables en una decisión de seguridad](https://cwe.mitre.org/data/definitions/807.html)

[Errores de lógica empresarial CWE-840](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Aplicación inadecuada del flujo de trabajo conductual](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Uso de intención implícita para comunicación sensible](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Restricción inadecuada de capas o marcos de IU renderizados](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Uso inadecuado del marco de validación](https://cwe.mitre.org/data/definitions/1173.html)