# A04:2021 – Diseño Inseguro   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png)

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Explotabilidad ponderada prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 6.46                 | 6.78                | 77.25%       | 42.51%       | 262,407           | 2,691      |

## Resumen

Una nueva categoría para 2021 se centra en los riesgos relacionados con el diseño y las fallas arquitectónicas, con un llamado a un mayor uso del modelado de amenazas, patrones de diseño seguros y arquitecturas de referencia. Como comunidad, debemos ir más allá de solo abandonar las metodologias tradicionales (movimiento "shift-left" en inglés) en el espacio de codificación para precodificar actividades que son críticas para los principios de Secure by Design. Los CWE notables incluidos son *CWE-209: Generación de mensaje de error que contiene información confidencial*, *CWE-256: Almacenamiento desprotegido de credenciales*, *CWE-501: Infracción de límites de confianza* y *CWE-522: Credenciales protegidas insuficientemente*.

## Descripción

El diseño inseguro es una categoría amplia que representa diferentes debilidades, expresadas como "diseño de control faltante o ineficaz". El diseño inseguro no es la fuente de todas las otras 10 categorías de riesgo principales. Existe una diferencia entre un diseño inseguro y una implementación insegura. Distinguimos entre fallas de diseño y defectos de implementación por una razón, tienen diferentes causas y soluciones. Un diseño seguro aún puede tener defectos de implementación que conduzcan a vulnerabilidades que pueden explotarse. Un diseño inseguro no se puede arreglar con una implementación perfecta ya que, por definición, los controles de seguridad necesarios nunca se crearon para defenderse de ataques específicos. Uno de los factores que contribuyen al diseño inseguro es la falta de perfiles de riesgo empresarial inherentes al software o sistema que se está desarrollando y, por lo tanto, la falta de determinación del nivel de diseño de seguridad que se requiere.

### Gestión de requerimientos y recursos

Recopile y negocie los requerimientos comerciales para una aplicación con la empresa, incluidos los requisitos de protección relacionados con la confidencialidad, integridad, disponibilidad y autenticidad de todos los activos de datos y la lógica de negocio esperada. Tenga en cuenta qué tan expuesta estará su aplicación y si necesita segregación de tenants (además del control de acceso). Compile los requisitos técnicos, incluidos los requerimientos de seguridad funcionales y no funcionales. Planifique y negocie el presupuesto que cubra todo el diseño, construcción, prueba y operación, incluidas las actividades de seguridad.

### Diseño seguro

El diseño seguro es una cultura y metodología que evalúa constantemente las amenazas y garantiza que el código esté diseñado y probado de manera sólida para prevenir métodos de ataque conocidos. El modelado de amenazas debe estar integrado en sesiones de refinamiento (o actividades similares); buscar cambios en los flujos de datos y el control de acceso u otros controles de seguridad. Durante el desarrollo de la historia de usuario, determine el flujo correcto y los estados de falla, asegúrese de que sean bien entendidos y acordados por las partes responsables e impactadas. Analice las suposiciones y las condiciones para los flujos esperados y de falla, asegúrese de que aún sean precisos y deseables. Determine cómo validar las suposiciones y hacer cumplir las condiciones necesarias para los comportamientos adecuados. Asegúrese de que los resultados estén documentados en la historia del usuario. Aprenda de los errores y ofrezca incentivos positivos para promover mejoras. El diseño seguro no es un complemento ni una herramienta que pueda agregar al software.

### Ciclo de Vida de Desarrollo Seguro (S-SDLC)

El software seguro requiere un ciclo de vida de desarrollo seguro, alguna forma de patrón de diseño seguro, metodologías "Paved Road", biblioteca de componentes seguros, herramientas y modelado de amenazas. Comuníquese con sus especialistas en seguridad al comienzo de un proyecto de software durante todo el proyecto y el mantenimiento de su software. Considere aprovechar el [Modelo de madurez de garantía de software de OWASP (SAMM)](https://owaspsamm.org) para ayudar a estructurar sus esfuerzos de desarrollo de software seguro.

## Cómo se previene

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

**Escenario #1:** Un flujo de trabajo de recuperación de credenciales puede incluir "preguntas y respuestas", lo cual está prohibido por NIST 800-63b, OWASP ASVS y OWASP Top 10. No se puede confiar en preguntas y respuestas como evidencia de identidad como más de una persona puede conocer las respuestas, por lo que están prohibidas. Dicho código debe eliminarse y reemplazarse por un diseño más seguro.

**Escenario #2:** Una cadena de cines permite descuentos en la reserva de grupos y tiene un máximo de quince asistentes antes de solicitar un depósito. Los atacantes podrían modelar este flujo y probar si podían reservar seiscientos asientos y todos los cines a la vez en unas pocas solicitudes, lo que provocaría una pérdida masiva de ingresos.

**Escenario #3:** El sitio web de comercio electrónico de una cadena minorista no tiene protección contra bots administrados por revendedores que compran tarjetas de video de alta gama para revender sitios web de subastas. Esto crea una publicidad terrible para los fabricantes de tarjetas de video y los propietarios de cadenas minoristas y una mala sangre duradera con
entusiastas que no pueden obtener estas tarjetas a ningún precio. El diseño cuidadoso de anti-bot y las reglas de lógica de dominio, como las compras realizadas a los pocos segundos de disponibilidad, pueden identificar compras no auténticas y rechazar dichas transacciones.

## Referencias

- Hoja de referencia de OWASP: Principios de diseño seguro (Próximamente)

- [OWASP SAMM: Diseño: Arquitectura de seguridad](https://owaspsamm.org/model/design/security-architecture/)

- [OWASP SAMM: Diseño: Evaluación de amenazas](https://owaspsamm.org/model/design/threat-assessment/)

- [NIST - Directrices sobre estándares mínimos para la verificación de software por parte de desarrolladores](https://www.nist.gov/system/files/documents/2021/07/13/Developer%20Verification%20of%20Software.pdf)

- [El manifiesto de modelado de amenazas](https://threatmodelingmanifesto.org)

- [Increíble modelado de amenazas](https://github.com/hysnsec/awesome-threat-modelling)

## Lista de CWEs mapeadas

[CWE-73 Control externo de nombre de archivo o ruta](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Lista permisiva de entradas permitidas](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generación de mensaje de error que contiene información confidencial](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposición de información confidencial debido a políticas incompatibles](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Manejo inadecuado de parámetros adicionales](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Almacenamiento de credenciales sin protección](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Almacenamiento de contraseñas en un formato recuperable](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Asignación de privilegios incorrecta](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Gestión inadecuada de privilegios](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Manejo inadecuado de permisos o privilegios insuficientes](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Falta encriptación de datos confidenciales](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Almacenamiento de texto sin cifrar de información confidencial](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Almacenamiento de texto sin cifrar en un archivo o en un disco](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Almacenamiento de texto sin cifrar de información confidencial en la memoria](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Canal principal desprotegido](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Implementación de un controlador incorrecto](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Carga sin restricciones de archivo con tipo peligroso](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Interpretación inconsistente de solicitudes HTTP ('Contrabando de solicitudes HTTP')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 Tergiversación de información crítica en la Interfaz de usuario(UI)](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 Control externo de parámetro web supuestamente inmutable](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Violación de los límites de confianza](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Credenciales insuficientemente protegidas](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Uso de la caché del navegador web que contiene información confidencial](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Uso de cookies persistentes que contienen información confidencial](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Malas prácticas: Objeto no serializable almacenado en la sesión](https://cwe.mitre.org/data/definitions/579.html)

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

[CWE-840 Errores de lógica empresarial](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Aplicación inadecuada del flujo de trabajo conductual](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Uso de intención implícita para comunicación sensible](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Restricción inadecuada de capas o marcos de IU renderizados](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Uso inadecuado del marco de validación](https://cwe.mitre.org/data/definitions/1173.html)
