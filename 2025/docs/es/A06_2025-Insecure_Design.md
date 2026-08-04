# A06:2025 – Diseño Inseguro   ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## Antecedentes

Diseño Inseguro baja dos posiciones del #4 al #6 en el ranking, ya que **[A02:2025-Configuración de Seguridad Incorrecta](A02_2025-Security_Misconfiguration.md)** y **[A03:2025-Fallas en la Cadena de Suministro de Software](A03_2025-Software_Supply_Chain_Failures.md)** la superan. Esta categoría fue introducida en 2021 y hemos observado mejoras notables en la industria relacionadas con el modelado de amenazas y un mayor énfasis en el diseño seguro. Esta categoría se enfoca en los riesgos relacionados con fallas de diseño y arquitectura, con un llamado a un mayor uso de modelado de amenazas, patrones de diseño seguros y arquitecturas de referencia. Esto incluye fallas en la lógica de negocio de una aplicación, por ejemplo, la falta de definición de cambios de estado no deseados o inesperados dentro de una aplicación. Como comunidad, necesitamos ir más allá del "desplazamiento a la izquierda" en el espacio de codificación, hacia actividades previas al código, como la redacción de requisitos y el diseño de aplicaciones, que son fundamentales para los principios de Seguridad por Diseño (ver **[Establecer un Programa Moderno de AppSec: Fase de Planificación y Diseño](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**). Las Enumeraciones de Debilidades Comunes (CWE) notables incluyen *CWE-256: Almacenamiento Desprotegido de Credenciales, CWE-269: Gestión Incorrecta de Privilegios, CWE-434: Subida sin Restricciones de Archivos de Tipo Peligroso, CWE-501: Violación de Límites de Confianza y CWE-522: Credenciales Insuficientemente Protegidas.*

## Tabla de Puntuación

<table>
  <tr>
   <td>CWEs Mapeadas</td>
   <td>Tasa de Incidencia Máx</td>
   <td>Tasa de Incidencia Prom</td>
   <td>Cobertura Máx</td>
   <td>Cobertura Prom</td>
   <td>Explotabilidad Ponderada Prom</td>
   <td>Impacto Ponderado Prom</td>
   <td>Incidencias Totales</td>
   <td>Total CVEs</td>
  </tr>
  <tr>
   <td>39</td>
   <td>22.18%</td>
   <td>1.86%</td>
   <td>88.76%</td>
   <td>35.18%</td>
   <td>6.96</td>
   <td>4.05</td>
   <td>729,882</td>
   <td>7,647</td>
  </tr>
</table>

## Descripción

El diseño inseguro es una categoría amplia que representa diferentes debilidades, expresadas como "diseño de control faltante o ineficaz". El diseño inseguro no es la fuente de las otras 10 categorías. Existe una diferencia entre un diseño inseguro y una implementación insegura. Distinguimos entre fallas de diseño y defectos de implementación por un motivo, difieren en la causa raíz y remediaciones. Incluso un diseño seguro puede tener defectos de implementación que conduzcan a vulnerabilidades que pueden explotarse. Un diseño inseguro no se puede arreglar con una implementación perfecta, ya que, por definición, los controles de seguridad necesarios nunca se crearon para defenderse de ataques específicos. Uno de los factores que contribuye al diseño inseguro es la falta de perfiles de riesgo empresarial inherentes al software o sistema en desarrollo y, por lo tanto, la falta de determinación del nivel de diseño de seguridad que se requiere.

Los tres componentes clave de un diseño seguro son:

* Recopilación de Requisitos y Gestión de Recursos
* Creación de un Diseño Seguro
* Contar con un Ciclo de Vida de Desarrollo Seguro

### Gestión de requerimientos y recursos

Recopile y negocie los requisitos de negocio de la aplicación con las partes interesadas, incluidos los requisitos de protección relacionados con la confidencialidad, integridad, disponibilidad y autenticidad de todos los activos de datos y la lógica de negocio esperada. Tenga en cuenta qué tan expuesta estará su aplicación y si necesita segregación de funcionalidades (además del control de acceso). Recopile los requerimientos técnicos, incluidos los funcionales de seguridad y los no funcionales. Planifique y negocie que el presupuesto cubra el diseño, construcción, prueba y operación, incluyendo las actividades de seguridad.

### Diseño seguro

El diseño seguro es una cultura y metodología que evalúa constantemente las amenazas y garantiza que el código esté diseñado y probado de manera sólida para prevenir métodos de ataque conocidos. El modelado de amenazas debe estar integrado en sesiones de refinamiento (o actividades similares); buscar cambios en los flujos de datos y el control de acceso u otros controles de seguridad. Durante la creación de las historias de usuario, determine el flujo correcto y los estados de falla. Asegúrese de que sean bien entendidos y acordados por las partes responsables e impactadas. Analice las suposiciones y las condiciones para los flujos esperados y de falla, asegúrese de que aún sean precisos y deseables. Determine cómo validar las suposiciones y hacer cumplir las condiciones necesarias para los comportamientos adecuados. Asegúrese de que los resultados estén documentados en las historias de usuario. Aprenda de los errores y ofrezca incentivos positivos para promover mejoras. El diseño seguro no es un complemento ni una herramienta que pueda agregar al software.

### Ciclo de Desarrollo Seguro (S-SDLC)

El software seguro requiere un ciclo de vide de desarrollo seguro, un patrón de diseño seguro, una metodología de carretera pavimentada ("paved road"), bibliotecas de componentes seguros, herramientas y modelado de amenazas. Comuníquese con sus especialistas en seguridad desde el comienzo y durante todo el proyecto, así como durante su fase de mantenimiento. Considere aprovechar el [Modelo de Madurez para el Aseguramiento del Software (SAMM)](https://owaspsamm.org) para ayudar a estructurar sus esfuerzos de desarrollo de software seguro.

A menudo se subestima la autorresponsabilidad de los desarrolladores. Fomente una cultura de conciencia, responsabilidad y mitigación proactiva de riesgos. Los intercambios regulares sobre seguridad (por ejemplo, durante sesiones de modelado de amenazas) pueden generar una mentalidad para incluir la seguridad en todas las decisiones de diseño importantes.

## Cómo se previene

* Establezca y use un ciclo de vida de desarrollo seguro apoyado en Profesionales en Seguridad de Aplicaciones para ayudarlo a evaluar y diseñar la seguridad y controles relacionados con la privacidad
* Establezca y utilice un catálogo de patrones de diseño seguros o componentes de "camino pavimentado" listos para ser utilizados
* Utilice el modelado de amenazas para flujos críticos de autenticación, control de acceso, lógica de negocio y todo clave
* Use el modelado de amenazas como herramienta educativa para generar una mentalidad de seguridad
* Integre el lenguaje y los controles de seguridad en las historias de usuario
* Integre verificaciones de viabilidad en cada capa de su aplicación (desde el frontend al backend)
* Escriba pruebas unitarias y de integración para validar que todos los flujos críticos son resistentes al modelo de amenazas. Recopile casos de uso *y* casos de mal uso para cada capa de la aplicación.
* Separe las capas del sistema y las capas de red según las necesidades de exposición y protección
* Separe a los tenants de manera robusta por diseño en todos los niveles

## Ejemplos de Escenarios de Ataque

**Escenario #1:** Un flujo de trabajo de recuperación de credenciales podría incluir "preguntas y respuestas", lo cual está prohibido por NIST 800-63b, OWASP ASVS y OWASP Top 10. Las preguntas y respuestas no pueden considerarse como evidencia de identidad, ya que más de una persona puede conocer las respuestas. Dicha funcionalidad debe eliminarse y reemplazarse con un diseño más seguro.

**Escenario #2:** Una cadena de cines permite descuentos en reservas grupales y tiene un máximo de quince asistentes antes de solicitar un depósito. Los atacantes podrían modelar este flujo y probar si pueden encontrar un vector de ataque en la lógica de negocio de la aplicación, por ejemplo, reservar seiscientos asientos en todos los cines a la vez en pocas solicitudes, causando una pérdida masiva de ingresos.

**Escenario #3:** El sitio web de comercio electrónico de una cadena minorista no tiene protección contra bots administrados por revendedores que compran tarjetas de video de alta gama para revender en sitios de subastas. Esto genera una publicidad terrible para los fabricantes de tarjetas de video y los dueños de la cadena minorista, así como un resentimiento duradero entre los entusiastas que no pueden obtener estas tarjetas a ningún precio. El diseño cuidadoso de medidas anti-bot y reglas de lógica de dominio, como compras realizadas a los pocos segundos de la disponibilidad, pueden identificar compras no auténticas y rechazar dichas transacciones.

## Referencias

* [Guía de referencia rápida de OWASP: Principios de Diseño Seguro](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Diseño | Arquitectura Segura](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Diseño | Evaluación de Amenazas](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Pautas sobre Estándares Mínimos para la Verificación de Software por Desarrolladores](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [El Manifiesto de Modelado de Amenazas](https://threatmodelingmanifesto.org/)
* [Asombroso Modelado de Amenazas](https://github.com/hysnsec/awesome-threat-modelling)

## Lista de CWEs Mapeadas

* [CWE-73 Control Externo del Nombre o Ruta de Archivo (External Control of File Name or Path)](https://cwe.mitre.org/data/definitions/73.html)

* [CWE-183 Lista Permisiva de Entradas Permitidas (Permissive List of Allowed Inputs)](https://cwe.mitre.org/data/definitions/183.html)

* [CWE-256 Almacenamiento Desprotegido de Credenciales (Unprotected Storage of Credentials)](https://cwe.mitre.org/data/definitions/256.html)

* [CWE-266 Asignación Incorrecta de Privilegios (Incorrect Privilege Assignment)](https://cwe.mitre.org/data/definitions/266.html)

* [CWE-269 Gestión Incorrecta de Privilegios (Improper Privilege Management)](https://cwe.mitre.org/data/definitions/269.html)

* [CWE-286 Gestión Incorrecta de Usuarios (Incorrect User Management)](https://cwe.mitre.org/data/definitions/286.html)

* [CWE-311 Falta de Cifrado de Datos Sensibles (Missing Encryption of Sensitive Data)](https://cwe.mitre.org/data/definitions/311.html)

* [CWE-312 Almacenamiento en Texto Claro de Información Sensible (Cleartext Storage of Sensitive Information)](https://cwe.mitre.org/data/definitions/312.html)

* [CWE-313 Almacenamiento en Texto Claro en un Archivo o en Disco (Cleartext Storage in a File or on Disk)](https://cwe.mitre.org/data/definitions/313.html)

* [CWE-316 Almacenamiento en Texto Claro de Información Sensible en Memoria (Cleartext Storage of Sensitive Information in Memory)](https://cwe.mitre.org/data/definitions/316.html)

* [CWE-362 Ejecución Concurrente Usando un Recurso Compartido con Sincronización Incorrecta ('Condición de Carrera') (Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'))](https://cwe.mitre.org/data/definitions/362.html)

* [CWE-382 Malas Prácticas en J2EE: Uso de System.exit() (J2EE Bad Practices: Use of System.exit())](https://cwe.mitre.org/data/definitions/382.html)

* [CWE-419 Canal Principal Desprotegido (Unprotected Primary Channel)](https://cwe.mitre.org/data/definitions/419.html)

* [CWE-434 Subida sin Restricciones de Archivos de Tipo Peligroso (Unrestricted Upload of File with Dangerous Type)](https://cwe.mitre.org/data/definitions/434.html)

* [CWE-436 Conflicto de Interpretación (Interpretation Conflict)](https://cwe.mitre.org/data/definitions/436.html)

* [CWE-444 Interpretación Inconsistente de Solicitudes HTTP ('Contrabando de Solicitudes HTTP') (Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling'))](https://cwe.mitre.org/data/definitions/444.html)

* [CWE-451 Representación Incorrecta de Información Crítica en la Interfaz de Usuario (UI) (User Interface (UI) Misrepresentation of Critical Information)](https://cwe.mitre.org/data/definitions/451.html)

* [CWE-454 Inicialización Externa de Variables o Almacenes de Datos de Confianza (External Initialization of Trusted Variables or Data Stores)](https://cwe.mitre.org/data/definitions/454.html)

* [CWE-472 Control Externo de Parámetros Web Asumidos como Inmutables (External Control of Assumed-Immutable Web Parameter)](https://cwe.mitre.org/data/definitions/472.html)

* [CWE-501 Violación de Límites de Confianza (Trust Boundary Violation)](https://cwe.mitre.org/data/definitions/501.html)

* [CWE-522 Credenciales Insuficientemente Protegidas (Insufficiently Protected Credentials)](https://cwe.mitre.org/data/definitions/522.html)

* [CWE-525 Uso de Caché del Navegador Web que Contiene Información Sensible (Use of Web Browser Cache Containing Sensitive Information)](https://cwe.mitre.org/data/definitions/525.html)

* [CWE-539 Uso de Cookies Persistentes que Contienen Información Sensible (Use of Persistent Cookies Containing Sensitive Information)](https://cwe.mitre.org/data/definitions/539.html)

* [CWE-598 Uso del Método de Solicitud GET con Cadenas de Consulta Sensibles (Use of GET Request Method With Sensitive Query Strings)](https://cwe.mitre.org/data/definitions/598.html)

* [CWE-602 Forzamiento en el Lado del Cliente la Seguridad del Lado del Servidor (Client-Side Enforcement of Server-Side Security)](https://cwe.mitre.org/data/definitions/602.html)

* [CWE-628 Llamada a Función con Argumentos Especificados Incorrectamente (Function Call with Incorrectly Specified Arguments)](https://cwe.mitre.org/data/definitions/628.html)

* [CWE-642 Control Externo de Datos de Estado Crítico (External Control of Critical State Data)](https://cwe.mitre.org/data/definitions/642.html)

* [CWE-646 Confianza en el Nombre o Extensión de Archivo Suministrado Externamente (Reliance on File Name or Extension of Externally-Supplied File)](https://cwe.mitre.org/data/definitions/646.html)

* [CWE-653 Aislamiento o Compartimentación Inadecuado (Improper Isolation or Compartmentalization)](https://cwe.mitre.org/data/definitions/653.html)

* [CWE-656 Confianza en la Seguridad a través de la Oscuridad (Reliance on Security Through Obscurity)](https://cwe.mitre.org/data/definitions/656.html)

* [CWE-657 Violación de los Principios de Diseño Seguro (Violation of Secure Design Principles)](https://cwe.mitre.org/data/definitions/657.html)

* [CWE-676 Uso de Función Potencialmente Peligrosa (Use of Potentially Dangerous Function)](https://cwe.mitre.org/data/definitions/676.html)

* [CWE-693 Fallo del Mecanismo de Protección (Protection Mechanism Failure)](https://cwe.mitre.org/data/definitions/693.html)

* [CWE-799 Control Inadecuado de la Frecuencia de Interacción (Improper Control of Interaction Frequency)](https://cwe.mitre.org/data/definitions/799.html)

* [CWE-807 Confianza en Entradas No Confiables en una Decisión de Seguridad (Reliance on Untrusted Inputs in a Security Decision)](https://cwe.mitre.org/data/definitions/807.html)

* [CWE-841 Forzamiento Incorrecto del Flujo de Comportamiento (Improper Enforcement of Behavioral Workflow)](https://cwe.mitre.org/data/definitions/841.html)

* [CWE-1021 Restricción Incorrecta de Capas o Marcos de UI Renderizados (Improper Restriction of Rendered UI Layers or Frames)](https://cwe.mitre.org/data/definitions/1021.html)

* [CWE-1022 Uso de Enlace Web a un Destino No Confiable con Acceso window.opener (Use of Web Link to Untrusted Target with window.opener Access)](https://cwe.mitre.org/data/definitions/1022.html)

* [CWE-1125 Superficie de Ataque Excesiva (Excessive Attack Surface)](https://cwe.mitre.org/data/definitions/1125.html)
