# Siguientes Pasos

Por diseño, el OWASP Top 10 está intrínsecamente limitado a los diez riesgos más significativos. Cada OWASP Top 10 tiene riesgos "al límite" que se consideran detenidamente para su inclusión, pero que al final no pasaron el corte. Los otros riesgos fueron más prevalentes e impactantes.

Vale la pena esforzarse en identificar y remediar los siguientes tres problemas, ya sea para organizaciones que trabajan hacia un programa de seguridad de aplicaciones (AppSec) maduro, consultorías de seguridad o proveedores de herramientas que deseen ampliar la cobertura de sus ofertas.


## X01:2025 Falta de Resiliencia de la Aplicación

### Antecedentes

Este es un cambio de nombre de la Denegación de Servicio (Denial of Service) de 2021. Se le cambió el nombre porque describía un síntoma más que una causa raíz. Esta categoría se centra en CWEs que describen debilidades relacionadas con problemas de resiliencia. La puntuación de esta categoría estuvo muy cerca de A10:2025 - Manejo Inadecuado de Condiciones Excepcionales. Los CWE relevantes incluyen: *CWE-400 Consumo de Recursos No Controlado (Uncontrolled Resource Consumption), CWE-409 Manejo Inadecuado de Datos Altamente Comprimidos (Amplificación de Datos) (Improper Handling of Highly Compressed Data (Data Amplification)), CWE-674 Recursión No Controlada (Uncontrolled Recursion)* y *CWE-835 Bucle con Condición de Salida Inalcanzable ('Bucle Infinito') (Loop with Unreachable Exit Condition ('Infinite Loop'))*.


### Tabla de puntuación


<table>
  <tr>
   <td>CWEs Mapeados 
   </td>
   <td>Tasa de Incidencia Máxima
   </td>
   <td>Tasa de Incidencia Promedio
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Promedio
   </td>
   <td>Explotación Ponderada Promedio
   </td>
   <td>Impacto Ponderado Promedio
   </td>
   <td>Ocurrencias Totales
   </td>
   <td>CVEs Totales
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>20.05%
   </td>
   <td>4.55%
   </td>
   <td>86.01%
   </td>
   <td>41.47%
   </td>
   <td>7.92
   </td>
   <td>3.49
   </td>
   <td>865,066
   </td>
   <td>4,423
   </td>
  </tr>
</table>



### Descripción

Esta categoría representa una debilidad sistémica en la forma en que las aplicaciones responden al estrés, las fallas y los casos extremos de los que no pueden recuperarse. Cuando una aplicación no maneja, resiste o se recupera con elegancia de condiciones inesperadas, restricciones de recursos y otros eventos adversos, puede resultar fácilmente en problemas de disponibilidad (lo más común), pero también en corrupción de datos, divulgación de datos sensibles, fallas en cascada y/o elusión de controles de seguridad.

Además, [X02:2025 Fallas en la Gestión de Memoria](#x022025-memory-management-failures) también pueden provocar la falla de la aplicación o incluso de todo el sistema.

### Cómo prevenir 

Para prevenir este tipo de vulnerabilidad, debe diseñar sus sistemas para la falla y la recuperación.

* Añada límites, cuotas y funcionalidad de conmutación por error (failover), prestando especial atención a las operaciones que más recursos consumen.
* Identifique las páginas que consumen muchos recursos y planifique con antelación: Reduzca la superficie de ataque, especialmente no exponiendo "gadgets" y funciones innecesarias que requieran muchos recursos (por ejemplo, CPU, memoria) a usuarios desconocidos o no confiables.
* Realice una validación de entradas estricta con listas de permitidos (allow-lists) y limitaciones de tamaño, luego realice pruebas exhaustivas.
* Limite los tamaños de las respuestas y nunca envíe respuestas sin procesar al cliente (procéselas en el lado del servidor).
* Establezca por defecto un estado seguro/cerrado (nunca abierto), deniegue por defecto y realice una reversión (roll back) si hay un error.
* Evite llamadas síncronas bloqueantes en los hilos de solicitud (use asíncronas/no bloqueantes, establezca tiempos de espera (timeouts), límites de concurrencia, etc.).
* Pruebe cuidadosamente su funcionalidad de manejo de errores.
* Implemente patrones de resiliencia como interruptores (circuit breakers), mamparos (bulkheads), lógica de reintento (retry logic) y degradación elegante (graceful degradation).
* Realice pruebas de rendimiento y carga; añada ingeniería de caos (chaos engineering) si tiene el apetito de riesgo para ello.
* Implemente y diseñe arquitecturas con redundancia donde sea razonable y asequible.
* Implemente monitorización, observabilidad y alertas.
* Filtre las direcciones de remitente no válidas de acuerdo con RFC 2267.
* Bloquee botnets conocidas mediante huellas digitales (fingerprints), IPs o dinámicamente por comportamiento.
* Prueba de Trabajo (Proof-of-Work): inicie operaciones que consuman recursos en el lado del *atacante*, lo que no tiene grandes impactos en los usuarios normales pero afecta a los bots que intentan enviar una gran cantidad de solicitudes. Haga que la Prueba de Trabajo sea más difícil si la carga general del sistema aumenta, especialmente para los sistemas que son menos confiables o parecen ser bots.
* Limite el tiempo de sesión en el lado del servidor basándose en la inactividad y un tiempo de espera final.
* Limite el almacenamiento de información vinculada a la sesión.


### Escenarios de ataque de ejemplo

**Escenario #1:** Los atacantes consumen intencionadamente los recursos de la aplicación para provocar fallas en el sistema, lo que resulta en una denegación de servicio (Denial of Service). Esto podría ser el agotamiento de la memoria, el llenado del espacio en disco, la saturación de la CPU o la apertura de conexiones infinitas.

**Escenario #2:** Fuzzing de entrada que conduce a respuestas manipuladas que rompen la lógica de negocio de la aplicación.

**Escenario #3:** Los atacantes se centran en las dependencias de la aplicación, derribando APIs u otros servicios externos, y la aplicación no puede continuar.


### Referencias

* [OWASP Cheat Sheet: Denegación de Servicio](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [Mejores prácticas de ASP.NET Core (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resiliencia en microservicios: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Patrón Bulkhead (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [Marco de Ciberseguridad del NIST (CSF)](https://www.nist.gov/cyberframework)
* [Evite llamadas bloqueantes: Vuelva asíncrono en Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### Lista de CWEs Mapeados
* [CWE-73 Control Externo del Nombre o Ruta del Archivo (External Control of File Name or Path)](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Lista Permisiva de Entradas Permitidas (Permissive List of Allowed Inputs)](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Almacenamiento de Contraseña en Texto Plano (Plaintext Storage of a Password)](https://cwe.mitre.org/data/definitions/256.html)
* [CWE-266 Asignación Incorrecta de Privilegios (Incorrect Privilege Assignment)](https://cwe.mitre.org/data/definitions/266.html)
* [CWE-269 Gestión Inadecuada de Privilegios (Improper Privilege Management)](https://cwe.mitre.org/data/definitions/269.html)
* [CWE-286 Gestión de Usuarios Incorrecta (Incorrect User Management)](https://cwe.mitre.org/data/definitions/286.html)
* [CWE-311 Falta de Cifrado de Datos Sensibles (Missing Encryption of Sensitive Data)](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312 Almacenamiento de Información Sensible en Texto Claro (Cleartext Storage of Sensitive Information)](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-313 Almacenamiento en Texto Claro en un Archivo o en Disco (Cleartext Storage in a File or on Disk)](https://cwe.mitre.org/data/definitions/313.html)
* [CWE-316 Almacenamiento de Información Sensible en Texto Claro en Memoria (Cleartext Storage of Sensitive Information in Memory)](https://cwe.mitre.org/data/definitions/316.html)
* [CWE-362 Ejecución Concurrente utilizando un Recurso Compartido con Sincronización Inadecuada ('Condición de Carrera') (Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'))](https://cwe.mitre.org/data/definitions/362.html)
* [CWE-382 Malas Prácticas de J2EE: Uso de System.exit() (J2EE Bad Practices: Use of System.exit())](https://cwe.mitre.org/data/definitions/382.html)
* [CWE-419 Canal Primario No Protegido (Unprotected Primary Channel)](https://cwe.mitre.org/data/definitions/419.html)
* [CWE-434 Carga sin Restricciones de Archivos con un Tipo Peligroso (Unrestricted Upload of File with Dangerous Type)](https://cwe.mitre.org/data/definitions/434.html)
* [CWE-436 Conflicto de Interpretación (Interpretation Conflict)](https://cwe.mitre.org/data/definitions/436.html)
* [CWE-444 Interpretación Inconsistente de Solicitudes HTTP ('HTTP Request/Response Smuggling') (Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling'))](https://cwe.mitre.org/data/definitions/444.html)
* [CWE-451 Tergiversación de Información Crítica en la Interfaz de Usuario (UI) (User Interface (UI) Misrepresentation of Critical Information)](https://cwe.mitre.org/data/definitions/451.html)
* [CWE-454 Inicialización Externa de Variables Confiables o Almacenes de Datos (External Initialization of Trusted Variables or Data Stores)](https://cwe.mitre.org/data/definitions/454.html)
* [CWE-472 Control Externo de un Parámetro Web Supuestamente Inmutable (External Control of Assumed-Immutable Web Parameter)](https://cwe.mitre.org/data/definitions/472.html)
* [CWE-501 Violación del Límite de Confianza (Trust Boundary Violation)](https://cwe.mitre.org/data/definitions/501.html)
* [CWE-522 Credenciales Insuficientemente Protegidas (Insufficiently Protected Credentials)](https://cwe.mitre.org/data/definitions/522.html)
* [CWE-525 Uso de la Caché del Navegador Web que Contiene Información Sensible (Use of Web Browser Cache Containing Sensitive Information)](https://cwe.mitre.org/data/definitions/525.html)
* [CWE-539 Uso de Cookies Persistentes que Contienen Información Sensible (Use of Persistent Cookies Containing Sensitive Information)](https://cwe.mitre.org/data/definitions/539.html)
* [CWE-598 Uso del Método de Solicitud GET con Cadenas de Consulta Sensibles (Use of GET Request Method With Sensitive Query Strings)](https://cwe.mitre.org/data/definitions/598.html)
* [CWE-602 Ejecución en el Lado del Cliente de la Seguridad del Lado del Servidor (Client-Side Enforcement of Server-Side Security)](https://cwe.mitre.org/data/definitions/602.html)
* [CWE-628 Llamada a Función con Argumentos Especificados Incorrectamente (Function Call with Incorrectly Specified Arguments)](https://cwe.mitre.org/data/definitions/628.html)
* [CWE-642 Control Externo de Datos de Estado Críticos (External Control of Critical State Data)](https://cwe.mitre.org/data/definitions/642.html)
* [CWE-646 Dependencia en el Nombre o Extensión de un Archivo Suministrado Externamente (Reliance on File Name or Extension of Externally-Supplied File)](https://cwe.mitre.org/data/definitions/646.html)
* [CWE-653 Aislamiento o Compartimentación Inadecuados (Improper Isolation or Compartmentalization)](https://cwe.mitre.org/data/definitions/653.html)
* [CWE-656 Dependencia en la Seguridad por Oscuridad (Reliance on Security Through Obscurity)](https://cwe.mitre.org/data/definitions/656.html)
* [CWE-657 Violación de los Principios de Diseño Seguro (Violation of Secure Design Principles)](https://cwe.mitre.org/data/definitions/657.html)
* [CWE-676 Uso de una Función Potencialmente Peligrosa (Use of Potentially Dangerous Function)](https://cwe.mitre.org/data/definitions/676.html)
* [CWE-693 Falla del Mecanismo de Protección (Protection Mechanism Failure)](https://cwe.mitre.org/data/definitions/693.html)
* [CWE-799 Control Inadecuado de la Frecuencia de Interacción (Improper Control of Interaction Frequency)](https://cwe.mitre.org/data/definitions/799.html)
* [CWE-807 Dependencia en Entradas No Confiables en una Decisión de Seguridad (Reliance on Untrusted Inputs in a Security Decision)](https://cwe.mitre.org/data/definitions/807.html)
* [CWE-841 Ejecución Inadecuada del Flujo de Trabajo de Comportamiento (Improper Enforcement of Behavioral Workflow)](https://cwe.mitre.org/data/definitions/841.html)
* [CWE-1021 Restricción Inadecuada de Capas o Marcos de la Interfaz de Usuario Renderizados (Improper Restriction of Rendered UI Layers or Frames)](https://cwe.mitre.org/data/definitions/1021.html)
* [CWE-1022 Uso de un Enlace Web a un Destino No Confiable con Acceso a window.opener (Use of Web Link to Untrusted Target with window.opener Access)](https://cwe.mitre.org/data/definitions/1022.html)
* [CWE-1125 Superficie de Ataque Excesiva (Excessive Attack Surface)](https://cwe.mitre.org/data/definitions/1125.html)


## X02:2025 Fallas en la Gestión de Memoria

### Antecedentes

Lenguajes como Java, C#, JavaScript/TypeScript (node.js), Go y Rust "seguro" (safe) son seguros en memoria (memory safe). Los problemas de manejo de memoria suelen ocurrir en lenguajes no seguros en memoria, como C y C++. Esta categoría obtuvo la puntuación más baja en la encuesta de la comunidad y baja en los datos, a pesar de tener el tercer mayor número de CVE relacionados. Creemos que esto se debe al predominio de las aplicaciones web sobre las aplicaciones de escritorio más tradicionales. Las vulnerabilidades de manejo de memoria suelen tener las puntuaciones CVSS más altas.


### Tabla de puntuación


<table>
  <tr>
   <td>CWEs Mapeados 
   </td>
   <td>Tasa de Incidencia Máxima
   </td>
   <td>Tasa de Incidencia Promedio
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Promedio
   </td>
   <td>Explotación Ponderada Promedio
   </td>
   <td>Impacto Ponderado Promedio
   </td>
   <td>Ocurrencias Totales
   </td>
   <td>CVEs Totales
   </td>
  </tr>
  <tr>
   <td>24
   </td>
   <td>2.96%
   </td>
   <td>1.13%
   </td>
   <td>55.62%
   </td>
   <td>28.45%
   </td>
   <td>6.75
   </td>
   <td>4.82
   </td>
   <td>220,414
   </td>
   <td>30,978
   </td>
  </tr>
</table>



### Descripción

Cuando una aplicación se ve obligada a gestionar la memoria por sí misma, es muy fácil cometer errores. Los lenguajes seguros en memoria se utilizan cada vez más, pero todavía hay muchos sistemas heredados (legacy) en producción en todo el mundo, nuevos sistemas de bajo nivel que requieren el uso de lenguajes no seguros en memoria y aplicaciones web que interactúan con mainframes, dispositivos IoT, firmware y otros sistemas que pueden verse obligados a gestionar su propia memoria. Los CWE representativos son el *CWE-120 Copia de Búfer sin Comprobar el Tamaño de la Entrada ('Desbordamiento de Búfer Clásico') (Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'))* y el *CWE-121 Desbordamiento de Búfer basado en Pila (Stack-based Buffer Overflow)*.

Las fallas en el manejo de memoria pueden ocurrir cuando:

* No se asigna suficiente memoria para una variable.
* No se valida la entrada, lo que provoca un desbordamiento del montón (heap), la pila (stack) o un búfer.
* Se almacena un valor de datos que es mayor de lo que el tipo de variable puede contener.
* Se intenta utilizar memoria o espacios de direcciones no asignados.
* Se crean errores por uno (off-by-one errors) (contar desde 1 en lugar de desde cero).
* Se intenta acceder a un objeto después de haber sido liberado.
* Se utilizan variables no inicializadas.
* Se producen fugas de memoria (memory leaks) o se agota de otro modo toda la memoria disponible por error hasta que la aplicación falla.

Las fallas en el manejo de memoria pueden provocar la falla de la aplicación o incluso de todo el sistema, consulte también [X01:2025 Falta de Resiliencia de la Aplicación](#x012025-lack-of-application-resilience).


### Cómo prevenir

La mejor manera de prevenir las fallas en el manejo de memoria es utilizar un lenguaje seguro en memoria (memory-safe). Los ejemplos incluyen Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript, etc. Al crear nuevas aplicaciones, intente convencer a su organización de que vale la pena la curva de aprendizaje para cambiar a un lenguaje seguro en memoria. Si se realiza una refactorización completa, presione para una reescritura en un lenguaje seguro en memoria cuando sea posible y factible.

Si no puede utilizar un lenguaje seguro en memoria, realice lo siguiente:

* Habilite las siguientes características del servidor que dificultan la explotación de los errores de manejo de memoria: aleatorización del diseño del espacio de direcciones (ASLR), protección de ejecución de datos (DEP) y protección contra la sobrescritura del manejo de excepciones estructuradas (SEHOP).
* Supervise su aplicación en busca de fugas de memoria.
* Valide cuidadosamente todas las entradas a su sistema y rechace cualquier entrada que no cumpla con las expectativas.
* Estudie el lenguaje que está utilizando y haga una lista de las funciones inseguras y las más seguras, luego comparta esa lista con todo su equipo. Si es posible, añádala a su guía o estándar de codificación segura. Por ejemplo, en C, prefiera strncpy() sobre strcpy() y strncat() sobre strcat().
* Si su lenguaje o entorno de trabajo (framework) ofrece librerías de seguridad de memoria, úselas. Por ejemplo: Safestringlib o SafeStr.
* Utilice búferes y cadenas gestionados en lugar de matrices (arrays) y punteros brutos siempre que sea posible.
* Realice una formación en codificación segura que se centre en los problemas de memoria y/o en el lenguaje de su elección. Informe a su instructor que le preocupan las fallas en el manejo de memoria.
* Realice revisiones de código y/o análisis estáticos.
* Utilice herramientas del compilador que ayuden con la gestión de la memoria, como StackShield, StackGuard y Libsafe.
* Realice pruebas de fuzzing en cada entrada de su sistema.
* Si realiza una prueba de penetración, informe a su evaluador que le preocupan las fallas en el manejo de memoria y que le gustaría que prestara especial atención a esto durante las pruebas.
* Corrija todos los errores *y* advertencias del compilador. No ignore las advertencias solo porque su programa se compile.
* Asegúrese de que su infraestructura subyacente se parchea, escanea y robustece (hardened) regularmente.
* Supervise su infraestructura subyacente específicamente para detectar posibles vulnerabilidades de memoria y otros fallas.
* Considere el uso de [canarios](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) para proteger su pila de direcciones de los ataques de desbordamiento.

### Escenarios de ataque de ejemplo

**Escenario #1:** Los desbordamientos de búfer (buffer overflows) son la vulnerabilidad de memoria más famosa, una situación en la que un atacante envía más información a un campo de la que puede aceptar, de modo que desborda el búfer creado para la variable subyacente. En un ataque exitoso, los caracteres de desbordamiento sobrescriben el puntero de la pila, permitiendo al atacante insertar instrucciones maliciosas en su programa.

**Escenario #2:** El uso después de la liberación (Use-After-Free (UAF)) ocurre con la frecuencia suficiente como para ser una entrega semi-común en programas de recompensas por errores (bug bounty) de navegadores. Imagine un navegador web que procesa JavaScript que manipula elementos DOM. El atacante diseña una carga útil de JavaScript que crea un objeto (como un elemento DOM) y obtiene referencias a él. A través de una manipulación cuidadosa, provocan que el navegador libere la memoria del objeto mientras mantienen un puntero colgante (dangling pointer) hacia él. Antes de que el navegador se dé cuenta de que la memoria ha sido liberada, el atacante asigna un nuevo objeto que ocupa el *mismo* espacio de memoria. Cuando el navegador intenta utilizar el puntero original, ahora apunta a datos controlados por el atacante. Si este puntero era para una tabla de funciones virtuales, el atacante puede redirigir la ejecución del código a su carga útil.

**Escenario #3:** Un servicio de red que acepta la entrada del usuario, no la valida ni sanea adecuadamente y luego la pasa directamente a la función de registro (logging). La entrada del usuario se pasa a la función de registro como `syslog(user_input)` en lugar de `syslog("%s", user_input)`, lo que no especifica el formato. El atacante envía cargas útiles maliciosas que contienen especificadores de formato como `%x` para leer la memoria de la pila (divulgación de datos sensibles) o `%n` para escribir en direcciones de memoria. Al encadenar múltiples especificadores de formato, podrían mapear la pila, localizar direcciones importantes y luego sobrescribirlas. Esto sería una vulnerabilidad de cadena de formato (Format string vulnerability) (formato de cadena no controlado).

Nota: los navegadores modernos utilizan muchos niveles de defensa para protegerse contra tales ataques, incluyendo el aislamiento de procesos del navegador (browser sandboxing), ASLR, DEP/NX, RELRO y PIE. Un ataque de falla en el manejo de memoria en un navegador no es un ataque sencillo de realizar.

### Referencias

* [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### Lista de CWEs Mapeados
* [CWE-14 Eliminación por el Compilador de Código para Limpiar Búferes (Compiler Removal of Code to Clear Buffers)](https://cwe.mitre.org/data/definitions/14.html)
* [CWE-119 Restricción Inadecuada de las Operaciones dentro de los Límites de un Búfer de Memoria (Improper Restriction of Operations within the Bounds of a Memory Buffer)](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 Copia de Búfer sin Comprobar el Tamaño de la Entrada ('Desbordamiento de Búfer Clásico') (Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'))](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 Desbordamiento de Búfer basado en Pila (Stack-based Buffer Overflow)](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 Desbordamiento de Búfer basado en Montón (Heap-based Buffer Overflow)](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-124 Subescritura de Búfer ('Subdesbordamiento de Búfer') (Buffer Underwrite ('Buffer Underflow'))](https://cwe.mitre.org/data/definitions/124.html)
* [CWE-125 Lectura Fuera de Límites (Out-of-bounds Read)](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-126 Sobrelectura de Búfer (Buffer Over-read)](https://cwe.mitre.org/data/definitions/126.html)
* [CWE-190 Desbordamiento de Enteros o Envolvimiento (Integer Overflow or Wraparound)](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-191 Subdesbordamiento de Enteros (Envolvimiento) (Integer Underflow (Wrap or Wraparound))](https://cwe.mitre.org/data/definitions/191.html)
* [CWE-196 Error de Conversión de Sin Signo a Con Signo (Unsigned to Signed Conversion Error)](https://cwe.mitre.org/data/definitions/196.html)
* [CWE-367 Condición de Carrera de Tiempo de Comprobación a Tiempo de Uso (TOCTOU) (Time-of-check Time-of-use (TOCTOU) Race Condition)](https://cwe.mitre.org/data/definitions/367.html)
* [CWE-415 Liberación Doble (Double Free)](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 Uso Después de la Liberación (Use After Free)](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-457 Uso de Variable No Inicializada (Use of Uninitialized Variable)](https://cwe.mitre.org/data/definitions/457.html)
* [CWE-459 Limpieza Incompleta (Incomplete Cleanup)](https://cwe.mitre.org/data/definitions/459.html)
* [CWE-467 Uso de sizeof() en un Tipo de Puntero (Use of sizeof() on a Pointer Type)](https://cwe.mitre.org/data/definitions/467.html)
* [CWE-787 Escritura Fuera de Límites (Out-of-bounds Write)](https://cwe.mitre.org/data/definitions/787.html)
* [CWE-788 Acceso a una Ubicación de Memoria Después del Final del Búfer (Access of Memory Location After End of Buffer)](https://cwe.mitre.org/data/definitions/788.html)
* [CWE-824 Acceso a un Puntero No Inicializado (Access of Uninitialized Pointer)](https://cwe.mitre.org/data/definitions/824.html)



## X03:2025 Confianza Inapropiada en el Código Generado por IA ('Vibe Coding')

### Antecedentes

Actualmente, todo el mundo habla y utiliza la IA, y esto incluye a los desarrolladores de software. Aunque actualmente no existen CVE o CWE relacionados con el código generado por IA, es bien sabido y está documentado que el código generado por IA a menudo contiene más vulnerabilidades que el código escrito por seres humanos.


### Descripción

Estamos viendo cómo cambian las prácticas de desarrollo de software para incluir no solo código escrito con la ayuda de la IA, sino código escrito y entregado casi por completo sin supervisión humana (a menudo denominado *vibe coding*). Así como nunca fue una buena idea copiar fragmentos de código de blogs o sitios web sin pensarlo dos veces, el problema se agrava en este caso. Los fragmentos de código buenos y seguros eran y son escasos, y la IA podría ignorarlos estadísticamente debido a las limitaciones del sistema.


### Cómo prevenir
Instamos a todas las personas que escriben código a que consideren lo siguiente cuando utilicen la IA:

* Debe ser capaz de leer y comprender completamente todo el código que envíe, incluso si ha sido escrito por una IA o copiado de un foro en línea. Usted es responsable de todo el código que entregue.
* Debe revisar a fondo todo el código asistido por IA en busca de vulnerabilidades, idealmente con sus propios ojos y también con herramientas de seguridad creadas para este fin (como el análisis estático). Considere el uso de técnicas clásicas de revisión de código como las descritas en [OWASP Cheat Sheet Series: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
* Idealmente, escriba su propio código, deje que la IA sugiera mejoras, verifique el código de la IA y deje que la IA haga correcciones hasta que esté satisfecho con el resultado.
* Considere el uso de un servidor de Generación Aumentada por Recuperación (RAG) con sus propias muestras de código seguro y documentación recopiladas y revisadas, como la guía, estándar o política de codificación de seguridad de su organización, y haga que el servidor RAG aplique cualquier política o estándar.
* Considere la compra de herramientas que implementen salvaguardas (guardrails) para la privacidad y la seguridad para su uso con la(s) IA(s) de su elección.
* Considere la compra de una IA privada, idealmente con un acuerdo contractual (incluyendo un acuerdo de privacidad) que estipule que la IA no debe ser entrenada con los datos, consultas, código o cualquier otra información sensible de su organización.
* Considere la implementación de un servidor de Protocolo de Contexto de Modelo (MCP) entre su IDE y la IA, y luego configúrelo para imponer el uso de su herramienta de seguridad preferida.
* Implemente políticas y procesos como parte de su SDLC para informar a los desarrolladores (y a todos los empleados) sobre cómo deben y no deben usar la IA dentro de su organización.
* Cree una lista de prompts (instrucciones) buenos y efectivos que tengan en cuenta las mejores prácticas de seguridad de TI. Idealmente, también deberían considerar sus pautas internas de codificación segura. Los desarrolladores pueden usar estos prompts como punto de partida para sus programas.
* Es probable que la IA se convierta en parte de cada fase del ciclo de vida de desarrollo de su sistema; aprenda cómo usarla de manera efectiva y segura. Úsela sabiamente.
* De hecho, **<u>no</u>** se recomienda utilizar *vibe coding* para funciones complejas, programas críticos para el negocio o programas que se utilicen durante mucho tiempo.
* Implemente comprobaciones técnicas y salvaguardas contra el uso de IA en la sombra (Shadow AI).
* Capacite a sus desarrolladores en sus políticas, así como en el uso seguro de la IA y las mejores prácticas para usar la IA en el desarrollo de software.


### Referencias

* [OWASP Cheat Sheet: Revisión de Código Seguro](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


### Lista de CWEs Mapeados
-ninguno-
