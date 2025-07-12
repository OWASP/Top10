# A11:2021 – Siguientes pasos

Por diseño, el Top 10 de OWASP se limita a los diez riesgos más importantes. Cada Top 10 de OWASP tuvo riesgos "en el umbral" considerados detenidamente para su inclusión, pero al final, no lo fueron. No importando cuánto intentáramos interpretar o tergiversar los datos, los otros riesgos fueron más prevalentes e impactantes.

Para aquellas organizaciones que trabajan en pos de un programa de AppSec maduro, consultores de seguridad o proveedores de herramientas que deseen ampliar la cobertura de sus ofertas, vale la pena el esfuerzo de identificar y solucionar los siguientes tres problemas.
																														
## Problemas de calidad de código

| CWEs mapeadas  | Tasa de incidencia máx | Tasa de incidencia prom  | Explotabilidad ponderada prom  | Impacto ponderado prom | Cobertura máx  | Cobertura prom | Total de Incidencias   | Total de CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |
								
-   **Descripción.** Los problemas de calidad del código incluyen patrones o defectos de seguridad conocidos, reutilización de variables para múltiples propósitos, exposición de información sensible en la salida de depuración, errores por uno (off-by-one), condiciones de carrera de tiempo de verificación/tiempo de uso (TOC/TOU), errores de conversión firmados o no firmados, uso de memoria ya liberada y más. El sello distintivo de esta sección es que generalmente se pueden identificar con estrictas marcas de compilación, herramientas de análisis de código estático y complementos de IDE para análisis de tipo *lint*.
Los lenguajes modernos por diseño eliminaron muchos de estos problemas, como la propiedad de la memoria de Rust y el concepto de préstamo, el diseño de hilos de subproceso de Rust y la tipificación estricta y la verificación de límites de Go.

-   **Cómo se previene**. Habilite y use las opciones de análisis de código estático de su editor específico para cada lenguaje. Considere el uso de una herramienta de análisis de código estático.
Considere si fuera posible usar o migrar a un lenguaje o marco que elimine este tipo de errores, como Rust o Go.
	
-   **Ejemplos de escenarios de ataque**. Un atacante puede obtener o actualizar información confidencial aprovechando una condición de carrera utilizando una variable compartida estáticamente en varios subprocesos.		  

-   **Referencias**
  - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

  - [Google Code Review Guide](https://google.github.io/eng-practices/review/)

## Denegación de servicio

| CWEs mapeadas  | Tasa de incidencia máx  | Tasa de incidencia prom  | Explotabilidad ponderada prom  | Impacto ponderado prom  | Cobertura máx  | Cobertura prom  | Incidencias totales  | Total CVEs   |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |
					
-   **Descripción**. La denegación de servicio siempre es posible con suficientes recursos. Sin embargo, las prácticas de diseño y codificación tienen una influencia significativa en la magnitud de la denegación de servicio. Supongamos que cualquier persona con el enlace puede acceder a un archivo grande, o que se produce una transacción computacionalmente costosa en cada página. En ese caso, la denegación de servicio requiere menos esfuerzo para llevarse a cabo.

-   **Cómo se previene**. Realizar pruebas de rendimiento para el uso de CPU, E/S y memoria, rediseñar, optimizar o almacenar en caché las operaciones pesadas.
Considere los controles de acceso para objetos más grandes para asegurarse de que solo las personas autorizadas puedan acceder a archivos u objetos grandes o servirlos a través de una red de almacenamiento en caché perimetral.
																														 
-   **Ejemplos de escenarios de ataque**. Un atacante podría determinar que una operación tarda entre 5 y 10 segundos en completarse. Cuando se ejecutan cuatro subprocesos simultáneos, el servidor parece dejar de responder. El atacante entonces usa 1000 subprocesos y saca de servicio todo el sistema.

-   **Referencias**
  - [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

  - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Errores de administración de memoria
				  

| CWEs mapeadas  | Tasa de incidencia máx  | Tasa de incidencia prom  | Explotabilidad ponderada prom  | Impacto ponderado prom  | Cobertura máx  | Cobertura prom  | Incidencias totales  | Total CVEs  |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Descripción**. Las aplicaciones web usualmente se escriben en lenguajes de memoria administrada, como Java, .NET o Node.js (JavaScript o TypeScript). Sin embargo, estos lenguajes están escritos en lenguajes de sistema que tienen problemas de administración de memoria, como desbordamientos de búfer o de pila, uso de memoria luego de liberada, desbordamiento de números enteros y más. A lo largo de los años, han habido muchos escapes de espacio aislado (sandbox escapes) que demuestran que aunque el lenguaje de la aplicación web es nominalmente "seguro" para la memoria, la estructura de base no siempre lo es.				 

-   **Cómo se previene**. Muchas API modernas ahora están escritas en lenguajes seguros para la memoria como Rust o Go. En el caso de Rust, la seguridad de la memoria es una característica crucial del lenguaje. Para el código existente, el uso de banderas de compilador estrictas, fuerte tipado, análisis de código estático y pruebas de fuzzing puede ser beneficioso para identificar pérdidas de memoria, desbordamientos de matrices y memoria, y más.

-   **Ejemplos de escenarios de ataque**. Los desbordamientos de búfer y pila han sido un pilar de los atacantes a lo largo de los años. El atacante envía datos a un programa, que almacena en un búfer de pila de tamaño insuficiente. El resultado es que se sobrescribe la información de la pila de llamadas, incluido el puntero de retorno de la función. Los datos establecen el valor del puntero de retorno para que cuando la función regrese, transfiera el control al código malicioso contenido en los datos del atacante.

-   **Referencias**
  - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

  - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)

  - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
