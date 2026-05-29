![Logotipo de OWASP](../assets/TOP_10_logo_Final_Logo_Colour.png)

# Los Diez Riesgos de Seguridad de Aplicaciones Web Más Críticos

# Introducción

¡Bienvenidos a la octava edición del OWASP Top Ten!

Un enorme agradecimiento a todos los que contribuyeron con datos y perspectivas en la encuesta. Sin ustedes, esta edición no habría sido posible. **¡GRACIAS!**


## Presentación del OWASP Top 10:2025



* [A01:2025 - Pérdida de Control de Acceso](A01_2025-Perdida_de_Control_de_Acceso.md)
* [A02:2025 - Configuración de Seguridad Incorrecta](A02_2025-Configuracion_de_Seguridad_Incorrecta.md)
* [A03:2025 - Fallas en la Cadena de Suministro de Software](A03_2025-Fallas_en_la_Cadena_de_Suministro_de_Software.md)
* [A04:2025 - Fallas Criptográficas](A04_2025-Fallas_Criptograficas.md)
* [A05:2025 - Inyección](A05_2025-Inyeccion.md)
* [A06:2025 - Diseño Inseguro](A06_2025-Diseno_Inseguro.md)
* [A07:2025 - Fallas de Autenticación](A07_2025-Fallas_de_Autenticacion.md)
* [A08:2025 - Fallas en la Integridad del Software o de los Datos](A08_2025-Fallas_en_la_Integridad_del_Software_y_de_los_Datos.md)
* [A09:2025 - Fallas en el Registro, Alerta y Monitoreo de Seguridad](A09_2025-Fallas_en_el_Registro_y_Monitoreo.md)
* [A10:2025 - Manejo Inadecuado de Condiciones Excepcionales](A10_2025-Manejo_Inadecuado_de_Condiciones_Excepcionales.md)


## Qué ha cambiado en el Top 10 para 2025

Hay dos categorías nuevas y una consolidación en el Top Ten para 2025. Hemos trabajado para mantener nuestro enfoque en la causa raíz por encima de los síntomas tanto como ha sido posible. Debido a la complejidad de la ingeniería de software y la seguridad del software, es básicamente imposible crear diez categorías sin algún nivel de solapamiento.

![Mapeo](../assets/2025-mappings.png)

* **[A01:2025 - Pérdida de Control de Acceso](A01_2025-Perdida_de_Control_de_Acceso.md)** mantiene su posición en el #1 como el riesgo de seguridad de aplicaciones más grave; los datos aportados indican que, de media, el 3,73% de las aplicaciones analizadas presentaban una o más de las 40 Enumeraciones de Debilidades Comunes (CWE, por sus siglas en inglés: *Common Weakness Enumerations*) en esta categoría. Como indica la línea discontinua en la figura anterior, la Falsificación de Solicitudes del Lado del Servidor (SSRF, *Server-Side Request Forgery*) se ha integrado en esta categoría.
* **[A02:2025 - Configuración de Seguridad Incorrecta](A02_2025-Configuracion_de_Seguridad_Incorrecta.md)** subió del #5 en 2021 al #2 en 2025. Las configuraciones incorrectas son más prevalentes en los datos de este ciclo. El 3,00% de las aplicaciones analizadas tenían una o más de las 16 CWE en esta categoría. Esto no es sorprendente, ya que la ingeniería de software sigue aumentando la cantidad de comportamiento de una aplicación que se basa en configuraciones.
* **[A03:2025 - Fallas en la Cadena de Suministro de Software](A03_2025-Fallas_en_la_Cadena_de_Suministro_de_Software.md)** es una expansión de [A06:2021 - Componentes Vulnerables y Desactualizados](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) para incluir un alcance más amplio de compromisos que ocurren dentro o a través de todo el ecosistema de dependencias de software, sistemas de construcción (*build systems*) e infraestructura de distribución. Esta categoría fue votada mayoritariamente como una de las principales preocupaciones en la encuesta de la comunidad. Esta categoría cuenta con 5 CWE y una presencia limitada en los datos recopilados, pero creemos que esto se debe a los desafíos en las pruebas y esperamos que las pruebas se pongan al día en esta área. Esta categoría tiene el menor número de ocurrencias en los datos, pero también las puntuaciones medias más altas de explotación e impacto de CVE (*Common Vulnerabilities and Exposures*).
* **[A04:2025 - Fallas Criptográficas](A04_2025-Fallas_Criptograficas.md)** baja dos puestos del #2 al #4 en la clasificación. Los datos aportados indican que, de media, el 3,80% de las aplicaciones tienen una o más de las 32 CWE en esta categoría. Esta categoría a menudo conduce a la exposición de datos sensibles o al compromiso del sistema.
* **[A05:2025 - Inyección](A05_2025-Inyeccion.md)** baja dos puestos del #3 al #5 en la clasificación, manteniendo su posición relativa respecto a Fallas Criptográficas y Diseño Inseguro. La inyección es una de las categorías más probadas, con el mayor número de CVE asociados a las 38 CWE de esta categoría. La inyección incluye una gama de problemas que van desde el Secuencia de Comandos en Sitios Cruzados (XSS, alta frecuencia/bajo impacto) hasta vulnerabilidades de Inyección SQL (baja frecuencia/alto impacto).
* **[A06:2025 - Diseño Inseguro](A06_2025-Diseno_Inseguro.md)** desciende dos puestos del #4 al #6 en el ranking, al ser superada por Configuración de Seguridad Incorrecta y Fallas en la Cadena de Suministro de Software. Esta categoría se introdujo en 2021, y hemos visto mejoras notables en la industria relacionadas con el modelado de amenazas y un mayor énfasis en el diseño seguro.
* **[A07:2025 - Fallas de Autenticación](A07_2025-Fallas_de_Autenticacion.md)** mantiene su posición en el #7 con un ligero cambio de nombre (anteriormente era "[Fallas de Identificación y Autenticación](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)") para reflejar con mayor precisión las 36 CWE de esta categoría. Esta categoría sigue siendo importante, pero el mayor uso de marcos de trabajo estandarizados para la autenticación parece estar teniendo efectos beneficiosos en la incidencia de las fallas de autenticación.
* **[A08:2025 - Fallas en la Integridad del Software o de los Datos](A08_2025-Fallas_en_la_Integridad_del_Software_y_de_los_Datos.md)** continúa en el #8 de la lista. Esta categoría se centra en la falla al mantener los límites de confianza y verificar la integridad del software, el código y los artefactos de datos a un nivel inferior al de las fallas en la Cadena de Suministro de Software.
* **[A09:2025 - Fallas en el Registro, Alerta y Monitoreo de Seguridad](A09_2025-Fallas_en_el_Registro_y_Monitoreo.md)** conserva su posición en el #9. Esta categoría tiene un ligero cambio de nombre (anteriormente "[Fallas de Registro y Monitorización de Seguridad](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)") para enfatizar la importancia de la funcionalidad de alerta necesaria para inducir una acción apropiada ante eventos de registro relevantes. Un excelente registro sin alertas tiene un valor mínimo para identificar incidentes de seguridad. Esta categoría siempre estará infrarrepresentada en los datos, y fue votada de nuevo para una posición en la lista por los participantes de la encuesta de la comunidad.
* **[A10:2025 - Manejo Inadecuado de Condiciones Excepcionales](A10_2025-Manejo_Inadecuado_de_Condiciones_Excepcionales.md)** es una nueva categoría para 2025. Esta categoría contiene 24 CWE que se centran en el manejo inadecuado de errores, errores lógicos, fallas en modo abierto (*failing open*) y otros escenarios relacionados derivados de condiciones anormales que los sistemas pueden encontrar.


## Metodología

Esta entrega del Top Ten sigue estando informada por los datos, pero no impulsada ciegamente por ellos. Clasificamos 12 categorías basándonos en los datos aportados, y permitimos que dos fueran promovidas o destacadas por las respuestas de la encuesta de la comunidad. Hacemos esto por una razón fundamental: examinar los datos aportados es, esencialmente, mirar al pasado. Los investigadores de seguridad de aplicaciones dedican tiempo a identificar nuevas vulnerabilidades y a desarrollar nuevos métodos de prueba. Se necesitan de semanas a años para integrar estas pruebas en herramientas y procesos. Para cuando podemos probar una debilidad de forma fiable a escala, pueden haber pasado años. También existen riesgos importantes que quizá nunca podamos probar de forma fiable y que no estén presentes en los datos. Para equilibrar esa visión, utilizamos una encuesta comunitaria para preguntar a los profesionales de la seguridad y el desarrollo de aplicaciones que están en primera línea qué ven como riesgos esenciales que pueden estar infrarrepresentados en los datos de las pruebas.


## Cómo se estructuran las categorías

Algunas categorías han cambiado con respecto a la entrega anterior del OWASP Top Ten. He aquí un resumen de alto nivel de los cambios en las categorías.

En esta iteración, solicitamos datos sin restricciones sobre las CWE, a diferencia de lo que hicimos para la edición de 2021. Preguntamos por el número de aplicaciones probadas en un año determinado (empezando en 2021) y el número de aplicaciones con al menos una instancia de una CWE encontrada en las pruebas. Este formato nos permite seguir la prevalencia de cada CWE dentro de la población de aplicaciones. Ignoramos la frecuencia para nuestros propósitos; aunque puede ser necesaria para otras situaciones, solo oculta la prevalencia real en la población de aplicaciones. Que una aplicación tenga cuatro instancias de una CWE o 4.000 instancias no forma parte del cálculo para el Top Ten. Especialmente porque los evaluadores manuales tienden a listar una vulnerabilidad solo una vez, sin importar cuántas veces se repita en una aplicación, mientras que los marcos de pruebas automatizadas listan cada instancia de una vulnerabilidad como única. Pasamos de aproximadamente 30 CWE en 2017, a casi 400 CWE en 2021, a 589 CWE en esta edición para analizar en el conjunto de datos. Planeamos realizar análisis de datos adicionales como suplemento en el futuro. Este aumento significativo en el número de CWE hace necesarios cambios en la estructura de las categorías.

Pasamos varios meses agrupando y categorizando CWE y podríamos haber continuado durante meses adicionales. Tuvimos que parar en algún momento. Existen CWE de tipo causa raíz y de tipo síntoma, donde los tipos de causa raíz son como "Falla Criptográfica" y "Configuración Incorrecta", en contraste con los tipos de síntoma como "Exposición de Datos Sensibles" y "Denegación de Servicio". Decidimos centrarnos en la causa raíz siempre que fuera posible, ya que es más lógico para proporcionar orientación de identificación y remediación. Centrarse en la causa raíz por encima del síntoma no es un concepto nuevo; el Top Ten ha sido una mezcla de síntoma y causa raíz. Las CWE también son una mezcla de síntoma y causa raíz; simplemente estamos siendo más deliberados al señalarlo. Hay un promedio de 25 CWE por categoría en esta entrega, con los límites inferiores en 5 CWE para A03:2025 - Fallas en la Cadena de Suministro de Software y A09:2025 - Fallas en el Registro, Alerta y Monitoreo de Seguridad, hasta 40 CWE en A01:2025 - Pérdida de Control de Acceso. Tomamos la decisión de limitar el número de CWE en una categoría a 40. Esta estructura de categorías actualizada ofrece beneficios adicionales de formación, ya que las empresas pueden centrarse en las CWE que tengan sentido para un lenguaje o marco de trabajo (*framework*).

Se nos ha preguntado por qué no cambiar a una lista de 10 CWE como un Top 10, similar a las 25 debilidades de software más peligrosas de MITRE (MITRE Top 25). Hay dos razones principales por las que utilizamos múltiples CWE en las categorías. En primer lugar, no todas las CWE existen en todos los lenguajes de programación o marcos de trabajo. Esto causa problemas para las herramientas y los programas de formación/concienciación, ya que parte del Top Ten puede no ser aplicable. La segunda razón es que existen múltiples CWE para vulnerabilidades comunes. Por ejemplo, hay múltiples CWE para Inyección general, Inyección de Comandos, Secuencia de Comandos en Sitios Cruzados, Contraseñas Codificadas (*Hardcoded Passwords*), Falta de Validación, Desbordamientos de Búfer (*Buffer Overflows*), Almacenamiento de Información Sensible en Texto Claro y muchas otras. Dependiendo de la organización o del evaluador, se pueden utilizar diferentes CWE. Al utilizar una categoría con múltiples CWE, podemos ayudar a elevar el nivel base y la concienciación sobre los diferentes tipos de debilidades que pueden ocurrir bajo un nombre de categoría común. En esta edición del Top Ten 2025, hay 248 CWE dentro de las 10 categorías. Hay un total de 968 CWE en el [diccionario descargable de MITRE](https://cwe.mitre.org) en el momento de este lanzamiento.


## Cómo se utilizan los datos para seleccionar las categorías

Al igual que hicimos para la edición de 2021, aprovechamos los datos de CVE para la *Explotabilidad* y el *Impacto (Técnico)*. Descargamos OWASP Dependency Check y extrajimos las puntuaciones de Explotación e Impacto de CVSS (*Common Vulnerability Scoring System*), agrupándolas por las CWE relevantes listadas con los CVE. Requirió bastante investigación y esfuerzo, ya que todos los CVE tienen puntuaciones de CVSSv2, pero existen fallas en CVSSv2 que CVSSv3 debería abordar. A partir de cierto momento, a todos los CVE se les asigna también una puntuación CVSSv3. Además, los rangos de puntuación y las fórmulas se actualizaron entre CVSSv2 y CVSSv3.

En CVSSv2, tanto la Explotación como el Impacto (Técnico) podían ser de hasta 10.0, pero la fórmula los reducía al 60% para Explotación y al 40% para Impacto. En CVSSv3, el máximo teórico se limitó a 6,0 para Explotación y 4,0 para Impacto. Teniendo en cuenta la ponderación, la puntuación de Impacto se desplazó hacia arriba, casi un punto y medio de media en CVSSv3, y la explotabilidad se desplazó casi medio punto hacia abajo de media.

Existen aproximadamente 175.000 registros (frente a los 125.000 de 2021) de CVE mapeados a CWE en la Base de Datos Nacional de Vulnerabilidades (NVD, *National Vulnerability Database*), extraídos de OWASP Dependency Check. Además, hay 643 CWE únicas mapeadas a CVE (frente a las 241 de 2021). Dentro de los casi 220.000 CVE que se extrajeron, 160.000 tenían puntuaciones CVSS v2, 156.000 tenían puntuaciones CVSS v3 y 6.000 tenían puntuaciones CVSS v4. Muchos CVE tienen múltiples puntuaciones, razón por la cual el total es superior a 220.000.

Para el Top Ten 2025, calculamos las puntuaciones medias de explotación e impacto de la siguiente manera. Agrupamos todos los CVE con puntuaciones CVSS por CWE y ponderamos tanto las puntuaciones de explotación como las de impacto por el porcentaje de la población que tenía CVSSv3, así como la población restante con puntuaciones CVSSv2, para obtener una media global. Mapeamos estos promedios a las CWE en el conjunto de datos para utilizarlos como puntuación de Explotación e Impacto (Técnico) para la otra mitad de la ecuación de riesgo.

¿Por qué no utilizar CVSS v4.0?, se preguntarán. Esto se debe a que el algoritmo de puntuación cambió fundamentalmente y ya no proporciona fácilmente las puntuaciones de *Explotación* o *Impacto* como lo hacen CVSS v2 y CVSSv3. Intentaremos encontrar una manera de utilizar la puntuación CVSS v4.0 para futuras versiones del Top Ten, pero no pudimos determinar una manera oportuna de hacerlo para la edición de 2025.


## Por qué utilizamos una encuesta comunitaria

Los resultados en los datos se limitan en gran medida a lo que la industria puede probar de forma automatizada. Hable con un profesional veterano de AppSec y le hablará de cosas que encuentra y tendencias que ve que aún no están en los datos. Se necesita tiempo para que la gente desarrolle metodologías de prueba para ciertos tipos de vulnerabilidades y luego más tiempo para que esas pruebas se automaticen y se ejecuten contra una gran población de aplicaciones. Todo lo que encontramos es mirar hacia el pasado y podría estar omitiendo tendencias del último año que no están presentes en los datos.

Por lo tanto, solo seleccionamos ocho de las diez categorías a partir de los datos porque están incompletos. Las otras dos categorías provienen de la encuesta comunitaria del Top 10. Permite a los profesionales que están en primera línea votar por lo que consideran los riesgos más altos que podrían no estar en los datos (y que quizá nunca se expresen en datos).


## Gracias a nuestros colaboradores de datos

Las siguientes organizaciones (junto con varios donantes anónimos) donaron amablemente datos de más de 2,8 millones de aplicaciones para hacer de este el conjunto de datos de seguridad de aplicaciones más grande y completo. Sin ustedes, esto no sería posible.

* Accenture (Praga)
* Anónimo (múltiples)
* Bugcrowd
* Contrast Security
* CryptoNet Labs
* Intuitor SoftTech Services
* Orca Security
* Probely
* Semgrep
* Sonar
* usd AG
* Veracode
* Wallarm

## Autores Principales
* Andrew van der Stock - X: [@vanderaj](https://x.com/vanderaj)
* Brian Glas - X: [@infosecdad](https://x.com/infosecdad)
* Neil Smithline - X: [@appsecneil](https://x.com/appsecneil)
* Tanya Janca - X: [@shehackspurple](https://x.com/shehackspurple)
* Torsten Gigler - Mastodon: [@torsten_gigler@infosec.exchange](https://infosec.exchange/@torsten_gigler)

## Registro de problemas y solicitudes de incorporación de cambios (*pull requests*)

Por favor, registre cualquier corrección o problema:

### Enlaces del proyecto:
* [Página principal](https://owasp.org/www-project-top-ten/)
* [Repositorio de GitHub](https://github.com/OWASP/Top10)
