# ¿Qué son los Riesgos de Seguridad de Aplicaciones?
Los atacantes pueden utilizar potencialmente muchos caminos diferentes a través de su aplicación para dañar a su empresa u organización. Cada una de estas vías plantea un riesgo potencial que debe ser investigado.

![Diagrama de cálculo](../assets/2025-algorithm-diagram.png)

<table>
  <tr>
   <td>
    <strong>Agentes de Amenaza</strong>
   </td>
   <td>
    <strong>Vectores de Ataque</strong>
   </td>
   <td>
    <strong>Explotabilidad</strong>
   </td>
   <td>
    <strong>Probabilidad de Ausencia de Controles</strong>
<p style="text-align: center">

    <strong>de Seguridad</strong>
   </td>
   <td>
    <strong>Impactos Técnicos</strong>
   </td>
   <td>
    <strong>Impactos de Negocio</strong>
   </td>
  </tr>
  <tr>
   <td>
    <strong>Por entorno, dinámicos según el panorama de la situación</strong>
   </td>
   <td>
    <strong>Por exposición de la Aplicación (por entorno)</strong>
   </td>
   <td>
    <strong>Promedio Ponderado de Explotación</strong>
   </td>
   <td>
    <strong>Controles Ausentes por tasa media de Incidencia Ponderada por cobertura</strong>
   </td>
   <td>
    <strong>Promedio Ponderado de Impacto</strong>
   </td>
   <td>
    <strong>Por Negocio</strong>
   </td>
  </tr>
</table>


En nuestra Calificación de Riesgo hemos tenido en cuenta los parámetros universales de explotabilidad, la probabilidad media de ausencia de controles de seguridad para una debilidad y sus impactos técnicos.

Cada organización es única, al igual que los actores de amenazas para esa organización, sus objetivos y el impacto de cualquier brecha de seguridad. Si una organización de interés público utiliza un sistema de gestión de contenidos (CMS) para información pública y un sistema de salud utiliza exactamente el mismo CMS para registros médicos sensibles, los actores de amenazas y los impactos de negocio pueden ser muy diferentes para el mismo software. Es fundamental comprender el riesgo para su organización basándose en la exposición de la aplicación, los agentes de amenaza aplicables según el panorama de la situación (para ataques dirigidos y no dirigidos por negocio y ubicación) y los impactos de negocio individuales.


## Cómo se utilizan los datos para seleccionar y clasificar las categorías

En 2017, seleccionamos las categorías por tasa de incidencia para determinar la probabilidad, y luego las clasificamos mediante una discusión del equipo basada en décadas de experiencia para Explotabilidad, Detectabilidad (también probabilidad) e Impacto Técnico. Para 2021, utilizamos datos de Explotabilidad e Impacto (Técnico) de las puntuaciones CVSSv2 y CVSSv3 en la Base de Datos Nacional de Vulnerabilidades (NVD). Para 2025, continuamos con la misma metodología que creamos en 2021.

Descargamos OWASP Dependency Check y extrajimos las puntuaciones de Explotación e Impacto de CVSS agrupadas por CWE relacionadas. Requirió bastante investigación y esfuerzo, ya que todos los CVE tienen puntuaciones CVSSv2, pero existen fallas en CVSSv2 que CVSSv3 debería abordar. A partir de cierto momento, a todos los CVE se les asigna también una puntuación CVSSv3. Además, los rangos de puntuación y las fórmulas se actualizaron entre CVSSv2 y CVSSv3.

En CVSSv2, tanto la Explotación como el Impacto (Técnico) podían ser de hasta 10.0, pero la fórmula los reducía al 60% para Explotación y al 40% para Impacto. En CVSSv3, el máximo teórico se limitó a 6,0 para Explotación y 4,0 para Impacto. Teniendo en cuenta la ponderación, la puntuación de Impacto se desplazó hacia arriba, casi un punto y medio de media en CVSSv3, y la explotabilidad se desplazó casi medio punto hacia abajo de media cuando realizamos el análisis para el Top Ten de 2021.

Existen aproximadamente 175.000 registros (frente a los 125.000 de 2021) de CVE mapeados a CWE en la Base de Datos Nacional de Vulnerabilidades (NVD), extraídos de OWASP Dependency Check. Además, hay 643 CWE únicas mapeadas a CVE (frente a las 241 de 2021). Dentro de los casi 220.000 CVE que se extrajeron, 160.000 tenían puntuaciones CVSS v2, 156.000 tenían puntuaciones CVSS v3 y 6.000 tenían puntuaciones CVSS v4. Muchos CVE tienen múltiples puntuaciones, razón por la cual el total es superior a 220.000.

Para el Top Ten 2025, calculamos las puntuaciones medias de explotación e impacto de la siguiente manera. Agrupamos todos los CVE con puntuaciones CVSS por CWE y ponderamos tanto las puntuaciones de explotación como las de impacto por el porcentaje de la población que tenía CVSSv3, así como la población restante con puntuaciones CVSSv2, para obtener una media global. Mapeamos estos promedios a las CWE en el conjunto de datos para utilizarlos como puntuación de Explotación e Impacto (Técnico) para la otra mitad de la ecuación de riesgo.

¿Por qué no utilizar CVSS v4.0?, se preguntarán. Esto se debe a que el algoritmo de puntuación cambió fundamentalmente y ya no proporciona fácilmente las puntuaciones de *Explotación* o *Impacto* como lo hacen CVSSv2 y CVSSv3. Intentaremos encontrar una manera de utilizar la puntuación CVSS v4.0 para futuras versiones del Top Ten, pero no pudimos determinar una manera oportuna de hacerlo para la edición de 2025.

Para la tasa de incidencia, calculamos el porcentaje de aplicaciones vulnerables a cada CWE a partir de la población analizada por una organización durante un periodo de tiempo. Como recordatorio, no estamos utilizando la frecuencia (o cuántas veces aparece un problema en una aplicación), nos interesa qué porcentaje de la población de aplicaciones se encontró que tenía cada CWE.

Para la cobertura, observamos el porcentaje de aplicaciones probadas por todas las organizaciones para una CWE determinada. Cuanto mayor sea la cobertura calculada, mayor será la seguridad de que la tasa de incidencia es precisa, ya que el tamaño de la muestra es más representativo de la población.

La fórmula que utilizamos para esta iteración es similar a la de 2021, con algunos cambios en la ponderación:
(Tasa de Incidencia Máxima % * 1000) + (Cobertura Máxima % * 100) + (Promedio de Explotación * 10) + (Promedio de Impacto * 20) + (Suma de Ocurrencias / 10000) = Puntuación de Riesgo

Las puntuaciones calculadas oscilaron entre 621,60 para la categoría de Pérdida de Control de Acceso y 271,08 para Errores de Gestión de Memoria.

Este no es un sistema perfecto, pero es valioso para clasificar las categorías de riesgo.

Un desafío adicional que está creciendo es la definición de una "aplicación". A medida que la industria se desplaza hacia diferentes arquitecturas compuestas por microservicios y otras implementaciones que son más pequeñas que una aplicación tradicional, los cálculos son más difíciles. Por ejemplo, si una organización está probando repositorios de código, ¿qué considera una aplicación? Al igual que el crecimiento de CVSSv4, la próxima edición del Top Ten podría necesitar ajustar el análisis y la puntuación para tener en cuenta una industria en constante cambio.

## Factores de Datos

Existen factores de datos que se enumeran para cada una de las categorías del Top Ten; esto es lo que significan:

**CWE Mapeadas:** El número de CWE mapeadas a una categoría por el equipo del Top Ten.

**Tasa de Incidencia:** La tasa de incidencia es el porcentaje de aplicaciones vulnerables a esa CWE de la población analizada por esa organización para ese año.

**Explotación Ponderada:** La subpuntuación de Explotación de las puntuaciones CVSSv2 y CVSSv3 asignadas a los CVE mapeados a las CWE, normalizada y colocada en una escala de 10 puntos.

**Impacto Ponderado:** La subpuntuación de Impacto de las puntuaciones CVSSv2 y CVSSv3 asignadas a los CVE mapeados a las CWE, normalizada y colocada en una escala de 10 puntos.

**Cobertura (de Pruebas):** El porcentaje de aplicaciones probadas por todas las organizaciones para una CWE determinada.

**Ocurrencias Totales:** Número total de aplicaciones que se encontró que tenían las CWE mapeadas a una categoría.

**CVE Totales:** Número total de CVE en la base de datos NVD que fueron mapeados a las CWE mapeadas a una categoría.

**Fórmula:** (Tasa de Incidencia Máxima % * 1000) + (Cobertura Máxima % * 100) + (Promedio de Explotación * 10) + (Promedio de Impacto * 20) + (Suma de Ocurrencias / 10000) = Puntuación de Riesgo
