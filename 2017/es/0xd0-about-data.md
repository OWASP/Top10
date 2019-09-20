# +Dat Metodología y Datos

En la Cumbre del Proyecto OWASP, participantes activos y miembros de la comunidad decidieron una visión de vulnerabilidad, con hasta dos (2) clases de vulnerabilidad con visión de futuro, con un orden definido parcialmente por datos cuantitativos y parcialmente por encuestas cualitativas.

At the OWASP Project Summit, active participants and community members decided on a vulnerability view, with up to two (2) forward looking vulnerability classes, with ordering defined partially by quantitative data, and partially by qualitative surveys.
 
## Encuesta a la Industria

Para la encuesta, recopilamos las categorías de vulnerabilidad que habían sido identificadas previamente como "en la cúspide" o que se mencionaron en las devoluciones a la RC1 del Top 10 2017 en la lista de correo. Los incluimos en una encuesta ordenada y les pedimos a los encuestados que clasificaran las cuatro principales vulnerabilidades que consideraban deberían incluirse en el Top 10 - 2017 de OWASP. La encuesta se realizó del 2 de agosto al 18 de septiembre de 2017. Se obtuvieron 516 respuestas y se clasificaron las vulnerabilidades.

| Clasificación | Categorías de Vulnerabilidad de la Encuesta | Puntuación |
| -- | -- | -- |
| 1 | Exposición de Información Privada ('Violación de Privacidad') [CWE-359] | 748 |
| 2 | Fallas criptográficas [CWE-310/311/312/326/327]| 584 |
| 3 | Deserialización de datos no confiables [CWE-502] | 514 |
| 4 | Sobrepaso de Autorización a traves de entradas de datos controladas por el usuario (IDOR & Path Traversal) [CWE-639] | 493 |
| 5 | Registro y Monitoreo Insuficientes [CWE-223 / CWE-778]| 440 |

La exposición de la información privada es claramente la vulnerabilidad de mayor puntuación, pudiéndose considerar como un caso específico de la ya existente **A3:2017 Exposición de Datos Sensibles**. Las fallas criptográficas se pueden considerar dentro de la exposición de datos sensibles. La deserialización insegura fue clasificada en el tercer lugar, por lo que se agregó al Top 10 como **A8:2017 Deserialización Insegura** luego de haber clasificado su riesgo. La cuarta, claves de datos controladas por el usuario se encuentra incluída en **A5:2017 Pérdida de Control de Acceso**; es bueno verla en la encuesta, ya que no hay muchos datos relacionados con las vulnerabilidades de autorización. La categoría número cinco clasificada en la encuesta es Registro y Monitoreo Insuficientes, lo que creemos es una buena opción para la lista de los 10 Principales, razón por la cual se ha convertido en **A10:2017 Registro y Monitoreo Insuficientes**. Hemos llegado a un punto en el que las aplicaciones necesitan ser capaces de definir lo que puede ser un ataque y generar registros, alertas, escalada y respuesta adecuados. 


## Llamada Pública de Datos

Tradicionalmente, los datos recopilados y analizados se basaban más en los datos de frecuencia; cuántas vulnerabilidades fueron detectadas en las aplicaciones probadas. Como es bien sabido, las herramientas reportan tradicionalmente todos los casos encontrados de una vulnerabilidad y los seres humanos reportan tradicionalmente un solo hallazgo con un número de ejemplos. Esto hace que sea muy difícil agregar los dos estilos de reporte de forma comparable.

Para la versión 2017, la tasa de incidencia se calculó en función del número de aplicaciones en un conjunto de datos dado que tenían uno o más tipos de vulnerabilidad específicos. Los datos de muchos contribuyentes más grandes fueron proporcionaron en dos formas: La primera fue la manera tradicional de contar cada instancia encontrada de una vulnerabilidad, mientras que la segunda fue el conteo de aplicaciones en las que se encontró cada vulnerabilidad (una o más veces). Aunque no es perfecto, esto nos permite comparar razonablemente los datos de obtenidos tanto por las herramientas asistidas por humanos como por pruebas humanas asistidas por herramientas. Los datos en bruto y el trabajo de análisis se encuentran disponibles en [GitHub](https://github.com/OWASP/Top10/tree/master/2017/datacall). Nos proponemos ampliarlo con una estructura adicional en futuras versiones del Top 10.

Recibimos más de 40 respuestas al llamado público de datos. Dado que ya muchas de ellas procedían de la llamado público de de datos original que se centraba en la frecuencia, pudimos utilizar datos de 23 contribuyentes que cubrían unas 114.000 aplicaciones aproximadamente. Utilizamos un bloque de tiempo de un año cuando fue posible e identificado por el colaborador. La mayoría de las aplicaciones son únicas, aunque reconocemos la probabilidad de algunas aplicaciones repetidas entre los datos anuales de Veracode. Los 23 conjuntos de datos utilizados se identificaron como pruebas humanas asistidas por herramientas o bien como tasas de incidencia proporcionadas específicamente por herramientas asistidas por humanos. Las anomalías en los datos seleccionados de incidencia del 100%+ se ajustaron hasta el 100% máximo. Para calcular la tasa de incidencia, se calculó el porcentaje de las aplicaciones totales que contenían cada tipo de vulnerabilidad. La clasificación de la incidencia se utilizó para el cálculo de la prevalencia en el riesgo global para la clasificación de los 10 primeros. 
