# Cómo iniciar un programa AppSec con OWASP Top 10 

En el pasado, el OWASP Top 10 nunca fue diseñado para ser la base de un programa AppSec. Sin embargo, es esencial comenzar en algún lugar para muchas organizaciones que recién comienzan en su travesía en seguridad de aplicaciones.
El OWASP Top 10 2021 es un buen comienzo como base para las listas de control, etc., pero no es suficiente en sí mismo.

## Etapa 1. Identifique las necesidades y los objetivos de su programa appsec

Muchos programas de seguridad de aplicaciones (AppSec) intentan correr antes de poder gatear o caminar. Estos esfuerzos están condenados al fracaso. Recomendamos encarecidamente a los CISO y a los líderes de AppSec que utilicen el [Modelo de Madurez para el Aseguramiento del Software (SAMM)](https://owaspsamm.org) de OWASP para identificar debilidades y áreas de mejora durante un período de 1 a 3 años. El primer paso es evaluar dónde se encuentra ahora, identificar las necesidades en la administración, el diseño, la implementación, la verificación y las operaciones que necesita resolver de inmediato frente a las que pueden esperar, y priorizar la implementación o mejora de las quince prácticas de seguridad SAMM de OWASP. OWASP SAMM puede ayudar a construir y medir mejoras en sus esfuerzos de aseguramiento de software.
															   																	  
## Etapa 2. Planifique un ciclo de vida de desarrollo seguro de carretera pavimentada("paved road")

Tradicionalmente, el refugio de los llamados "unicornios", el concepto de carretera pavimentada("paved road") es la forma más fácil de generar el mayor impacto y escalar los recursos de AppSec con la velocidad del equipo de desarrollo, que solo aumenta cada año.
																   
El concepto de camino pavimentado es: "la forma más fácil es también la forma más segura" y debe involucrar una cultura de asociaciones profundas entre el equipo de desarrollo y el equipo de seguridad, preferiblemente de manera que sean el mismo equipo. El camino pavimentado tiene como objetivo mejorar, medir, detectar y reemplazar continuamente alternativas inseguras al tener una biblioteca de reemplazos seguros para toda la empresa, con herramientas para ayudar a ver dónde se pueden realizar mejoras al adoptar el camino pavimentado. Esto permite que las herramientas de desarrollo existentes informen sobre compilaciones inseguras y ayude a los equipos de desarrollo a autocorregirse de las alternativas inseguras.

La carretera pavimentada puede parecer mucho para asimilar, pero debe construirse gradualmente con el tiempo. Existen otras formas de programas appsec, en particular, el ciclo de vida de desarrollo seguro ágil de Microsoft. No todas las metodologías de programas de appsec se adaptan a todas las empresas.
																	 
## Etapa 3. Implemente la carretera pavimentada con sus equipos de desarrollo.

Las carreteras pavimentadas se construyen con el consentimiento y la participación directa de los equipos de desarrollo y operaciones involucrados. La carretera pavimentada debe estar alineada estratégicamente con el negocio y ayudar a entregar aplicaciones más seguras con mayor rapidez. El desarrollo de la carretera pavimentada debería ser un ejercicio holístico que cubra todo el ecosistema empresarial o de aplicaciones, no una curita por aplicación, como en los viejos tiempos.
																   
## Etapa 4. Migre todas las aplicaciones existentes y futuras a la carretera pavimentada.

Agregue herramientas de detección de tipo carretera pavimentada a medida que las desarrolle y proporcione información a los equipos de desarrollo para mejorar la seguridad de sus aplicaciones mediante la forma en que pueden adoptar directamente elementos de tipo carretera pavimentada.
Una vez que se ha adoptado un aspecto de la carretera pavimentada, las organizaciones deben implementar controles de integración continuos que inspeccionen el código existente y los check-ins que utilizan alternativas prohibidas y que luego advierten o rechazan el build o el check-in. Esto evita que las opciones inseguras se introduzcan en el código con el tiempo, evitando la deuda técnica y una aplicación insegura defectuosa.
Dichas advertencias deben estar ligadas a la alternativa segura, de modo que el equipo de desarrollo reciba la respuesta correcta de inmediato. Ellos pueden refactorizar y adoptar los componentes de la carretera pavimentada rápidamente.

## Etapa 5. Pruebe que la carretera pavimentada haya mitigado los problemas encontrados en el Top 10 de OWASP

Los componentes de carretera pavimentada deben abordar un problema importante del OWASP Top 10, por ejemplo, cómo detectar o reparar automáticamente componentes vulnerables, o un complemento IDE de análisis de código estático para detectar inyecciones o, mejor aún, comenzar a usar una biblioteca que se sabe que es segura contra inyecciones.
Cuantos más de estos reemplazos seguros directos se proporcionen a los equipos, mejor.
Una tarea vital del equipo de appsec es garantizar que la seguridad de estos componentes se evalúe y mejore continuamente.
Una vez que se mejoran, alguna forma de vía de comunicación con los consumidores del componente debe indicar que debe ocurrir una actualización, preferiblemente de forma automática, pero si no, al menos resaltado en un dashboard o algo parecido.
																								 
## Etapa 6. Transforme su programa en un programa de AppSec maduro

No debe detenerse en el Top 10 de OWASP. Este solo cubre 10 categorías de riesgo. Recomendamos enfáticamente a las organizaciones que adopten el Estándar de verificación de seguridad de aplicaciones y agreguen progresivamente componentes de carretera pavimentada y pruebas para los niveles 1, 2 y 3, según el nivel de riesgo de las aplicaciones desarrolladas.
	
## Yendo más allá

Todos los grandes programas de AppSec van más allá del mínimo indispensable. Todos deben ir más allá si queremos realmente superar las vulnerabilidades de appsec.

-   **Integridad conceptual**. Los programas maduros de AppSec deben contener algún concepto de arquitectura de seguridad, ya sea una arquitectura formal de seguridad en la nube o empresarial o modelado de amenazas.

-   **Automatización y escala**. Los programas maduros de AppSec intentan automatizar la mayor cantidad posible de sus entregables, utilizando scripts para emular pasos complejos de pruebas de penetración, herramientas de análisis de código estático directamente disponibles para los equipos de desarrollo, ayudan a los equipos de desarrollo a crear pruebas de integración y unidad de appsec, y más.

-   **Cultura**. Los programas maduros de AppSec intentan construir el diseño inseguro y eliminar la deuda técnica del código existente al ser parte del equipo de desarrollo y no fuera del mismo. Los equipos de AppSec que ven a los equipos de desarrollo como "nosotros" y "ellos" están condenados al fracaso.

-   **Mejora continua**. Los programas maduros de AppSec buscan mejorar constantemente. Si algo no funciona, deje de hacerlo. Si algo es inútil o no escalable, trabaje para mejorarlo. Si los equipos de desarrollo no están utilizando algo y tiene un impacto nulo o limitado, haga algo diferente. El hecho de que hayamos realizado pruebas como comprobaciones de escritorio desde la década de 1970 no significa que sea una buena idea. Haga mediciones, evaluaciones y luego cree o mejore.
