# Cómo iniciar un programa de Seguridad en Aplicaciones (AppSec) con el OWASP Top 10 

Anteriormente, el OWASP Top 10 no había sido diseñado para ser la base de un programa de AppSec. Sin embargo, es esencial comenzar en algún lugar, sobre todo para aquellas organizaciones que recién comienzan su travesía en seguridad de aplicaciones.
El OWASP Top 10 2021 no es suficiente en sí mismo, pero es un buen comienzo como base para las listas de controles, etc.

## Etapa 1. Identifique las necesidades y los objetivos de su programa de AppSec

Muchos programas de seguridad en aplicaciones intentan correr antes de poder gatear o caminar. Estos esfuerzos están condenados al fracaso. Recomendamos encarecidamente a los CISO y a los líderes de AppSec que utilicen el [Modelo de Madurez para el Aseguramiento del Software (SAMM)](https://owaspsamm.org) de OWASP para identificar debilidades y áreas de mejora durante un período de 1 a 3 años. El primer paso es evaluar dónde se encuentra ahora, identificar las brechas en las áreas de gobernanza, diseño, implementación, verificación y operaciones que necesita resolver de inmediato frente a las que pueden esperar, priorizando la implementación o mejora de las quince prácticas de seguridad SAMM de OWASP. OWASP SAMM puede ayudar a construir y medir mejoras en sus esfuerzos de aseguramiento de software.
															   																	  
## Etapa 2. Planifique un ciclo de vida de desarrollo seguro de carretera pavimentada ("paved road")

El concepto de carretera pavimentada ("paved road") en seguridad informática es una forma concisa de expresar que el camino mas rápido también es el mas seguro. Esto permite escalar los recursos necesarios de AppSec al mismo ritmo que aumenta la velocidad requerida por los equipos de desarrollo; que dicho sea de paso, se acelera cada año.
																   
El concepto de camino pavimentado es: "la forma más fácil es también la forma más segura" y debe involucrar una cultura de asociaciones profundas entre el equipo de desarrollo y el equipo de seguridad, preferiblemente de manera que sean el mismo equipo. El camino pavimentado tiene como objetivo mejorar, medir, detectar y reemplazar alternativas inseguras, teniendo a nivel de toda la organización una biblioteca de alternativas seguras, utilizando a su vez herramientas de apoyo para detectar dónde es posible realizar mejoras al adoptar el camino pavimentado. Esto permite que las herramientas de desarrollo ya existentes informen sobre compilaciones inseguras y ayude a los equipos de desarrollo a autocorregirse.

La carretera pavimentada puede parecer mucho para asimilar, pero debe construirse gradualmente con el tiempo. Existen otras formas de programas de AppSec, como por ejemplo el ciclo de vida de desarrollo seguro ágil de Microsoft. No todas las metodologías de programas de AppSec se adaptan a todas las organizaciones.
																	 
## Etapa 3. Implemente la carretera pavimentada con sus equipos de desarrollo.

Las carreteras pavimentadas se construyen con el consentimiento y la participación directa de los equipos de desarrollo y operaciones involucrados. Debe estar alineada estratégicamente con el negocio y ayudar a entregar aplicaciones más seguras con mayor rapidez. El desarrollo de la carretera pavimentada debería ser un ejercicio holístico que cubra todo el ecosistema de aplicaciones de la organización, no un remiendo por aplicación, como en los viejos tiempos.
																   
## Etapa 4. Migre todas las aplicaciones existentes y futuras a la carretera pavimentada.

Agregue herramientas de detección a la carretera pavimentada a medida que las desarrolle y proporcione información a los equipos de desarrollo para mejorar la seguridad de sus aplicaciones a través de la adopción de herramientas ya incluidas en la carretera pavimentada. Una vez que se ha adoptado un aspecto de la carretera pavimentada, las organizaciones deberían implementar controles en los procesos de integración continua que inspeccionen el código ya existente y las modificaciones (check-ins), rechazando o advirtiendo sobre aquellas que introducen alternativas prohibidas. Esto evita que las opciones inseguras se introduzcan en el código con el tiempo, evitando la deuda técnica y una aplicación insegura defectuosa.
Dichas advertencias deben estar ligadas a la alternativa segura, de modo que el equipo de desarrollo reciba la respuesta correcta de inmediato. Ellos pueden refactorizar y adoptar los componentes de la carretera pavimentada rápidamente.

## Etapa 5. Pruebe que la carretera pavimentada haya mitigado los problemas encontrados en el Top 10 de OWASP

Los componentes de carretera pavimentada deben abordar un problema importante del OWASP Top 10, por ejemplo, cómo detectar o reparar automáticamente componentes vulnerables, o un complemento IDE de análisis de código estático para detectar inyecciones o, mejor aún, comenzar a usar una biblioteca que se sabe que es segura contra inyecciones.
Cuantas más de estas sustituciones seguras se proporcionen a los equipos, mejor.
Una tarea vital del equipo de AppSec es garantizar que la seguridad de estos componentes se evalúe y mejore continuamente.
Una vez mejorados, alguna forma de comunicación debe existir con los consumidores del componente para indicar que existe una actualización disponible. Es preferiblemente una forma automática, pero si no es posible, se recomienda utilizar al menos un resaltado en un dashboard o algo similar.
																								 
## Etapa 6. Transforme su programa en un programa de AppSec maduro

No debe detenerse en el OWASP Top 10. Sólo cubre 10 categorías de riesgo. Recomendamos enfáticamente a las organizaciones que adopten el [Estándar de Verificación de Seguridad de Aplicaciones](https://owasp.org/www-project-application-security-verification-standard/) (ASVS) de OWASP  y agreguen progresivamente componentes a la carretera pavimentada pensados en los niveles 1, 2 y 3, según el nivel objetivo determinado para cada aplicación desarrolladas.
	
## Yendo más allá

Todos los grandes programas de AppSec van más allá del mínimo indispensable. Todos deben ir más allá si queremos realmente superar las vulnerabilidades de AppSec.

-   **Integridad conceptual**. Los programas maduros de AppSec deben contener algún concepto de arquitectura de seguridad, ya sea una arquitectura formal de seguridad en la nube o empresarial o modelado de amenazas.

-   **Automatización y escala**. Los programas maduros de AppSec intentan automatizar la mayor cantidad de entregables posibles, utilizando scripts para emular pasos complejos de pruebas de penetración, herramientas de análisis de código estático directamente disponibles para los equipos de desarrollo, ayudando a los equipos de desarrollo a crear pruebas de integración y unitarias de AppSec, y más.

-   **Cultura**. Los programas maduros de AppSec intentan evitar el diseño inseguro y eliminan la deuda técnica del código existente al ser parte del equipo de desarrollo y no uno anexo. Los equipos de AppSec que ven a los equipos de desarrollo como "ellos" y "nosotros", están condenados al fracaso.

-   **Mejora continua**. Los programas maduros de AppSec buscan mejorar constantemente. Si algo no funciona, deje de hacerlo. Si algo es inútil o no escalable, trabaje para mejorarlo. Si los equipos de desarrollo no están utilizando algo o tiene un impacto nulo o limitado, haga algo diferente. El hecho de que hayamos realizado pruebas como comprobaciones de escritorio desde la década de 1970 no significa que sea una buena idea. Haga mediciones, evalúe y luego construya o mejore.
