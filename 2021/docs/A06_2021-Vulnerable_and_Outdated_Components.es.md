# A06:2021 – Componentes vulnerables y obsoletos    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Explotabilidad ponderada prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Resumen

Era el #2 de la encuesta de la comunidad Top 10, pero también tuvo datos suficientes para llegar al Top 10 a través del análisis de datos. Los componentes vulnerables son un problema conocido que es difícil de testear y evaluar el riesgo y es la única categoría que no tiene enumeraciones de debilidades comunes (CWE) asignadas a las CWE incluidas, por lo que se utiliza un peso de impacto/exploits predeterminado de 5.0. Las CWE notables incluidas son *CWE-1104: Uso de componentes de terceros no mantenidos* y las dos CWE del Top 10 2013 y 2017.

## Descripción

Usted probablemente sea vulnerable:

-   Si no conoce las versiones de todos los componentes que utiliza (tanto del lado del cliente como del lado del servidor). Esto incluye los componentes que usa directamente, así como las dependencias anidadas.

-   Si el software es vulnerable, carece de soporte o no está actualizado. Esto incluye el sistema operativo, el servidor web/de aplicaciones, el sistema de administración de bases de datos (DBMS), las aplicaciones, las API y todos los componentes, los entornos de ejecución y las bibliotecas.

-   Si no se actualiza sobre nuevas vulnerabilidades con regularidad y se suscribe a los boletines de seguridad relacionados con los componentes que utiliza.

-   Si no repara o actualiza la plataforma subyacente, los frameworks y las dependencias de manera oportuna y basada en el riesgo. Esto suele ocurrir en entornos en los que la aplicación de parches de seguridad es una tarea mensual o trimestral bajo control de cambios, lo que deja a las organizaciones abiertas a días o meses de exposición innecesaria a vulnerabilidades reparadas.

-   Si los desarrolladores de software no testean la compatibilidad de las bibliotecas actualizadas, actualizadas o parchadas.

-   Si no asegura las configuraciones de los componentes (consulte [A05: 2021-Configuración incorrecta de seguridad](A05_2021-Security_Misconfiguration.es.md)).

## Cómo se previene

Debe existir un proceso de administración de parches que:

-   Elimine las dependencias que no son utilizadas, las funciones, los componentes, los archivos y la documentación innecesarios.

-   Realice un inventario continuo de las versiones de los componentes del lado del cliente y del lado del servidor (por ejemplo, frameworks, bibliotecas) y sus dependencias utilizando herramientas como Versions Maven Plugin, OWASP Dependency Check, retire.js, etc. Supervise continuamente fuentes como Common Vulnerability and Exposures (CVE) y National Vulnerability Database (NVD) para detectar vulnerabilidades en los componentes. Utilice herramientas de análisis de composición de software para automatizar el proceso. Suscríbase para recibir alertas por correo electrónico sobre vulnerabilidades de seguridad relacionadas con los componentes que utiliza.

-   Solo obtenga componentes de fuentes oficiales a través de enlaces seguros.
    Prefiera los paquetes firmados para reducir la posibilidad de incluir un componente malicioso modificado (consulte A08: 2021-Fallos de integridad de datos y software).

-   Supervise las bibliotecas y los componentes que no se mantienen o no crean parches de seguridad para versiones anteriores. Si la aplicación de parches no es posible, considere implementar un parche virtual para monitorear, detectar o protegerse contra el problema descubierto.

Cada organización debe garantizar un plan continuo para monitorear, clasificar y aplicar actualizaciones o cambios de configuración durante la vida útil de la aplicación o portafolio de aplicaciones.

## Ejemplos de escenarios de ataque

**Escenario #1:** Los componentes normalmente se ejecutan con los mismos privilegios que la propia aplicación, por lo que las fallas en cualquier componente pueden tener un impacto grave. Tales fallas pueden ser accidentales (por ejemplo, error de codificación) o intencionales (por ejemplo, una puerta trasera en un componente). Algunos ejemplos de vulnerabilidades de componentes explotables descubiertos son:

-   CVE-2017-5638, una vulnerabilidad de ejecución remota de código de Struts 2 que permite la ejecución de código arbitrario en el servidor, ha sido acusada de infracciones importantes.

-   Si bien el Internet de las cosas (IoT) es con frecuencia difícil o imposible de parchear, la importancia de parchearlo puede ser grande (por ejemplo, dispositivos biomédicos).

Existen herramientas automatizadas para ayudar a los atacantes a encontrar sistemas sin parches o mal configurados. Por ejemplo, el motor de búsqueda Shodan IoT puede ayudarlo a encontrar dispositivos que aún sufren la vulnerabilidad Heartbleed parchada en abril de 2014.

## Referencias

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## Lista de CWEs mapeadas 

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
