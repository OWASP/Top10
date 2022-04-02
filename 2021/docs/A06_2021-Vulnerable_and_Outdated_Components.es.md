# A06:2021 – Componentes Vulnerables y Desactualizados    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Explotabilidad ponderada prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Resumen

Era el segundo de la encuesta de la comunidad Top 10, pero también tuvo datos suficientes para llegar al Top 10 a través del análisis de datos. Los componentes vulnerables son un problema conocido que es difícil de probar y evaluar el riesgo. Es la única categoría que no tiene enumeraciones de debilidades comunes (CWE) asignadas a las CWE incluidas, por lo que se utiliza un peso de impacto/exploits predeterminado de 5,0. Las CWE notables incluidas son *CWE-1104: Uso de componentes de terceros no mantenidos* y las dos CWE del Owasp Top 10 2013 y 2017.

## Descripción

Usted probablemente sea vulnerable:

-   Si no conoce las versiones de todos los componentes que utiliza (tanto en el cliente como en el servidor). Esto incluye los componentes que usa directamente, así como las dependencias anidadas.

-   Si el software es vulnerable, carece de soporte o no está actualizado. Esto incluye el sistema operativo, el servidor web/de aplicaciones, el sistema de administración de bases de datos (DBMS), las aplicaciones, las API y todos los componentes, los entornos de ejecución y las bibliotecas.

-   Si no analiza en búsqueda de vulnerabilidades de forma regular y no se suscribe a los boletines de seguridad relacionados con los componentes que utiliza.

-   Si no repara o actualiza la plataforma subyacente, frameworks y dependencias de manera oportuna y basada en el riesgo. Esto suele ocurrir en entornos en los que la aplicación de parches de seguridad es una tarea mensual o trimestral bajo control de cambios, lo que deja a las organizaciones abiertas a días o meses de exposición innecesaria a vulnerabilidades con soluciones disponibles.

-   Si los desarrolladores de software no testean la compatibilidad de las bibliotecas actualizadas, actualizadas o parcheadas.

-   Si no asegura las configuraciones de los componentes (consulte [A05:2021 – Configuración de Seguridad Incorrecta](A05_2021-Security_Misconfiguration.es.md)).

## Cómo se previene

Debe existir un proceso de administración de parches que:

-   Elimine las dependencias que no son utilizadas, funcionalidades, componentes, archivos y documentación innecesarios.

-   Realice un inventario continuo de las versiones de los componentes en el cliente y en el servidor (por ejemplo, frameworks, bibliotecas) y sus dependencias utilizando herramientas como: versions, OWASP Dependency Check, retire.js, etc. Supervise continuamente fuentes como Common Vulnerability and Exposures (CVE) y National Vulnerability Database (NVD) para detectar vulnerabilidades en los componentes. Utilice herramientas de análisis de composición de software para automatizar el proceso. Suscríbase para recibir alertas por correo electrónico sobre vulnerabilidades de seguridad relacionadas con los componentes que utiliza.

-   Solo obtenga componentes de fuentes oficiales a través de enlaces seguros.
    Prefiera los paquetes firmados para reducir la posibilidad de incluir un componente malicioso modificado (consulte [A08:2021 – Fallas en el Software y en la Integridad de los Datos](A08_2021-Software_and_Data_Integrity_Failures.es.md)).

-   Supervise las bibliotecas y los componentes que no sea mantenidos o no generen parches de seguridad para versiones anteriores. Si la aplicación de parches no es posible, considere implementar un parche virtual para monitorear, detectar o protegerse contra el problema descubierto.

Toda organización debe garantizar un plan continuo para monitorear, clasificar y aplicar actualizaciones o cambios de configuración durante la vida útil de la aplicación o portafolio de aplicaciones.

## Ejemplos de escenarios de ataque

**Escenario #1:** Los componentes normalmente se ejecutan con los mismos privilegios que la propia aplicación, por lo que las fallas en cualquier componente pueden tener un impacto grave. Tales fallas pueden ser accidentales (por ejemplo, error de codificación) o intencionales (por ejemplo, una puerta trasera en un componente). Algunos ejemplos de vulnerabilidades de componentes explotables descubiertos son:

-   CVE-2017-5638, una vulnerabilidad de ejecución remota de código de Struts 2 que permite la ejecución arbitraria de código en el servidor, ha sido culpada de brechas importantes.

-   Si bien el Internet de las Cosas (IoT) es con frecuencia difícil o imposible de parchear, la importancia de parchearlo puede ser grande (por ejemplo, dispositivos biomédicos).

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
