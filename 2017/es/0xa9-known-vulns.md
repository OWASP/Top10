# A9:2017 Uso de Componentes con Vulnerabilidades Conocidas

| Agentes de Amenazas/Vectores de Ataque | Debilidades de Seguridad           | Impactos               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 3 \| Detectability 2 | Technical 2 \| Business |
| Mientras que es sencillo de obtener exploits para vulnerabilidades ya conocidas, otras requieren un esfuerzo considerable para desarrollar un exploit personalizado. | La prevalencia de esta debilidad es muy difundida. El desarrollo basado fuertemente en componentes puede llevar al equipo de desarrollo a ni siquiera entender cuales componentes se utilizan en la aplicación o la API, mucho menos a mantenerlos actualizados. Esta debilidad es detectable mediante el uso de analizadores tales como retire.js o inspección de cabezales. La verificación de si es posible su explotación requiere de la descripción del posible ataque. | Mientras que ciertas vulnerabilidades conocidas conllevan impactos menores, algunas de las mayores brechas registradas hasta la fecha han sido realizadas explotando vulnerabilidades conocidas en componentes. Dependiendo de activo que se está protegiendo, este riesgo puede ser incluso el principal de su lista.|

## ¿Soy Vulnerable?

Es potencialmente vulnerable si:

* No conoce las versiones de todos los componentes que utiliza (tanto del lado del cliente como del servidor). Esto incluye componentes utilizados directamente como sus dependencias anidadas.
* Su software se encuentra desactualizado? Esto incluye el Sistema Operativo, Servidor Web o de Aplicaciones, DBMS, aplicaciones, APIS y todos los componentes, ambientes de ejecución y bibliotecas.
* Si no conoce si son vulnerables o no. Tanto si no investiga en busca de esta información cómo si no las analiza de forma periódica.
* Si no parchea o actualiza la plataforma subyacente, frameworks y dependencias en tiempo y forma. Esto sucede comunmente en ambientes en las cuales la aplicación de parches se realiza de forma mensual o trimestral bajo control de cambios, lo que deja a la organización abierta a varios días o meses de exposición innecesaria a vulnerabilidades ya solucionadas. Esta es probablemente la causa raiz de una de las mayores brechas de todos los tiempos.
* Si no asegura la configuración de los componentes correctamente (vea A6:2017-Configuración de Seguridad Incorrecta).

## ¿Cómo puedo prevenirlo?

Los proyectos de software deben poseer implementado un proceso para:

* Remover dependencias, funcionalidades, componentes, archivos y documentación innecesaria y no utilizada.
* Utilizar una herramienta para mantener un inventario contínuo  de las versiones tanto de los componentes en el cliente como en el servidor.
tales como [versions](http://www.mojohaus.org/versions-maven-plugin/), [DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/), etc.
* Monitorizar continuamente fuentes como [CVE](https://cve.mitre.org/) y [NVD](https://nvd.nist.gov/) en búsqueda de vulnerabilidades en los componentes que utiliza. Utilizar herramientas de análisis para automatizar el proceso.
* Obtener componentes únicamente de orígenes oficiales y, de ser posible, utilizar preferentemente paquete firmados con el fin de reducir las probabilidades de uso de componentes modificados maliciosamente.
* Varias bibliotecas y componentes no crean parches de seguridad para sus versiones obsoletas o sin soporte. Si el parcheo no es posible, considere desplegar un [parche virtual](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F) para monitorizar, detectar o protegerse contra la debilidad detectada.

Cada organización debe asegurar la existencia de un plan en ejecución para monitorizar, evaluar amenazas y aplicar actualizaciones o cambios de configuraciones durante el ciclo de vida de las aplicaciones o su documentación.

## Ejemplo de Escenarios de Ataque 

Típicamente, los componentes ejecutan con los mismos privilegios de la aplicación que los contienen y, como consecuencia, fallas en éstos pueden resultar en impactos serios. Estas fallas pueden ser accidentales (errores de codificación, por ejemplo) o intencionales ( una puerta trasera en un componente, por ejemplo). Algunos ejemplos de vulnerabilidades en componentes explotables son:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), una ejecución remota de código en Struts 2 que ha sido culpada de grandes brechas de datos.
* Aunque los dispositivos del [internet de las cosas (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) frecuentemente son imposibles o muy dificultosos de ser actualizados, la importancia de éstas actualizaciones puede ser enorme ( por ejemplo: [ Marcapasos St. Jude ]((http://www.zdnet.com/article/fda-forces-st-jude-pacemaker-recall-to-patch-security-vulnerabilities/)).

Existen herramientas automáticas que ayudan a los ataques a descubrir sistemas mal configurados o desactualizados. A modo de ejemplo, el [motor de búsqueda Shodan IoT](https://www.shodan.io/report/89bnfUyJ) ayuda a descubrir dispositivos que aún son vulnerables a [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed), la cual fue parcheada en abril del 2014.

## Referencias

### OWASP

* [Controles Proactivos de OWASP - TBA]()
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP - TBA]()
* [Guía de Pruebas de OWASP - TBA]()
* [Cheat sheet de OWASP - TBA]()
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Externas

* [The Unfortunate Reality of Insecure Libraries (Inglés)](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [Búsqueda en MITRE Common Vulnerabilities and Exposures (CVE)](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js para la detección de vulnerabilidades en bibliotecas de JavaScript](https://github.com/retirejs/retire.js/)
* [Consejos de seguridad para bibliotecas de Node](https://nodesecurity.io/advisories)
* [Base de datos de consejos de seguridad y herramientas para Ruby](https://rubysec.com/)
* [Snyk: Herramientas y base de datos de vulnerabilidades para Node/JS, Ruby, Java y Python](https://snyk.io/vuln)
