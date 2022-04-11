# A9:2017 Uso de Componentes con Vulnerabilidades Conocidas

| Agentes de Amenazas/Vectores de Ataque | Debilidades de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de Acceso : Exploitabilidad 2 | Prevalencia 3 : Detectabilidad 2 | Técnico 2 : Negocio |
| Mientras que es sencillo de obtener exploits para vulnerabilidades ya conocidas, otras requieren un esfuerzo considerable para desarrollar un exploit personalizado. | La prevalencia de estos defectos es muy difundida. El desarrollo basado fuertemente en componentes puede llevar al equipo de desarrollo a ni siquiera entender cuales componentes se utilizan en la aplicación o API, mucho menos a mantenerlos actualizados. Esta debilidad es detectable mediante el uso de analizadores tales como retire.js o inspección de cabezales. La verificación de si es posible su explotación requiere de la descripción del posible ataque. | Mientras que ciertas vulnerabilidades conocidas conllevan impactos menores, algunas de las mayores brechas registradas hasta la fecha han sido realizadas explotando vulnerabilidades conocidas en componentes. Dependiendo de activo que se está protegiendo, este riesgo puede ser incluso el principal de la lista.|

## ¿La aplicación es vulnerable?

Es potencialmente vulnerable si:

* No conoce las versiones de todos los componentes que utiliza (tanto del lado del cliente como del servidor). Esto incluye componentes utilizados directamente como sus dependencias anidadas.
* Su software es vulnerable, no posee soporte o se encuentra desactualizado Esto incluye el Sistema Operativo, Servidor Web o de Aplicaciones, DBMS, aplicaciones, APIS y todos los componentes, ambientes de ejecución y bibliotecas.
* No analiza los componentes periódicamente y se suscribe a los boletines de seguridad de los componentes que utiliza.
* No parchea o actualiza la plataforma subyacente, frameworks y dependencias en con un enfoque basado en riesgos. Esto sucede comunmente en ambientes en las cuales la aplicación de parches se realiza de forma mensual o trimestral bajo control de cambios, lo que deja a la organización abierta a varios días o meses de exposición innecesaria a vulnerabilidades ya solucionadas.
* No asegura la configuración de los componentes correctamente (consulte A6:2017-Configuración de Seguridad Incorrecta).

## ¿Como prevenirlo?

Debe de existir un proceso de gestión de parches para:

* Remover dependencias, funcionalidades, componentes, archivos y documentación innecesaria y no utilizada.
* Utilizar una herramienta para mantener un inventario contínuo de las versiones de los componentes (por ejemplo frameworks o bibliotecas) tanto en el cliente como en el servidor tales como versions, DependencyCheck, retire.js, etc.
* Monitorizar continuamente fuentes como CVE y NVD en búsqueda de vulnerabilidades en los componentes utilizados. Utilizar herramientas de análisis para automatizar el proceso. Suscribirse a alertas por email de alertas de seguridad en los componentes utilizados.
* Obtener componentes únicamente de orígenes oficiales utilizando canales seguros.Utilizar preferentemente paquete firmados con el fin de reducir las probabilidades de uso de versiones manipiladas maliciosamente.
* Monitorizar en búsqueda de bibliotecas y componentes que no poseen mantenimiento o no liberan parches de seguridad para sus versiones obsoletas o sin soporte. Si el parcheo no es posible, considere desplegar un parche virtual para monitorizar, detectar o protegerse contra la debilidad detectada.

Cada organización debe asegurar la existencia de un plan en ejecución para monitorizar, evaluar amenazas y aplicar actualizaciones o cambios de configuraciones durante el ciclo de vida de las aplicaciones o su documentación.

## Ejemplo de Escenarios de Ataque 

**Escenario #1**: Típicamente, los componentes ejecutan con los mismos privilegios de la aplicación que los contienen y, como consecuencia, fallas en éstos pueden resultar en impactos serios. Estas fallas pueden ser accidentales (errores de codificación, por ejemplo) o intencionales ( una puerta trasera en un componente, por ejemplo). Algunos ejemplos de vulnerabilidades en componentes explotables son:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), una ejecución remota de código en Struts 2 que ha sido culpada de grandes brechas de datos.
* Aunque los dispositivos del [internet de las cosas (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) frecuentemente son imposibles o muy dificultosos de ser actualizados, la importancia de éstas actualizaciones puede ser enorme ( por ejemplo dispositivos biomedicos).

Existen herramientas automáticas que ayudan a los atacantes a descubrir sistemas mal configurados o desactualizados. A modo de ejemplo, el [motor de búsqueda Shodan IoT](https://www.shodan.io/report/89bnfUyJ) ayuda a descubrir dispositivos que aún son vulnerables a [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed), la cual fue parcheada en abril del 2014.

## Referencias (en Inglés)

### OWASP

* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V1 Arquitectura, diseño y modelado de amenazas](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [Dependency Check de OWASP (para bibliotecas Java y .NET)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [Mejores Prácticas para el parcheo virtual de OWASP](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Externas

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [Búsquedas en MITRE Common Vulnerabilities and Exposures (CVE)](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js para la detección de vulnerabilidades en bibliotecas de JavaScript](https://github.com/retirejs/retire.js/)
* [Consejos de seguridad para bibliotecas de Node](https://nodesecurity.io/advisories)
* [Base de datos de consejos de seguridad y herramientas para Ruby](https://rubysec.com/)
* [Snyk: Herramientas y base de datos de vulnerabilidades para Node/JS, Ruby, Java y Python](https://snyk.io/vuln)
