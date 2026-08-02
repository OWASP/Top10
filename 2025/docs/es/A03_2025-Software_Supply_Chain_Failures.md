# A03:2025 Fallas en la Cadena de Suministro de Software (Software Supply Chain Failures) ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## Antecedentes

Este fue el primer clasificado en la encuesta comunitaria del Top 10, con exactamente el 50% de los encuestados situándolo en el #1. Desde su aparición inicial en el Top 10 de 2013 como "A9 – Uso de Componentes con Vulnerabilidades Conocidas", el riesgo ha crecido en alcance para incluir todas las fallas de la cadena de suministro, no solo los que involucran vulnerabilidades conocidas. A pesar de este mayor alcance, las fallas en la cadena de suministro siguen siendo un reto de identificar, con solo 11 CVE (Common Vulnerability and Exposures)(Vulnerabilidades y Exposiciones Comunes)  que tienen los CWE (Common Weakness Enumeration) relacionados. Sin embargo, cuando se prueban y se informan en los datos aportados, esta categoría tiene la tasa de incidencia promedio más alta, con un 5.19%. Los CWE relevantes son *CWE-477: Uso de Función Obsoleta*, *CWE-1104: Uso de Componentes de Terceros no Mantenidos*, *CWE-1329: Dependencia en un Componente que no es Actualizable*, y *CWE-1395: Dependencia en un Componente de Terceros Vulnerable*.


## Tabla de puntuación


<table>
  <tr>
   <td>CWE Mapeados
   </td>
   <td>Tasa de Incidencia Máx.
   </td>
   <td>Tasa de Incidencia Prom.
   </td>
   <td>Cobertura Máx.
   </td>
   <td>Cobertura Prom.
   </td>
   <td>Explotación Ponderada Prom.
   </td>
   <td>Impacto Ponderado Prom.
   </td>
   <td>Ocurrencias Totales
   </td>
   <td>CVE Totales
   </td>
  </tr>
  <tr>
   <td>6
   </td>
   <td>9.56%
   </td>
   <td>5.72%
   </td>
   <td>65.42%
   </td>
   <td>27.47%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>



## Descripción

Las fallas en la cadena de suministro de software son rupturas u otros compromisos en el proceso de construcción, distribución o actualización del software. A menudo son causados por vulnerabilidades o cambios maliciosos en el código de terceros, herramientas u otras dependencias en las que confía el sistema.

Es probable que sea vulnerable si:

* no realiza un seguimiento cuidadoso de las versiones de todos los componentes que utiliza (tanto en el lado del cliente como en el del servidor). Esto incluye los componentes que utiliza directamente, así como las dependencias anidadas (transitivas).
* el software es vulnerable, no tiene soporte o está desactualizado. Esto incluye el sistema operativo (SO), el servidor web/de aplicaciones, el sistema de gestión de bases de datos (DBMS), las aplicaciones, las API y todos los componentes, entornos de ejecución y bibliotecas.
* no escanea regularmente en busca de vulnerabilidades y no se suscribe a boletines de seguridad relacionados con los componentes que utiliza.
* no dispone de un proceso de gestión de cambios o de un seguimiento de los mismos dentro de su cadena de suministro, incluyendo el seguimiento de los IDE, las extensiones y actualizaciones de los IDE, los cambios en el repositorio de código de su organización, los entornos aislados (sandboxes), los repositorios de imágenes y bibliotecas, la forma en que se crean y almacenan los artefactos, etc. Cada parte de su cadena de suministro debe estar documentada, especialmente los cambios.
* no ha bastionado (hardenizado) cada parte de su cadena de suministro, con especial atención al control de acceso y la aplicación del mínimo privilegio.
* sus sistemas de cadena de suministro no tienen ninguna separación de funciones (separation of duty). Ninguna persona debería poder escribir código y desplegarlo a producción sin la supervisión de otro ser humano.
* se utilizan en entornos de producción, o pueden impactar en ellos, componentes de fuentes no confiables en cualquier parte de la pila (stack)tecnológica.
* no corrige ni actualiza la plataforma subyacente, los frameworks y las dependencias de forma oportuna y basada en el riesgo. Esto suele ocurrir en entornos donde el parcheado es una tarea mensual o trimestral bajo control de cambios, dejando a las organizaciones abiertas a días o meses de exposición innecesaria antes de corregir las vulnerabilidades.
* los desarrolladores de software no prueban la compatibilidad de las bibliotecas actualizadas o parcheadas.
* no asegura las configuraciones de cada parte de su sistema (consulte [A02:2025-Configuración de Seguridad Incorrecta](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
* su flujo de CI/CD (CI/CD pipeline) tiene una seguridad más débil que los sistemas que construye y despliega, especialmente si es complejo.


## Cómo prevenir

Debe existir un proceso de gestión de parches para:



* Generar y gestionar de forma centralizada la Lista de Materiales de Software (Software Bill of Materials, SBOM) (inventario de componentes de software) de todo su software.
* Realizar un seguimiento no solo de sus dependencias directas, sino también de sus dependencias (transitivas), y así sucesivamente.
* Reducir la superficie de ataque eliminando las dependencias no utilizadas, las funciones innecesarias, los componentes, los archivos y la documentación.
* Inventariar continuamente las versiones de los componentes tanto del lado del cliente como del servidor (por ejemplo, frameworks, bibliotecas) y sus dependencias utilizando herramientas como OWASP Dependency Track, OWASP Dependency Check, retire.js, etc.
* Supervisar continuamente fuentes como Common Vulnerability and Exposures (CVE), National Vulnerability Database (NVD) y [Open Source Vulnerabilities (OSV)](https://osv.dev/) en busca de vulnerabilidades en los componentes que utiliza. Utilice herramientas de análisis de composición de software (Software Composition Analysis, SCA), de cadena de suministro de software o herramientas de SBOM centradas en la seguridad para automatizar el proceso. Suscríbase a alertas de vulnerabilidades de seguridad relacionadas con los componentes que utiliza.
* Obtener únicamente componentes de fuentes oficiales (confiables) a través de enlaces seguros. Prefiera los paquetes firmados para reducir la posibilidad de incluir un componente modificado y malicioso (consulte [A08:2025-Fallas en la Integridad del Software o de los Datos](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
* Elegir deliberadamente qué versión de una dependencia utiliza y actualizarla solo cuando sea necesario.
* Vigilar las bibliotecas y componentes que no reciben mantenimiento o que no crean parches de seguridad para versiones antiguas. Si no es posible parchear, considere la posibilidad de migrar a una alternativa. Si eso no es posible, considere el despliegue de un parche virtual para monitorizar, detectar o proteger contra el problema descubierto.
* Actualizar regularmente su CI/CD, IDE y cualquier otra herramienta de desarrollo.
* Evitar el despliegue de actualizaciones en todos los sistemas simultáneamente. Utilice despliegues escalonados o despliegues canario (canary deployments) para limitar la exposición en caso de que un proveedor de confianza se vea comprometido.


Debe existir un proceso de gestión de cambios o un sistema de seguimiento para rastrear los cambios en:

* Ajustes de CI/CD (continuous integration / continuous delivery-deployment) (todas las herramientas y flujos de construcción)
* Repositorios de código
* Áreas de pruebas (sandboxes)
* IDE de los desarrolladores
* Herramientas de SBOM y artefactos creados
* Sistemas de registro (logging) y registros (logs)
* Integraciones con terceros, como SaaS
* Repositorios de artefactos
* Registros de contenedores


Bastione (hardening) los siguientes sistemas, lo que incluye habilitar MFA (Multi-Factor Authentication) (Autenticación multifactor) y restringir el IAM (Identity and Access Management) (Gestión de Identidades y Accesos):

* Su repositorio de código (lo que incluye no subir secretos, proteger ramas, copias de seguridad)
* Estaciones de trabajo de los desarrolladores (parcheado regular, MFA, monitoreo y más)
* Tu servidor de compilación y CI/CD (separación de funciones, control de acceso, compilaciones firmadas, secretos con alcance de entorno, registros a prueba de manipulaciones, más)
* Sus artefactos (garantizar la integridad mediante la procedencia, la firma y la marca de tiempo (time stamp), promocionar artefactos en lugar de reconstruirlos para cada entorno, garantizar que las compilaciones sean inalterables)
* Infraestructura como código (gestionada como todo el código, incluyendo el uso de PRs (Pull Requests) y control de versiones)

Cada organización debe garantizar un plan continuo para monitorear, triar y aplicar actualizaciones o cambios de configuración durante toda la vida útil de la aplicación o portafolio.



## Escenarios de ejemplo de ataque

**Escenario #1:** Un proveedor de confianza es comprometido con malware, lo que provoca que sus sistemas informáticos sean comprometidos al actualizar. El ejemplo más famoso de esto es probablemente:



* El compromiso de SolarWinds en 2019 que llevó a que unas 18,000 organizaciones se vieran comprometidas. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Escenario #2:** Un proveedor de confianza es comprometido de tal manera que se comporta de forma maliciosa solo bajo una condición específica.



* El robo de 1,500 millones de dólares a Bybit en 2025 fue causado por [un ataque a la cadena de suministro en el software de la billetera (wallet)](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/) que solo se ejecutaba cuando se utilizaba la billetera objetivo.

**Escenario #3:** El ataque a la cadena de suministro [`Shai-Hulud`](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) en 2025 fue el primer gusano npm autopropagable con éxito. Los ataques sembraron versiones maliciosas de paquetes populares, que utilizaban un script de post-instalación para recolectar y exfiltrar datos sensibles a repositorios públicos de GitHub. El malware también detectaba tokens de npm en el entorno de la víctima y los utilizaba automáticamente para subir versiones maliciosas de cualquier paquete accesible. El gusano alcanzó más de 500 versiones de paquetes antes de ser interrumpido por npm. Este ataque a la cadena de suministro fue avanzado, de rápida propagación y dañino, y al dirigirse a las máquinas de los desarrolladores demostró que los propios desarrolladores son ahora objetivos principales para los ataques a la cadena de suministro.

**Escenario #4:** Los componentes suelen ejecutarse con los mismos privilegios que la propia aplicación, por lo que las fallas en cualquier componente pueden tener un impacto grave. Tales fallas pueden ser accidentales (por ejemplo, un error de progrmación) o intencionados (por ejemplo, una puerta trasera (backdoor) en un componente). Algunos ejemplos de vulnerabilidades de componentes explotables descubiertas son:

* CVE-2017-5638, una vulnerabilidad de ejecución remota de código en Struts 2 que permite la ejecución de código arbitrario en el servidor, ha sido señalada como la causa de brechas significativas.
* CVE-2021-44228 ("Log4Shell"), una vulnerabilidad de día cero de ejecución remota de código en Apache Log4j, ha sido señalada como la causa de campañas de ransomware, criptominería y otros ataques.


## Referencias

* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V15 Arquitectura y Codificación Segura] (OWASP Application Security Verification Standard (ASVS)) (https://owasp.org/www-project-application-security-verification-standard/)
* [Serie de guías rápidas de OWASP: SBOM de Gráfico de Dependencias](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [Serie de guías rápidas de OWASP: Gestión de Dependencias Vulnerables](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V1 Arquitectura, diseño y modelado de amenazas](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (para bibliotecas Java y .NET)](https://owasp.org/www-project-dependency-check/)
* Guía de Pruebas de OWASP - Map Application Architecture (OTG-INFO-010)
* [Mejores Prácticas de Parcheado Virtual de OWASP](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [La desafortunada realidad de las bibliotecas inseguras](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [Búsqueda de Vulnerabilidades y Exposiciones Comunes (CVE) de MITRE](https://www.cve.org)
* [Base de Datos Nacional de Vulnerabilidades (NVD)](https://nvd.nist.gov)
* [Retire.js para detectar bibliotecas JavaScript vulnerables conocidas](https://retirejs.github.io/retire.js/)
* [Base de datos de alertas de seguridad de GitHub](https://github.com/advisories)
* Base de datos de avisos de seguridad y herramientas para bibliotecas Ruby
* [Controles de Integridad de Software de SAFECode (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Ataque a la cadena de suministro Glassworm](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [Campaña de ataque a la cadena de suministro PhantomRaven](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## Lista de CWE Mapeados

* [CWE-447 Uso de Función Obsoleta (Use of Obsolete Function)](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 Top 10 2017 A9: Uso de Componentes con Vulnerabilidades Conocidas (2017 Top 10 A9: Using Components with Known Vulnerabilities)](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Uso de Componentes de Terceros no Mantenidos (Use of Unmaintained Third Party Components)](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Dependencia en un Componente que no es Actualizable (Reliance on Component That is Not Updatable)](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Dependencia en un Componente Insuficientemente Confiable (Reliance on Insufficiently Trustworthy Component)](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependencia en un Componente de Terceros Vulnerable (Dependency on Vulnerable Third-Party Component)](https://cwe.mitre.org/data/definitions/1395.html)
