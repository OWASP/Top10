# A10:2021 – Falsificación de Solicitudes del Lado del Servidor (SSRF)    ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"}

## Factores

| CWEs mapeadas | Tasa de incidencia máx | Tasa de incidencia prom | Explotabilidad ponderada prom| Impacto ponderado prom | Cobertura máx | Cobertura prom | Incidencias totales | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 8.28                 | 6.72                | 67.72%       | 67.72%       | 9,503             | 385        |

## Resumen

Esta categoría se agrega debido a la encuesta de la comunidad Top 10 (primer lugar). Los datos muestran una tasa de incidencia relativamente baja con una cobertura de pruebas por encima del promedio, junto con calificaciones por encima del promedio para la capacidad de explotación e impacto. Como es probable que estas nuevas entradas sean una única o un pequeño grupo de Enumeraciones de debilidades comunes (CWE) para tomar en cuenta y concientizar sobre ellas, la esperanza es que se enfoque la atención en ellas y puedan integrarse en una categoría más amplia en una edición futura.

## Descripción 

Las fallas de SSRF ocurren cuando una aplicación web está obteniendo un recurso remoto sin validar la URL proporcionada por el usuario. Permite que un atacante coaccione a la aplicación para que envíe una solicitud falsificada a un destino inesperado, incluso cuando está protegido por un firewall, VPN u otro tipo de lista de control de acceso a la red (ACL).

Dado que las aplicaciones web modernas brindan a los usuarios finales funciones convenientes, la búsqueda de una URL se convierte en un escenario común. Como resultado, la incidencia de SSRF está aumentando. Además, la gravedad de SSRF es cada vez mayor debido a los servicios en la nube y la complejidad de las arquitecturas.

## Cómo se previene

Los desarrolladores pueden prevenir SSRF implementando algunos o todos los siguientes controles de defensa en profundidad:

### **Desde la capa de red**

-   Segmente la funcionalidad de acceso a recursos remotos en redes separadas para reducir el impacto de SSRF

-   Haga cumplir las políticas de firewall "denegar por defecto" o las reglas de control de acceso a la red para bloquear todo el tráfico de la intranet excepto el esencial.<br/> 
    *Consejos:*<br> 
    ~ Establezca la propiedad y un ciclo de vida para las reglas de firewall basadas en aplicaciones.<br/>
    ~ Registre en logs todos los flujos de red aceptados y bloqueados en firewalls (consulte [A09: 2021-Fallas en el Registro y Monitoreo](A09_2021-Security_Logging_and_Monitoring_Failures.md)).
    
### **Desde la capa de aplicación:**

-   Sanitice y valide todos los datos de entrada proporcionados por el cliente

-   Haga cumplir el esquema de URL, el puerto y destino a través de una lista positiva de items permitidos 

-   No envíe respuestas en formato "crudo" a los clientes

-   Deshabilite las redirecciones HTTP

-   Tenga en cuenta la coherencia de la URL para evitar ataques como el enlace de DNS y las condiciones de carrera de "tiempo de verificación, tiempo de uso" (TOCTOU por sus siglas en inglés)

No mitigue SSRF mediante el uso de una lista de denegación o una expresión regular. Los atacantes poseen listas de payloads, herramientas y habilidades para eludir las listas de denegación.

### **Medidas adicionales a considerar:**
    
-   No implemente otros servicios relevantes para la seguridad en los sistemas frontales (por ejemplo, OpenID). Controle el tráfico local en estos sistemas (por ejemplo, localhost)
    
-   Para frontends con grupos de usuarios dedicados y manejables, use el cifrado de red (por ejemplo, VPN) en sistemas independientes para considerar necesidades de protección muy altas  

## Ejemplos de escenarios de ataque

Los atacantes pueden usar SSRF para atacar sistemas protegidos detrás de firewalls de aplicaciones web, firewalls o ACLs de red, utilizando escenarios tales como:

**Escenario #1:** Escaneo de puertos de servidores internos – Si la arquitectura de red no se encuentra segmentada, los atacantes pueden trazar un mapa de las redes internas y determinar si los puertos están abiertos o cerrados en los servidores internos a partir de los resultados de la conexión o del tiempo transcurrido para conectar o rechazar las conexiones de payload SSRF.

**Escenario #2:** Exposición de datos sensibles: los atacantes pueden acceder a archivos locales como servicios internos para obtener información confidencial como `file:///etc/passwd</span>` y `http://localhost:28017/`.

**Escenario #3:** Acceso al almacenamiento de metadatos de los servicios en la nube: la mayoría de los proveedores de la nube tienen almacenamiento de metadatos como `http://169.254.169.254/`. Un atacante puede leer los metadatos para obtener información confidencial.

**Escenario #4:** Exposición de los servicios internos: el atacante puede abusar de los servicios internos para realizar más ataques, como la ejecución remota de código (RCE) o la denegación de servicio (DoS).

## Referencias

-   [OWASP - Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## Lista de CWEs mapeadas

[CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
