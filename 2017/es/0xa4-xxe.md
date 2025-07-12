# A4:2017 Entidad Externa de XML (XXE)

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad         |      Impactos       |
| -- | -- | -- |
| Nivel de acceso : Explotabilidad 2    | Prevalencia 2 : Detectabilidad 3 | Técnico 3 : Negocio |
| Atacantes pueden explotar  procesadores XML vulnerables si pueden cargar XMLs o incluir contenido hostil en un documento XML, explotando código vulnerable, dependencias o integraciones. De forma predeterminada, muchos procesadores XML antiguos permiten la especificación de una entidad externa, una URI que se dereferencia y evalúa durante el procesamiento XML. Las herramientas[SAST](https://wiki.owasp.org/index.php/Source_Code_Analysis_Tools) pueden descubrir estos problemas inspeccionando las dependencias y la configuración. Las herramientas[DAST](https://wiki.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) requieren pasos manuales adicionales para detectar y explotar estos problemas. Los testers necesitan ser entrenados en cómo hacer pruebas para el XXE, ya que no eran comúnmente probados antes de 2017. Estos defectos se pueden utilizar para extraer datos, ejecutar una solicitud remota desde el servidor, escanear sistemas internos, realizar un ataque de denegación de servicio y ejecutar otros ataques. |

## ¿La aplicación es vulnerable?

Aplicaciones y en particular servicios web basados en XML o integraciones que utilicen XML pueden ser vulnerables al ataque si:

* La aplicación acepta XML directamente o carga XML, especialmente de fuentes no confiables, o inserta datos no confiables en documentos XML, los cuales son entonces analizados sintácticamente por un procesador XML.
* Cualquiera de los procesadores XML en la aplicación o servicios web basados en SOAP poseen habilitadas las [definiciones de tipo de documento (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition). Dado que los mecanismos exactos para deshabilitar el procesamiento de DTDs varía por procesador, se recomienda consultar una referencia como la [Hoja de ayuda para Prevención de XXE de OWASP](https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Si la aplicación utiliza SAML para el procesamiento de identidades dentro de la seguridad federada o para propósitos de single sign on (SSO). SAML utiliza XML para aseveraciones de identidad, pudiendo ser vulnerable.
* Si su aplicación utiliza SOAP en versión previa a la 1.2, es probablemente susceptible a ataques XXE si las entidades XML son pasadas a la infraestructura SOAP.
* Ser vulnerable a ataques XXE significa que probablemente la aplicación es vulnerable a ataques de denegación de servicio incluyendo el ataque de Mil Millones de Risas.

## Cómo se previene

El entrenamiento del desarrollador es esencial para identificar y mitigar defectos de XXE. Aparte de esto, prevenir XXE requiere:

* De ser posible, utilice formatos de datos menos complejos como JSON y evite la serialización de datos confidenciales.
* Parchee o actualice todos los procesadores y bibliotecas XML que utilice la aplicación o el sistema operativo subyacente. Utilice validadores de dependencias. Actualice SOAP a 1.2 o superior.
* Deshabilitar entidades externas de XML y procesamiento DTD en todos los analizadores sintácticos XML en su aplicación, según se indica en la [Hoja de Ayuda Para Prevención de XXE de OWASP](https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Implementar validación de entrada positiva ("lista blanca"), filtrado, o sanitización para prevenir datos hostiles dentro de documentos ,cabeceras o nodos XML.
* Verificar que la funcionalidad de carga de archivos XML o XSL valida el XML entrante usando validación XSD o similar.
* Herramientas SAST pueden ayudar a detectar XXE en el código fuente, aunque la revisión manual de código es la mejor alternativa en aplicaciones grandes y complejas con muchas integraciones.

Si estos controles no son posibles, considere usar parcheo virtual, gateways de seguridad de API, o Firewalls de Aplicaciones Web (WAFs) para detectar, monitorear, y bloquear ataques XXE. 

## Ejemplos de escenarios de ataque

Numerosos XXE han sido publicados, incluyendo el ataque a dispositivos embebidos. XXE ocurre en una gran cantidad de lugares inesperados, incluyendo dependencias profundamente anidadas. La manera más fácil es cargar un archivo XML malicioso, si es aceptado:

**Escenario #1**: El atacante intenta extraer datos del servidor:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Escenario #2**: Un atacante sondea la red privada del servidor cambiando la linea ENTITY anterior por:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Escenario #3**: Un atacante intenta un ataque de denegación de servicio incluyendo un archivo potencialmente infinto:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Referencias (en inglés)

### OWASP

* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Guía de Pruebas de OWASP: Pruebas para Inyección XML](https://wiki.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [Vulnerabilidad XXE de OWASP](https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [Hojas de ayuda de Prevención de XXE de OWASP](https://wiki.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [Hojas de ayuda de Seguridad XML de OWASP](https://wiki.owasp.org/index.php/XML_Security_Cheat_Sheet)

### Externas

* [CWE-611 Restricción Impropia de XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Ataque Mil Millones de Risas](https://en.wikipedia.org/wiki/Billion_laughs_attack)
