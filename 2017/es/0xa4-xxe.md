# A4:2017 Entidades Externas XML (XXE)

| Agentes de Amenaza/Vectores de Ataque | Debilidad de Seguridad           | Impactos               |
| -- | -- | -- |
| Nivel de acceso \| Explotabilidad 2 | Prevalencia 2 \| Detectabilidad 3 | Técnico 3 \| Negocio |
| Atacantes que puedan acceder a páginas o servicios web, particularmente servicios web SOAP, que procesan XML. Los testeadores de penetración deberían ser capaces de explotar XXE una vez entrenados. Las herramientas DAST requieren pasos manuales adicionales para explotar este problema. | Por defecto, muchos procesadores XML antiguos permiten la especificación de una entidad externa, una URI que es leida y evaluada durante el procesamiento de XML. Las herramientas SAST pueden descubrir esta particularidad inspeccionando las dependencias y la configuración. | Estas fallas pueden ser usadas para extraer datos, ejecutar una solicitud remota desde el servidor, escanear sistemas internos, ejecutar un ataque de denegación de servicio, y otros ataques. El impacto al negocio depende de las necesidades de protección de todas/os las/os aplicaciones y datos afectados. |

## ¿Soy vulnerable a XXE?

Aplicaciones y en particular servicios web basados en XML o integraciones dependientes pueden ser vulnerables al ataque si:

* Su aplicación acepta XML directamente o cargas XML, especialmente de fuentes no confiables, o inserta datos no confiables en documentos XML, los cuales son entonces analizados sintácticamente por un procesador XML.
* Alguno de los procesadores XML en la aplicación o servicios web basados en SOAP tiene [definiciones de tipo de documento (DTDs)](https://en.wikipedia.org/wiki/Document_type_definition) habilitado. Como el mecanismo exacto para deshabilitar el procesamiento  DTD varía por procesador, se recomienda que consulte una referencia como la [Hoja de Trucos Para Prevención de XXE de OWASP](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Si su aplicación usa SOAP en versión previa a la 1.2, es probablemente susceptible a ataques XXE si las entidades XML son pasadas a la infraestructura SOAP.
* Las herramientas SAST pueden ayudar a detectar XXE en el código fuente, aunque la revisión manual del código es la mejor alternativa en aplicaciones grandes y complejas, con muchas integraciones.
* Ser vulnerable a ataques XXE probablemente significa que es vulnerable a otros ataques mil millones de risas de denegación de servicio.

## ¿Como prevenirlo?

El entrenamiento del desarrollador es esencial para identificar y mitigar XXE completamente. Aparte de esto, prevenir XXE requiere:

* Deshabilitar entidad externa XML y procesamiento DTD en todos los analizadores sintácticos XML en su aplicación, según se indica en la [Hoja de Trucos Para Prevención de XXE de OWASP](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet).
* Implementar validación de entrada positiva ("lista blanca"), filtrado, o sanitización para prevenir datos hostiles dentro de documentos , cabeceras, o nodos XML.
* Verificar que la funcionalidad de carga de archivos XML o XSL valida el XML entrante usando validación XSD o similar.
* Parchar o actualizar todos los últimos procesadores y bibliotecas XML en uso por la aplicación o en el sistema operativo subyacente. El uso de chequeadores de dependencias es crítico en administrar el riesgo de bibliotecas y componentes necesarios no solamente en su aplicación, sino también en cualquier integración dependiente.
* Actualizar SOAP a la última versión.

Si estos controles no son posibles, considere usar parcheo virtual, gateways de seguridad de API, o WAFs para detectar, monitorear, y bloquear ataques XXE. 

## Ejemplos de Escenarios de Ataques

Numerosos problemas XXE públicos han sido descubiertos, incluyendo el ataque a dispositivos embebidos. XXE ocurre en una gran cantidad de lugares inesperados, incluyendo dependencias profundamente anidadas. La manera más fácil es cargar un archivo XML malicioso, si es aceptado:

**Escenario #1**: El atacante intenta extraer datos del servidor:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Escenario #2**: Un atacante sondea la red privada del servidor cambiando la linea ENTITY superior a:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Escenario #3**: Un atacante intenta un ataque de denegación de servicio incluyendo un archivo potencialmente sin fin:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Referencias

### OWASP

* [Estándar de Verificación de Seguridad de Aplicación de OWASP](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [Guia de Testeo de OWASP - Testeo para Inyección XML](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [Vulnerabilidad XXE de OWASP](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [Hoja de Trucos de Prevención de XXE de OWASP](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [Hoja de Trucos de Seguridad XML de OWASP](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### Externas

* [CWE-611 Restricción Impropia de XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Ataque Mil Millones de Risas](https://en.wikipedia.org/wiki/Billion_laughs_attack)
