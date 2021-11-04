# A03:2021 – Inyección    ![icon](assets/TOP_10_Icons_Final_Injection.png)

## Factores

| CWEs Mapeados | Tasa de Incidencia Máxima | Tasa de Incidencia Promeedia | Explotación Ponderada Promedio | Impacto Ponderado Promedio | Covertura Màxima | Coverturra Promedia | Incidencias Totales| CVEs Totales |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 33          | 19.09%             | 3.37%              | 7.25                 | 7.15                | 94.04%       | 47.90%       | 274,228           | 32,078     |

## Vision General

la Inyección se desliza hasta la tercera posicion. El 94% de las aplicaciones fueron probadas sobre alguna forma de inyeccón con una tasa de incidencia máxima del 19%, una tasa de incidencia promedio del 3% y 274 mil ocurrencias. Los CWE notables incluidos son *CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, y la *CWE-73:Control Externo de Nombre de archivos o ruta*. 

## Descripción 

Una aplicación es vulnerable a este ataque cuando:

-   Los datos proporcionados por el usuario no son validados, filtrados ni sanitizados por la aplicación.

-   Se invocan consultas dinámicas o no parametrizadas, sin codificar los parámetros de forma acorde al contexto.

-   Se utilizan datos dañinos dentro de los parámetros de búsqueda en consultas Object-Relational Mapping (ORM), para extraer registros adicionales sensibles.

-   Los datos dañinos se usan directamente o se concatenan, de modo que el SQL o comando resultante contiene datos y estructuras con consultas dinámicas, comandos o procedimientos almacenados.

Algunas de las inyecciones más comunes son SQL, NoSQL,comandos de SO, Object-Relational Mapping (ORM), LDAP,
expresiones de lenguaje u Object Graph Navigation Library (OGNL).
El concepto es idéntico entre todos los intérpretes. La revisión del código fuente es el mejor método para detectar si las aplicaciones son vulnerables a inyecciones, seguido de cerca por pruebas automatizadas de todos los parámetros, encabezados, URL, cookies,JSON, SOAP y entradas de datos XML.

Las organizaciones pueden incluir herramientas de análisis estático (SAST) y pruebas dinámicas (DAST) para identificar errores de inyecciones recientemente introducidas y antes del despliegue de la aplicación en producción.

## Cómo prevenir

Para prevenir inyecciones, se requiere separar los datos de los comandos y las consultas.

-   La opción preferida es utilizar una API segura, que evite el uso de un intérprete por completo y proporcione una interfaz parametrizada. Se debe migrar y utilizar una herramientas de Mapeo Relacional de Objetos (ORMs).<br/>
    **Nota:** : Incluso cuando se parametrizan, los procedimientos almacenados pueden introducir una inyección SQL si el procedimiento PL/SQL o T-SQL concatena consultas y datos, o se ejecutan parámetros utilizando EXECUTE IMMEDIATE o exec().

-   Realice validaciones de entradas de datos en el servidor,utilizando "listas blancas". De todos modos, esto no es una defensa completa ya que muchas aplicaciones requieren el uso de caracteres especiales, como en campos de texto, APIs o aplicaciones móviles.

-   Para cualquier consulta dinámica residual, escape caracteres especiales utilizando la sintaxis de caracteres específica para el intérprete que se trate.<br/>
    **Nota:** La estructura de SQL como nombres de tabla, nombres de columna, etc. no se pueden escapar y, por lo tanto, los nombres de estructura suministrados por el usuario son peligrosos. Este es un problema común en el software de redacción de informes.

-   Utilice LIMIT y otros controles SQL dentro de las consultas para evitar la fuga masiva de registros en caso de inyección SQL.

## Ejemplos de escenarios de ataque

**Escenario #1:** Una aplicación usa datos no confiables en la construcción de la siguiente llamada SQL vulnerable:
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Escenario #2:** Del mismo modo, la confianza total de una aplicación en su framework
puede resultar en consultas que aún son vulneables a inyeccón, (por ejemplo: Hibernate Query
Language (HQL)):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

En ambos casos, el atacante modifica el valor del parámetro "id" en su navegador para enviar: ‘ or ‘1’=’1. Por ejemplo:
```
 http://example.com/app/accountView?id=' or '1'='1
```

Esto cambia el significado de ambas consultas, devolviendo
todos los registros de la tabla “accounts”. Ataques más
peligrosos podrían modificar los datos o incluso invocar
procedimientos almacenados.

## Referencias

-   [OWASP Controles Proavtivos: Acceso Seguro a la Base de Datos](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: Validación y codificación de entrada V5](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Guia de prueba: Inyección SQL,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Inyeccón de comandos](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    [Inyección ORM](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Prevención de Inyecciones](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Prevención de Inyeccón SQL](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Prevención de Inyecciones en Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Parametrización de consultas](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Amenazas automatizadas para aplicaciones web – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Inyeccón de plantilla del lado del servidor](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Lista de CWEs mapeadas

[CWE-20 Validación de entrada incorrecta](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Neutralización incorrecta de elementos especiales en la salida utilizada por un Componente descendente ('Inyección')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 No desinfectar elementos especiales en un plano diferente (Inyección de elementos especiales)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Neutralización incorrecta de elementos especiales utilizados en un comando ('Inyección de comandos')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Neutralización incorrecta de elementos especiales utilizados en un comando del sistema operativo ('Inyección de comandos del sistema operativo')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Neutralización incorrecta de la entrada durante la generación de la página web ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Neutralización incorrecta de etiquetas HTML relacionadas con secuencias de comandos en una página web (XSS básico)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Neutralización incorrecta de secuencias de comandos en atributos en una página web](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Neutralización incorrecta de la sintaxis XSS alternativa](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Neutralización inadecuada de los delimitadores de argumentos en un comando ('Inyección de argumentos')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Neutralización incorrecta de elementos especiales utilizados en un comando SQL ('Inyección SQL')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Neutralización incorrecta de elementos especiales utilizados en una consulta LDAP ('Inyección LDAP')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (también conocido como Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Neutralización incorrecta de secuencias CRLF ('Inyección CRLF')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Control inadecuado de la generación de código ('Inyección de código')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Neutralización incorrecta de directivas en código evaluado dinámicamente ('Inyección de evaluación')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Neutralización incorrecta de directivas en código guardado estáticamente ('Inyección de código estático')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Neutralización incorrecta de las inclusiones del lado del servidor (SSI) dentro de una página web](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Control incorrecto del nombre de archivo para la declaración Incluir / Requerir en el programa PHP ('Inclusión remota de archivos PHP')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Control inadecuado de identificadores de recursos ('Inyección de recursos')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 En desuso: era general para problemas de validación de entrada](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Neutralización incorrecta de secuencias CRLF en encabezados HTTP ('División de respuesta HTTP')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Codificación incorrecta o escape de salida](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Neutralización inadecuada de elementos especiales](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Lista incompleta de entradas no permitidas](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Uso de entrada controlada externamente para seleccionar clases o código ('Reflexión insegura')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modificación de datos supuestos-inmutables (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[Inyección SQL CWE-564: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Referencia controlada externamente a un recurso en otra esfera](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Neutralización incorrecta de datos dentro de expresiones XPath ('Inyección XPath')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Neutralización incorrecta de encabezados HTTP para sintaxis de secuencias de comandos](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Neutralización incorrecta de datos dentro de expresiones XQuery ('Inyección XQuery')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Neutralización inadecuada de elementos especiales utilizados en una declaración de lenguaje de expresión ('Inyección de lenguaje de expresión')](https://cwe.mitre.org/data/definitions/917.html)