# A05:2025 Inyección ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Antecedentes.

La Inyección cae dos posiciones del #3 al #5 en el ranking, manteniendo su posición relativa respecto a A04:2025-Fallos Criptográficos y A06:2025-Diseño Inseguro. La inyección es una de las categorías más probadas, con el 100% de las aplicaciones evaluadas para algún tipo de inyección. Tuvo el mayor número de CVEs de cualquier categoría, con 37 CWEs en esta categoría. La inyección incluye Cross-Site Scripting (XSS) (alta frecuencia/bajo impacto) con más de 30.000 CVEs e Inyección SQL (baja frecuencia/alto impacto) con más de 14.000 CVEs. La gran cantidad de CVEs reportados para CWE-79 Neutralización Inadecuada de Entradas Durante la Generación de Páginas Web ('Cross-site Scripting') reduce el impacto ponderado promedio de esta categoría.


## Tabla de puntuación.

<table>
  <tr>
   <td>CWEs Mapeados</td>
   <td>Tasa Máx. de Incidencia</td>
   <td>Tasa Prom. de Incidencia</td>
   <td>Cobertura Máx.</td>
   <td>Cobertura Prom.</td>
   <td>Explotabilidad Ponderada Prom.</td>
   <td>Impacto Ponderado Prom.</td>
   <td>Total de Ocurrencias</td>
   <td>Total de CVEs</td>
  </tr>
  <tr>
   <td>37</td>
   <td>13.77%</td>
   <td>3.08%</td>
   <td>100.00%</td>
   <td>42.93%</td>
   <td>7.15</td>
   <td>4.32</td>
   <td>1,404,249</td>
   <td>62,445</td>
  </tr>
</table>


## Descripción.

Una vulnerabilidad de inyección es una falla en una aplicación que permite que entradas no confiables del usuario sean enviadas a un intérprete (p. ej., un navegador, una base de datos, la línea de comandos) y provoca que el intérprete ejecute partes de esa entrada como comandos.

Una aplicación es vulnerable a estos tipos de ataque cuando:

* Los datos proporcionados por el usuario no son validados, filtrados ni sanitizados por la aplicación.
* Se invocan consultas dinámicas o llamadas no parametrizadas, sin codificar los parámetros de forma acorde al contexto, directamente en el intérprete.
* Se utilizan datos no sanitizados dentro de los parámetros de búsqueda en consultas de Mapeo Relacional de Objetos (ORM — Object-Relational Mapping), para extraer registros sensibles adicionales.
* Se utilizan datos potencialmente dañinos directamente o se concatenan. El SQL o comando resultante contiene la estructura y los datos maliciosos en consultas dinámicas, comandos o procedimientos almacenados.

Algunas de las inyecciones más comunes son SQL, NoSQL, comandos de sistema operativo (OS), Mapeo Relacional de Objetos (ORM), LDAP (Lightweight Directory Access Protocol) (Protocolo Ligero de Acceso a Directorios), y lenguaje de expresiones (EL) u Object Graph Navigation Library (OGNL). El concepto es idéntico para todos los intérpretes. La detección se logra mejor mediante una combinación de revisión de código fuente junto con pruebas automatizadas (incluyendo fuzzing) de todos los parámetros, encabezados, URL, cookies, datos JSON, SOAP y XML. La incorporación de herramientas de pruebas de seguridad de aplicaciones estáticas (SAST), dinámicas (DAST) e interactivas (IAST) en el pipeline de CI/CD también puede ser de utilidad para identificar fallas de inyección antes del despliegue en producción.

Una clase relacionada de vulnerabilidades de inyección se ha vuelto común en los LLMs. Estas se tratan por separado en el [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/), específicamente en [LLM01:2025 Inyección de Prompts (Prompt Injection)](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).


## Cómo se previene.

El mejor medio para prevenir inyecciones requiere mantener los datos separados de los comandos y las consultas:

* La opción preferida es utilizar una API segura, que evite el uso del intérprete por completo, proporcione una interfaz parametrizada, o migre a herramientas de Object-Relational Mapping (ORMs).
**Nota:** Incluso cuando se parametrizan, los procedimientos almacenados pueden seguir introduciendo inyección SQL si PL/SQL o T-SQL concatena consultas y datos, o si se ejecutan datos dañinos con EXECUTE IMMEDIATE o exec().

Cuando no sea posible separar los datos de los comandos, se pueden reducir las amenazas utilizando las siguientes técnicas.

* Implemente validaciones de entradas de datos del lado del servidor, utilizando "listas blancas" (allow-lists). De todos modos, esto no es una defensa completa, ya que muchas aplicaciones requieren el uso de caracteres especiales, como en campos de texto o APIs para aplicaciones móviles.
* Para cualquier consulta dinámica restante, escape los caracteres especiales utilizando la sintaxis de escape específica para el intérprete en cuestión.
**Nota:** Las estructuras SQL como nombres de tablas, nombres de columnas, etc. no pueden ser escapadas y, por lo tanto, los nombres de estructura suministrados por el usuario son peligrosos. Este es un problema común en el software de generación de informes.

**Advertencia:** estas técnicas implican el análisis sintáctico (parsing) y el escape de cadenas complejas, lo que las hace propensas a errores y poco robustas ante cambios menores en el sistema subyacente.

## Ejemplos de escenarios de ataque.

**Escenario #1:** Una aplicación utiliza datos no confiables en la construcción de la siguiente consulta SQL vulnerable:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

Un atacante modifica el valor del parámetro 'id' en su navegador para enviar: `' OR '1'='1`. Por ejemplo:

```
http://example.com/app/accountView?id=' OR '1'='1
```

Esto modifica el significado de la consulta para retornar todos los registros de la tabla accounts. Ataques más peligrosos podrían modificar o eliminar datos, o incluso invocar procedimientos almacenados.

**Escenario #2:** La confianza ciega de una aplicación en los frameworks puede dar lugar a consultas que siguen siendo vulnerables. Por ejemplo, Hibernate Query Language (HQL):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Un atacante suministra: `' OR custID IS NOT NULL OR custID='`. Esto elude el filtro y retorna todas las cuentas. Si bien HQL tiene menos funciones peligrosas que el SQL puro, sigue permitiendo el acceso no autorizado a datos cuando se concatenan entradas del usuario en las consultas.

**Escenario #3:** Una aplicación pasa la entrada del usuario directamente a un comando del sistema operativo:

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

Un atacante suministra `example.com; cat /etc/passwd` para ejecutar comandos arbitrarios en el servidor.

## Referencias.

* [OWASP Controles Proactivos: Acceso Seguro a Bases de Datos (Secure Database Access)](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Validación de Entradas y Codificación (Input Validation and Encoding)](https://owasp.org/www-project-application-security-verification-standard)
* [Guía de Pruebas OWASP: Inyección SQL (SQL Injection),](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Inyección de Comandos (Command Injection)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), y [Inyección ORM (ORM Injection)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* Guía de referencia rápida de OWASP: Prevención de Inyección (Injection Prevention)](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* Guía de referencia rápida de OWASP: Prevención de Inyección SQL (SQL Injection Prevention)](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* Guía de referencia rápida de OWASP: Prevención de Inyección en Java (Injection Prevention in Java)](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* Guía de referencia rápida de OWASP: Parametrización de Consultas (Query Parameterization)](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [Amenazas Automatizadas OWASP a Aplicaciones Web – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Inyección de plantillas del lado del servidor (Server-side template injection)](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: lista de recursos de fuzzing](https://github.com/secfigo/Awesome-Fuzzing)

## Lista de CWEs Mapeados

* [CWE-20 Validación Inadecuada de Entradas (Improper Input Validation)](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-74 Neutralización Inadecuada de Elementos Especiales en la Salida Usada por un Componente Posterior ('Inyección') (Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection'))](https://cwe.mitre.org/data/definitions/74.html)

* [CWE-76 Neutralización Inadecuada de Elementos Especiales Equivalentes (Improper Neutralization of Equivalent Special Elements)](https://cwe.mitre.org/data/definitions/76.html)

* [CWE-77 Neutralización Inadecuada de Elementos Especiales Usados en un Comando ('Inyección de Comandos') (Improper Neutralization of Special Elements used in a Command ('Command Injection'))](https://cwe.mitre.org/data/definitions/77.html)

* [CWE-78 Neutralización Inadecuada de Elementos Especiales Usados en un Comando del Sistema Operativo ('Inyección de Comandos OS') (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'))](https://cwe.mitre.org/data/definitions/78.html)

* [CWE-79 Neutralización Inadecuada de Entradas Durante la Generación de Páginas Web ('Secuencia de Comandos en Sitios Cruzados') (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'))](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-80 Neutralización Inadecuada de Etiquetas HTML Relacionadas con Scripts en una Página Web (XSS Básico) (Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS))](https://cwe.mitre.org/data/definitions/80.html)

* [CWE-83 Neutralización Inadecuada de Scripts en Atributos en una Página Web (Improper Neutralization of Script in Attributes in a Web Page)](https://cwe.mitre.org/data/definitions/83.html)

* [CWE-86 Neutralización Inadecuada de Caracteres Inválidos en Identificadores en Páginas Web (Improper Neutralization of Invalid Characters in Identifiers in Web Pages)](https://cwe.mitre.org/data/definitions/86.html)

* [CWE-88 Neutralización Inadecuada de Delimitadores de Argumentos en un Comando ('Inyección de Argumentos') (Improper Neutralization of Argument Delimiters in a Command ('Argument Injection'))](https://cwe.mitre.org/data/definitions/88.html)

* [CWE-89 Neutralización Inadecuada de Elementos Especiales Usados en un Comando SQL ('Inyección SQL') (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-90 Neutralización Inadecuada de Elementos Especiales Usados en una Consulta LDAP ('Inyección LDAP') (Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection'))](https://cwe.mitre.org/data/definitions/90.html)

* [CWE-91 Inyección XML (también conocida como Inyección XPath Ciega) (XML Injection (aka Blind XPath Injection))](https://cwe.mitre.org/data/definitions/91.html)

* [CWE-93 Neutralización Inadecuada de Secuencias CRLF ('Inyección CRLF') (Improper Neutralization of CRLF Sequences ('CRLF Injection'))](https://cwe.mitre.org/data/definitions/93.html)

* [CWE-94 Control Inadecuado de la Generación de Código ('Inyección de Código') (Improper Control of Generation of Code ('Code Injection'))](https://cwe.mitre.org/data/definitions/94.html)

* [CWE-95 Neutralización Inadecuada de Directivas en Código Evaluado Dinámicamente ('Inyección Eval') (Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection'))](https://cwe.mitre.org/data/definitions/95.html)

* [CWE-96 Neutralización Inadecuada de Directivas en Código Guardado Estáticamente ('Inyección de Código Estático') (Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection'))](https://cwe.mitre.org/data/definitions/96.html)

* [CWE-97 Neutralización Inadecuada de Inclusiones del Lado del Servidor (SSI) Dentro de una Página Web (Improper Neutralization of Server-Side Includes (SSI) Within a Web Page)](https://cwe.mitre.org/data/definitions/97.html)

* [CWE-98 Control Inadecuado del Nombre de Archivo para Sentencia Include/Require en Programas PHP ('Inclusión Remota de Archivos PHP') (Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion'))](https://cwe.mitre.org/data/definitions/98.html)

* [CWE-99 Control Inadecuado de Identificadores de Recursos ('Inyección de Recursos') (Improper Control of Resource Identifiers ('Resource Injection'))](https://cwe.mitre.org/data/definitions/99.html)

* [CWE-103 Struts: Definición Incompleta del Método validate() (Struts: Incomplete validate() Method Definition)](https://cwe.mitre.org/data/definitions/103.html)

* [CWE-104 Struts: Bean de Formulario No Extiende la Clase de Validación (Struts: Form Bean Does Not Extend Validation Class)](https://cwe.mitre.org/data/definitions/104.html)

* [CWE-112 Validación XML Faltante (Missing XML Validation)](https://cwe.mitre.org/data/definitions/112.html)

* [CWE-113 Neutralización Inadecuada de Secuencias CRLF en Cabeceras HTTP ('División de Respuesta HTTP') (Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting'))](https://cwe.mitre.org/data/definitions/113.html)

* [CWE-114 Control de Procesos (Process Control)](https://cwe.mitre.org/data/definitions/114.html)

* [CWE-115 Malinterpretación de la Salida (Misinterpretation of Output)](https://cwe.mitre.org/data/definitions/115.html)

* [CWE-116 Codificación o Escape Inadecuado de la Salida (Improper Encoding or Escaping of Output)](https://cwe.mitre.org/data/definitions/116.html)

* [CWE-129 Validación Inadecuada del Índice de Arreglo (Improper Validation of Array Index)](https://cwe.mitre.org/data/definitions/129.html)

* [CWE-159 Manejo Inadecuado del Uso Inválido de Elementos Especiales (Improper Handling of Invalid Use of Special Elements)](https://cwe.mitre.org/data/definitions/159.html)

* [CWE-470 Uso de Entrada Controlada Externamente para Seleccionar Clases o Código ('Reflexión Insegura') (Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection'))](https://cwe.mitre.org/data/definitions/470.html)

* [CWE-493 Variable Pública Crítica Sin Modificador Final (Critical Public Variable Without Final Modifier)](https://cwe.mitre.org/data/definitions/493.html)

* [CWE-500 Campo Estático Público No Marcado como Final (Public Static Field Not Marked Final)](https://cwe.mitre.org/data/definitions/500.html)

* [CWE-564 Inyección SQL: Hibernate (SQL Injection: Hibernate)](https://cwe.mitre.org/data/definitions/564.html)

* [CWE-610 Referencia Controlada Externamente a un Recurso en Otra Esfera (Externally Controlled Reference to a Resource in Another Sphere)](https://cwe.mitre.org/data/definitions/610.html)

* [CWE-643 Neutralización Inadecuada de Datos Dentro de Expresiones XPath ('Inyección XPath') (Improper Neutralization of Data within XPath Expressions ('XPath Injection'))](https://cwe.mitre.org/data/definitions/643.html)

* [CWE-644 Neutralización Inadecuada de Cabeceras HTTP para Sintaxis de Scripting (Improper Neutralization of HTTP Headers for Scripting Syntax)](https://cwe.mitre.org/data/definitions/644.html)

* [CWE-917 Neutralización Inadecuada de Elementos Especiales Usados en una Sentencia de Lenguaje de Expresiones ('Inyección de Lenguaje de Expresiones') (Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection'))](https://cwe.mitre.org/data/definitions/917.html)
