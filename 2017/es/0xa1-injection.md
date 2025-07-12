# A1:2017 Inyección

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad         |      Impactos       |
| -- | -- | -- |
| Nivel de acceso : Explotabilidad 3    | Prevalencia 2 : Detectabilidad 3 | Técnico 3 : Negocio |
| Casi cualquier fuente de datos puede ser un vector de inyección, variables de entorno, parámetros, servicios web externos e internos, y todo tipo de usuarios. [Los defectos de inyección](http://www.owasp.org/index.php/Injection_Flaws) ocurren cuando un atacante puede enviar información hostil a un intérprete. | Estos defectos son muy comunes, particularmente en código heredado. Las vulnerabilidades de inyección se encuentran a menudo en consultas SQL, LDAP, XPath, o NoSQL, comandos OS, analizadores XML, encabezados SMTP, lenguajes de expresión y consultas ORM. Los defectos de inyección son fáciles de descubrir al examinar el código. Los escáneres y los fuzzers pueden ayudar a los atacantes a encontrar defectos de inyecciones. | Una inyección puede causar divulgación, pérdida o corrupción de datos, pérdida de auditabilidad, o negación de acceso. El impacto del negocio depende de las necesidades de la aplicación y de los datos. |

## ¿La aplicación es vulnerable?

Una aplicación es vulnerable a ataque cuando:

* Los datos suministrados por el usuario no son validados, filtrados o sanitizados por la aplicación.
* Se invocan consultas dinámicas o no paremitrizadas sin codificar sus parámetros de forma acorde al contexto.
* Datos hostiles se utilizan dentro de los parámetros de búsqueda en consultas object-relational mapping (ORM) para extraer registros adicionales y sensibles.
* Datos hostiles se utilizan o concatenan directamente, de manera que el SQL o comando contiene tanto datos de estructura como hostiles en consultas dinámicas, comandos o procedimientos almacenados.
* Algunas de las inyecciones más comunes son SQL, NoSQL, comando OS, Object Relational Mapping (ORM), LDAP y Expresiones del Language (EL), o la inyección de la Biblioteca de Navegación Gráfica de Objetos (OGNL). El concepto es idéntico entre todos los intérpretes. La revisión del código fuente es el mejor método para detectar si las aplicaciones son vulnerables a inyecciones, seguido de cerca por pruebas automatizadas  de todos los parámetros, encabezados, URL, cookies, JSON, SOAP y entradas de datos XML. Las organizaciones pueden incluir herramientas de análisis estático ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools]) y pruebas dinámicas ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) en su pipeline de CI/CD para identificar defectos de inyecciones recientemente introducidas antes de su despliegue en producción.

## Cómo se previene

Para prevenir inyecciones, se requiere separar los datos de los comandos y las consultas.

* La opción preferida es utilizar una API segura, que evite el uso un intérprete en su totalidad o proporcione una interfaz parametrizada, o migrar a utilizar una Herramientas de Mapeo Relacional de Objetos (ORMs). Nota**: Incluso cuando se parametrizan, los procedimientos almacenados pueden introducir una inyección SQL si el procedimiento PL/SQL o T-SQL concatena consultas y datos, o ejecuta datos hostiles utilizando EXECUTE IMMEDIATE o exec().
* Utilizar validaciones de las entradade datos en el servidor utilizando "listas blancas". Esto no es una defensa completa ya que muchas aplicaciones requieren caracteres especiales en sus entradas, como campos de texto o APIs para aplicaciones móviles.
* Para cualquier consulta dinámica residual, escape caracteres especiales utilizando la sintaxis de escape de caracteres específica para ese intérprete. Nota**: La estructuras de SQL como nombres de tabla, nombres de columna, etc. no se puede escapar y, por lo tanto, los nombres de estructura suministrados por el usuario son peligrosos. Este es un problema común en el software de redacción de informes.
* Utilice LIMIT y otros controles SQL dentro de las consultas para evitar la divulgación masiva de registros en caso de inyección de SQL.

## Ejemplos de escenarios de ataque

**Escenario #1**: La aplicación utiliza datos no confiables en la construcción del siguiente llamado de SQL vulnerable:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Escenario #2**: En forma similar, la confianza total de una aplicación en su framework puede resultar en consultas que aún son vulnerables a inyección (por ejemplo Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

En ambos casos, al atacante modificar el parametro 'id' en su navegador para enviar:  ' UNION SELECT SLEEP(10);--. Por ejemplo:

* `http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

Esto cambia el significado de ambas consultas retornando todos los registro de la tabla "accounts". Ataques más peligrosos pueden modificar datos o incluso invocar procedimientos almacenados.

## Referencias (en inglés)

### OWASP

* [Controles Proactivos de OWASP: Consultas Parametrizadas](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [Estándar de Verificación de Seguridad en Aplicaciones de OWASP: V5 Validación de entradas de datos y codificación](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [Guía de Pruebas de OWASP: Inyecciones SQL](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Inyecciones de Comando](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [Inyecciones ORM](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [Hoja de ayuda de OWASP: Prevención de inyecciones SQL](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [Hoja de ayuda de OWASP: Prevención de inyecciones en Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [Hoja de ayuda de OWASP: Consultas parametrizadas](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [Hoja de ayuda de OWASP: Defensas contra inyecciones de Comandos](https://www.owasp.org/index.php/Command_Injection_Defense_Cheat_Sheet)

### Externas

* [CWE-77 Inyecciones de comandos](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89 Inyecciones SQL](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564 Inyecciones Hibernate](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917 Inyecciones de expresiones de lenguajes](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Inyecciones de plantillas en el servidor](https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection)
