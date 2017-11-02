# A1:2017 Inyección

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad           | Impacto               |
| -- | -- | -- |
| Nivel de acceso \| Explotabilidad FÁCIL | Prevalencia COMÚN \| Detección PROMEDIO | Impacto técnico SEVERO \| Impacto al negocio |
| Cualquier fuente de información puede ser un vector de inyección, incluyendo usuarios, parámetros, web services internos y externos, y todos los tipos de usuarios. [Las fallas de inyección](http://www.owasp.org/index.php/Injection_Flaws) ocurren cuando un atacante puede enviar información maliciosa a un intérprete. | Las fallas de inyección son muy prevamentes, especialmente en código legado. Habitualmente son halladas en SQL, LDAP, XPath o consultas NoSQL, comandos del sistema operativo, parsers XML, cabezales SMTP, lenguajes de expresiones, consultas ORM. Las fallas de inyección son fáciles de descubrir al examinar el código. Los analizadores y "fuzzers" pueden ayudar a encontrar fallas de inyección. | Una inyección puede causar pérdida o corrupción de datos, pérdida de responsabilidad o negación de acceso. A veces una inyección puede llevar al compromiso total del servidor. El impacto en el negocio depende de las necesidades de protección de su aplicación e información. |

## ¿Soy vulnerable?

Una aplicación es vulnerable cuando:

* La información proporcionada por el usuario no es validada, filtrada o sanitizada por la aplicación.
* Se utiliza información maliciosa directamente en consultas dinámicas o llamadas no parametrizadas en el intérprete, sin utilizar exclusiones dependientes del contexto.
* Se utiliza información maliciosa en parámetros de búsqueda ORM con el fin que la búsqueda incluya registros sensibles o todos los registros.
* Se utiliza información maliciosa directamente o concatenada, para que el código SQL incluya datos de estructura e información maliciosa en las consultas dinámicas, comandos, o procedimientos almacenados. 

Algunas de las inyecciones más frecuentes son SQL, comandos del sistema operativo, ORM, LDAP y lenguaje de expresión (EL) o inyección OGNL. El concepto es idéntico para todos los intérpretes. Las organiaciones pueden incluir herramientas SAST o DAST en el pipeline CI/CD para notificar si el código existente o nuevo contiene fallas de inyección previo a la puesta en producción. La revisión de código manual y automática es el mejor método para detectar si se es vulnerable a inyecciones, seguido por el análisis DAST minucioso de todos los parámetros, campos, cabezales, cookies, y entradas JSON y XML.

## ¿Cómo prevenirlo?

Evitar una inyección requiere mantener los datos separados de los comandos y consultas.

* La opción preferida es usar una API segura la cual evite el uso de interpretes por cmpleto o provea una interfaz parametrizada, o realizar una migración para utilizar ORMs o Entity Framework. **NB**: Aunque estén parametrizados, los procedimientos almacenados (stored procedures) igualmente pueden permitir inyección SQL si PL/SQL o T-SQL concatena las consultas y los datos, o ejecuta código malicioso utilizando EXECUTE IMMEDIATE() o exec().
* La validación de entradas positiva o de "lista blanca" también se recomienda, pero no es una defensa integral dado que muchas aplicaciones requieren caracteres especiales en sus entradas.
* Para las consultas dinámicas restantes, excluya caracteres especiales usando la sintaxis específica para su intérprete. El Codificador JAVA de OWASP y librerías similares proveen las rutinas de exclusión. **NB** La estructura SQL como por ejemplo nombres de tabla o columna y demás no pueden ser excluidas, por lo que nombres de estructura proporcionados por el usuario son peligrosos. Este es un problema común en software de generación de reportes.
* Use LIMIT y otros controles SQL en las consultas para prevenir la divulgación masiva de registros en caso de ser atacados mediante inyección SQL.

## Ejemplos de escenarios de ataques

**Escenario #1**: Una aplicación usa información no confiable en la construcción de la siguiente consulta SQL vulnerable a inyección::

```
Consulta SQLQuery= "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Escenario #2**: En forma similar, la confianza total de una aplicación en frameworks puede resultar en consultas que aún son vulnerables a inyección (por ejemplo Hibernate Query Language (HQL)):

```
Consulta HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

En ambos casos, un atacante modifica el parámetro 'id' en su navegador para enviar ' o '1'='1. Por ejemplo:
* `http://example.com/app/accountView?id=' or '1'='1`

Esto modifica ambas consultas para que retornen todos los registros de la tabla accounts. Ataques más peligrosos podrían modificar información o invocar procedimientos almacenados.

## Referencias

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](TBA)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Cheat Sheet: Command Injection Defense](https://www.owasp.org/index.php/Command_Injection_Defense_Cheat_Sheet)

### Externas

* [CWE-77 Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89 SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564 Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917 Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection)
