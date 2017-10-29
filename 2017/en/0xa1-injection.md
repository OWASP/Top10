# A1:2017 Inyección

| Agentes de amenaza/Vectores de ataque | Debilidades de seguridad           | Impacto               |
| -- | -- | -- |
| Nivel de acceso \| Explotabilidad FÁCIL | Prevalencia COMÚN \| Detección PROMEDIO | Impacto técnico SEVERO \| Impacto al negocio |
| Cualquier fuente de información puede ser un vector de inyección, incluyendo usuarios, parámetros, web services internos y externos, y todos los tipos de usuarios. [Las fallas de inyección](http://www.owasp.org/index.php/Injection_Flaws) ocurren cuando un atacante puede enviar información maliciosa a un intérprete. | Las fallas de inyección son muy prevamentes, especialmente en código legado. Habitualmente son halladas en SQL, LDAP, XPath o consultas NoSQL, comandos del sistema operativo, parsers XML, cabezales SMTP, lenguajes de expresiones, consultas ORM. Las fallas de inyección son fáciles de descubrir al examinar el código. Los analizadores y "fuzzers" pueden ayudar a encontrar fallas de inyección. | Una inyección puede causar pérdida o corrupción de datos, pérdida de responsabilidad o negación de acceso. A veces una inyección puede llevar al compromiso total del servidor. El impacto en el negocio depende de las necesidades de protección de su aplicación e información. |

## Am I vulnerable to Injection?

An application is vulnerable to attack when:

* User suppled data is not validated, filtered or sanitized by the application.
* Hostile data is used directly with dynamic queries or non-parameterized calls for the interpreter without context-aware escaping.
* Hostile data is used within ORM search parameters such that the search evaluates out to include sensitive or all records.
* Hostile data is directly used or concatenated, such that the SQL or command contains both structure and hostile data in dynamic queries, commands, or in stored procedures.

Some of the more common injections are SQL, OS command, ORM, LDAP, and Expression Language (EL) or OGNL injection.. The concept is identical between all interpreters. Organizations can include SAST and DAST tooling into the CI/CD pipeline to alert if existing or newly checked in code has injection prior to production deployment. Manual and automated source code review is the best method of detecting if you are vulnerable to injections, closely followed by thorough DAST scans of all parameters, fields, headers, cookies, JSON, and XML data inputs.

## ¿Cómo prevenirlo?

Evitar una inyección requiere mantener los datos separados de los comandos y consultas.

* La opción preferida es usar una API segura la cual evite el uso de interpretes por cmpleto o provea una interfaz parametrizada, o realizar una migración para utilizar ORMs o Entity Framework. **NB**: Aunque estén parametrizados, los procedimientos almacenados (stored procedures) igualmente pueden permitir inyección SQL si PL/SQL o T-SQL concatena las consultas y los datos, o ejecuta código malicioso utilizando EXECUTE IMMEDIATE() o exec().
* La validación de entradas positiva o de "lista blanca" también se recomienda, pero no es una defensa integral dado que muchas aplicaciones requieren caracteres especiales en sus entradas.
* Para las consultas dinámicas restantes, excluya caracteres especiales usando la sintaxis específica para su intérprete. El Codificador JAVA de OWASP y librerías similares proveen las rutinas de exclusión. **NB** La estructura SQL como por ejemplo nombres de tabla o columna y demás no pueden ser excluidas, por lo que nombres de estructura proporcionados por el usuario son peligrosos. Este es un problema común en software de generación de reportes.
* Use LIMIT y otros controles SQL en las consultas para prevenir la divulgación masiva de registros en caso de ser atacados mediante inyección SQL.

## Example Attack Scenarios

**Scenario #1**: An application uses untrusted data in the construction of the following vulnerable SQL call:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Scenario #2**: Similarly, an application’s blind trust in frameworks may result in queries that are still vulnerable, (e.g. Hibernate Query Language (HQL)):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

In both cases, the attacker modifies the 'id’ parameter value in her browser to send:  ' or '1'='1. For example:
* `http://example.com/app/accountView?id=' or '1'='1`

This changes the meaning of both queries to return all the records from the accounts table.  More dangerous attacks could modify data or even invoke stored procedures.

## References

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](TBA)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Cheat Sheet: Command Injection Defense](https://www.owasp.org/index.php/Command_Injection_Defense_Cheat_Sheet)

### External

* [CWE-77 Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89 SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564 Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917 Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection)
