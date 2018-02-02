# A1:2017 Injeção

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança           | Impactos               |
| -- | -- | -- |
| Access Lvl \| Exploitability 3 | Prevalence 2 \| Detectability 3 | Technical 3 \| Business |
| Quase qualquer fonte de dados pode ser um vetor de injeção, variáveis de ambiente, parâmetros, web services externas e internas e todos os tipos de usuários. [Falhas de injeção](https://www.owasp.org/index.php/Injection_Flaws) ocorrem quando um atacante pode enviar dados hostis a um interpretador. | As falhas de injeção são muito comuns, particularmente em código legado. As vulnerabilidades de injeção são freqüentemente encontradas em consultas SQL, LDAP, XPath ou NoSQL; Comandos de SO; parsers XML, cabeçalhos SMTP, expression languages e consultas ORM. As falhas de injeção são fáceis de descobrir ao examinar o código. Scanners e fuzzers podem ajudar os atacantes a encontrar falhas de injeção. | Injeção pode resultar em perda de dados ou corrupção, falta de responsabilidade ou negação de acesso. A injeção às vezes pode levar a uma aquisição completa do host. O impacto comercial depende das necessidades de proteção da sua aplicação e dos dados. |

## A Aplicação Está Vulnerável?

An application is vulnerable to attack when:

* User-supplied data is not validated, filtered, or sanitized by the application.
* Hostile data is used directly with dynamic queries or non-parameterized calls for the interpreter without context-aware escaping.
* Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.
* Hostile data is directly used or concatenated, such that the SQL or command contains both structure and hostile data in dynamic queries, commands, or stored procedures.
* Some of the more common injections are SQL, NoSQL, OS command, ORM, LDAP, and Expression Language (EL) or OGNL injection. The concept is identical among all interpreters. Source code review is the best method of detecting if your applications are vulnerable to injections, closely followed by thorough automated testing of all parameters, headers, URL, cookies, JSON, SOAP, and XML data inputs. Organizations can include static source ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) and dynamic application test ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) tools into the CI/CD pipeline to identify newly introduced injection flaws prior to production deployment.

## Como Prevenir?

Preventing injection requires keeping data separate from commands and queries.

* The preferred option is to use a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs). **Note**: When parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data, or executes hostile data with EXECUTE IMMEDIATE or exec().
* Use positive or "whitelist" server-side input validation, but this is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications.
* For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter. **Note**: SQL structure such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software.
* Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.

## Exemplos de Cenários de Ataque

**Scenario #1**: An application uses untrusted data in the construction of the following vulnerable SQL call:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Scenario #2**: Similarly, an application’s blind trust in frameworks may result in queries that are still vulnerable, (e.g. Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

In both cases, the attacker modifies the ‘id’ parameter value in their browser to send:  ' or '1'='1. For example:

`http://example.com/app/accountView?id=' or '1'='1`

This changes the meaning of both queries to return all the records from the accounts table. More dangerous attacks could modify or delete data, or even invoke stored procedures.

## Referências

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](TBA)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### Externas

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
