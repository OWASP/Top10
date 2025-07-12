# A1:2017 Injeção

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 3 | Prevalência 2 \| Detectabilidade 3 | Técnico 3 \| Negócio |
| Quase qualquer fonte de dados pode ser um vetor de injeção, variáveis de ambiente, parâmetros, web services externas e internas e todos os tipos de usuários. [Falhas de injeção](https://www.owasp.org/index.php/Injection_Flaws) ocorrem quando um atacante pode enviar dados hostis a um interpretador. | As falhas de injeção são muito comuns, particularmente em código legado. As vulnerabilidades de injeção são freqüentemente encontradas em consultas SQL, LDAP, XPath ou NoSQL; Comandos de SO; parsers XML, cabeçalhos SMTP, expression languages e consultas ORM. As falhas de injeção são fáceis de descobrir ao examinar o código. Scanners e fuzzers podem ajudar os atacantes a encontrar falhas de injeção. | Injeção pode resultar em perda ou corrupção de dados, falta de responsabilização ou negação de acesso. A injeção pode levar a que um atacante possa controlar completamente o servidor. O impacto comercial depende das necessidades de proteção da sua aplicação ou dos seus dados. |

## A Aplicação Está Vulnerável?

Uma aplicação é vulnerável a este ataque quando:

* Quando os dados fornecidos pelo usuário não são validados, filtrados ou limpos pela aplicação.
* Dados hostis são usados diretamente em pesquisas dinâmicas ou invocações não parametrizadas para um interpretador sem terem sido filtrados de acordo com o seu contexto.
* Os dados hostis são usados diretamente nos parâmetros de busca de mapeamento de objetos-relacionamentos (ORM) para extrair registros adicionais e sensíveis.
* Algumas das injeções mais comuns são SQL, NoSQL, comando do sistema operacional, ORM, LDAP e Expression Language (EL) ou injeção OGNL. O conceito é idêntico entre todos os intérpretes. A revisão do código-fonte é o melhor método para detectar se suas aplicações estão vulneráveis a injeções, seguidos de perto por testes automatizados completos de todos os parâmetros, cabeçalhos, URL, cookies, JSON, SOAP e entradas de dados XML. Organizações podem incluir testes de código fonte estáticos ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) e testes dinâmicos de aplicação ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) no fluxo de CI/CD (*Continuous Integration/Continuous Delivery*) para identificar as falhas de injeção recém-introduzidas antes da implantação em produção.

## Como Prevenir

Prevenir injeções requer que os dados estejam separados dos comandos e das consultas.

* A opção preferida é usar uma API segura, o que evite o uso exclusivo do interpretador ou que forneça uma interface parametrizada ou migrar para usar Object Relational Mapping Tools (ORMs). **Nota**: quando parametrizados, stored procedures ainda podem introduzir injeção de SQL se o PL/SQL ou T-SQL concatenar consultas e dados, ou executar dados hostis com EXECUTE IMMEDIATE ou exec ().
* Use a validação positiva de entrada do lado do servidor ou "lista branca", mas isso não é uma defesa completa, pois muitas aplicações requerem caracteres especiais, como áreas de texto ou APIs para aplicativos móveis.
* Para quaisquer consultas dinâmicas remanescentes, processe os caracteres especiais usando a sintaxe de escape específica para esse interpretador. **Nota**: Estruturas de SQL, como nomes de tabela, nomes de colunas, etc., não pode ser escapadas e, portanto, os nomes de estrutura fornecidos pelo usuário são perigosos. Este é um problema comum em software que produz relatórios.
* Use o LIMIT e outros controles de SQL dentro das consultas para prevenir a revelação não autorizada de grandes volumes de registros no caso de injeção de SQL.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação usa dados não confiáveis na construção da seguinte chamada de SQL vulnerável:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Cenário #2**: De forma similar, a confiança cega de uma aplicação em frameworks pode resultar em pesquisas que são igualmente vulneráveis, (ex.: Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

Em ambos os casos, um atacante modifica o valor do parâmetro 'id' no seu browser para enviar:  ' UNION SELECT SLEEP(10);--. Por exemplo:

`http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

Isto altera o significado de ambas as pesquisas para que retornem todos os registros da tabela "accounts".  Ataques mais perigosos podem modificar dados ou até invocar stored procedures.

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
