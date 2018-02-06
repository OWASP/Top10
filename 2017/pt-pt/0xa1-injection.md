# A1:2017 Injecção

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 3 | Prevalência 2 \| Detecção 3 | Técnica 3 \| Negócio |
| Quase todas as fontes de dados podem ser um vector de injecção, incluindo utilizadores, parâmetros, serviços web internos e externos, e todos os tipos de utilizadores. [Falhas de injecção][1] ocorrem quando um atacante pode enviar dados hostis para um interpretador. | As falhas de injecção são muito prevalentes, em especial em código legado. São encontrados frequentemente em pesquisas SQL, LDAP, XPath, ou NoSQL; comandos do SO; processadores de XML, cabeçalhos de SMTP, linguagens de expressões, pesquisas ORM. As falhas de injecção são fáceis de descobrir aquando da análise do código. Scanners e fuzzers podem ajudar os atacantes a encontrar falhas de injecção. | A injecção pode resultar em perda ou corrupção de dados, falha de responsabilização, ou negação de acesso. A injecção pode levar a que um atacante possa controlar completamente um sistema. O impacto no negócio depende das necessidades de proteção da aplicação ou dos seus dados. |

## Está a aplicação vulnerável?

Uma aplicação é vulnerável a este ataque quando:

* Quando os dados fornecidos pelo utilizador não são validados, filtrados ou limpos pela aplicação.
* Dados hostis são usados directamente com pesquisas dinâmicas ou invocações não parametrizadas para um interpretador sem terem sido filtrados de acordo com o seu contexto.
* Dados hostis são usados como parâmetros de pesquisa ORM de forma a que pesquisa inclua dados sensíveis ou todos os registos.
* Dados hostis são directamente usados ou concatenados, de forma a que o SQL ou comandos contenham tanto estrutura ou dados hostis em perguntas dinâmicas, comandos, ou procedimentos armazenados.
* Algumas das injecções mais comuns são SQL, comandos do SO, ORM, LDAP, Linguagens de Expressões (EL) ou injecção OGNL. O conceito é idêntico entre todos os interpretadores. As organizações podem incluir ferramentas SAST e DAST no pipeline de CI/CD para alertar se existe código que possua falhas de injecção antes de passar para produção. Revisões de código manuais ou automatizadas são a melhor forma de detectar se é vulnerável a injecções, seguidas por pesquisas DAST detalhadas de todos os parâmetros, campos, cabeçalhos, cookies, JSON, entradas de XML e de dados.

## Como Prevenir?

Prevenir as injecções requer que os dados estejam separados dos comandos e das pesquisas.

* A opção preferencial consiste em usar uma API que evite o uso do interpretador por completo ou que ofereça um interface parametrizável, ou migrar para o uso de ORM ou Entity Framework. **NB**: Quando parametrizados, os procedimentos armazenados podem ainda introduzir injecção de SQL se o PL/SQL ou T-SQL concatena pesquisa e dados, ou executa dados hostis com  EXECUTE IMMEDIATE ou exec().
* Validação de entradas do lado do servidor usando "whitelists", no entanto isto não é uma defesa completa uma vez que muitas aplicações necessitas de usar caracteres especiais, tais como campos de texto ou APIs para aplicações móveis.
* Para todas as perguntas dinâmicas, processar os caracteres especiais usando sintaxe especial de processamento para o interpretador específico. O Encoder de Java da OWASP e outras bibliotecas semelhantes oferecem estas rotinas de processamento. NB: Estruturas de SQL tais como o nome das tabelas, nomes das colunas, e outras não podem ser processadas, e por isso todos os nomes de estruturas fornecidos pelos utilizadores são perigosos. Este é um problema comum em software que produz relatórios.
* Usar o LIMIT e outros controlos de SQL dentro das pesquisas para prevenir a revelação não autorizada de grandes volumes de registos no caso de injecção de SQL.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação usa dados de pouca confiança na construção da sequinte chamada de SQL vulnerável:

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Cenário #2**: De forma similar, a confiança cega de uma aplicação em frameworks pode resultar em pesquisas que são igualmente vulneráveis, (p.e. Hibernate Query Language (HQL):

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Em ambos os casos, um atacante modifica o valor do parâmetro 'id' no seu browser para enviar:  ' or '1'='1. Por exemplo:
* `http://example.com/app/accountView?id=' or '1'='1`

Isto altera o significado de ambas as pesquisas para que retornem todos os registos da tabela "accounts".  Ataques mais perigosos podem modificar dados ou até invocar procedimentos armazenados.

## Referências

### OWASP

* [OWASP Proactive Controls: Parameterize Queries][2]
* [OWASP ASVS: V5 Input Validation and Encoding][3]
* [OWASP Testing Guide: SQL Injection][4], [Command Injection][5], [ORM injection][6]
* [OWASP Cheat Sheet: SQL Injection Prevention][7]
* [OWASP Cheat Sheet: Injection Prevention in Java][8]
* [OWASP Cheat Sheet: Query Parameterization][9]
* [OWASP Cheat Sheet: Command Injection Defense][10]

### Externas

* [CWE-77: Command Injection][11]
* [CWE-89: SQL Injection][12]
* [CWE-564: Hibernate Injection][13]
* [CWE-917: Expression Language Injection][14]
* [PortSwigger: Server-side template injection][15]

[1]:	https://www.owasp.org/index.php/Injection_Flaws
[2]:	https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries
[3]:	TBA
[4]:	https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)
[5]:	https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)
[6]:	https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007)
[7]:	https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet
[8]:	https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java
[9]:	https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet
[10]:	https://www.owasp.org/index.php/Command_Injection_Defense_Cheat_Sheet
[11]:	https://cwe.mitre.org/data/definitions/77.html
[12]:	https://cwe.mitre.org/data/definitions/89.html
[13]:	https://cwe.mitre.org/data/definitions/564.html
[14]:	https://cwe.mitre.org/data/definitions/917.html
[15]:	https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection
