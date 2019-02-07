# A1:2017 Injeção

| Agentes de Ameaça/Vectores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Abuso 3 | Prevalência 2 \| Deteção 3 | Técnica 3 \| Negócio |
| Quase todas as fontes de dados podem ser um vector de injeção: variáveis de ambiente, parâmetros, serviços web internos e externos e todos os tipos de utilizador. [Falhas de injeção][1] ocorrem quando um atacante consegue enviar dados hostis para um interpretador. | As falhas relacionadas com injeção são muito comuns, em especial em código antigo. São encontradas frequentemente em consultas SQL, LDAP, XPath ou NoSQL; comandos do SO; processadores de XML, cabeçalhos de SMTP, linguagens de expressão e consultas ORM. Estas falhas são fáceis de descobrir aquando da análise do código. Scanners e fuzzers podem ajudar os atacantes a encontrar falhas de injeção. | A injeção pode resultar em perda ou corrupção de dados, falha de responsabilização, ou negação de acesso. A injeção pode, às vezes, levar ao controlo total do sistema. O impacto no negócio depende das necessidades de proteção da aplicação ou dos seus dados. |

## A Aplicação é Vulnerável?

Uma aplicação é vulnerável a este ataque quando:

* Os dados fornecidos pelo utilizador não são validados, filtrados ou limpos
  pela aplicação.
* Dados hostis são usados diretamente em consultas dinâmicas ou invocações não
  parametrizadas para um interpretador sem terem sido processadas de acordo com
  o seu contexto.
* Dados hostis são usados como parâmetros de consulta ORM, por forma a obter
  dados adicionais ou sensíveis.
* Dados hostis são usados directamente ou concatenados em consultas SQL ou
  comandos, misturando a estrutura e os dados hostis em consultadas dinâmicas,
  comandos ou procedimentos armazenados.

Algumas das injeções mais comuns são SQL, NoSQl, comandos do sistema operativo,
ORM, LDAP, Linguagens de Expressão (EL) ou injeção OGNL. O conceito é idêntico
entre todos os interpretadores. A revisão de código é a melhor forma de detetar
se a sua aplicação é vulnerável a injeções, complementada sempre com testes
automáticos que cubram todos os parâmetros, cabeçalhos, URL, cookies, JSON, SOAP
e dados de entrada para XML. As organizações podem implementar ferramentas de
análise estática ([SAST][]) e dinâmica ([DAST][]) de código no seu processo de CI/CD por forma a
identificar novas falhas relacionadas com injeção antes de colocar as aplicações
em ambiente de produção.

## Como Prevenir

Prevenir as injeções requer que os dados estejam separados dos comandos e das
consultas.

* Optar por uma API que evite por completo o uso do interpretador ou que ofereça
  uma interface parametrizável, ou então usar uma ferramenta ORM - Object
  Relational Mapping.
  **NB**: Quando parametrizados, os procedimentos armazenados podem ainda
  introduzir injeção de SQL se o PL/SQL ou T-SQL concatenar consulta e dados, ou
  executar dados hostis com EXECUTE IMMEDIATE ou exec().
* Validação dos dados de entrada do lado do servidor usando "whitelists", pese
  embora isto não represente uma defesa completa uma vez que muitas aplicações
  necessitam de usar caracteres especiais, tais como campos de texto ou APIs
  para aplicações móveis.
* Para todas as consultas dinâmicas, processar os caracteres especiais usando
  sintaxe especial de processamento para o interpretador específico (escaping).
  **NB**: Estruturas de SQL tais como o nome das tabelas e colunas, entre
  outras, não podem ser processadas conforme descrito acima e por isso todos os
  nomes de estruturas fornecidos pelos utilizadores são perigosos. Este é um
  problema comum em software que produz relatórios.
* Usar o LIMIT e outros controlos de SQL dentro das consultas para prevenir a
  revelação não autorizada de grandes volumes de registos em caso de injeção de
  SQL.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação usa dados não confiáveis na construção da
seguinte consulta SQL vulnerável:

```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Cenário #2**: De forma semelhante, a confiança cega de uma aplicação em
frameworks pode resultar em consultas que são igualmente vulneráveis, (e.g.
Hibernate Query Language (HQL)):

```java
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Em ambos os casos, um atacante modifica o valor do parâmetro `id` no seu browser
para enviar: `' or '1'='1`. Por exemplo:

```
http://example.com/app/accountView?id=' or '1'='1
```

Isto altera o significado de ambas as consultas para que retornem todos os
registos da tabela "accounts". Ataques mais perigosos podem modificar dados ou
até invocar procedimentos armazenados.

## Referências

### OWASP

* [OWASP Proactive Controls: Parameterize Queries][2]
* [OWASP ASVS: V5 Input Validation and Encoding][3]
* [OWASP Testing Guide: SQL Injection][4], [Command Injection][5], [ORM
  injection][6]
* [OWASP Cheat Sheet: Injection Prevention][]
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

[1]: https://www.owasp.org/index.php/Injection_Flaws
[2]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries
[3]: https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding
[4]: https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)
[5]: https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)
[6]: https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007)
[7]: https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet
[8]: https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java
[9]: https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet
[10]: https://www.owasp.org/index.php/Command_Injection_Defense_Cheat_Sheet
[11]: https://cwe.mitre.org/data/definitions/77.html
[12]: https://cwe.mitre.org/data/definitions/89.html
[13]: https://cwe.mitre.org/data/definitions/564.html
[14]: https://cwe.mitre.org/data/definitions/917.html
[15]: https://portswigger.net/knowledgebase/issues/details/00101080_serversidetemplateinjection
[16]: https://www.owasp.org/index.php/Source_Code_Analysis_Tools
[17]: https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools
[18]: https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet

