# A1:2017 Injeção

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 3 | Prevalência: 2 \| Deteção: 3 | Técnico: 3 \| Negócio ? |
| Quase todas as fontes de dados podem ser um vetor de injeção: variáveis de ambiente, parâmetros, serviços web internos e externos e todos os tipos de utilizador. [Falhas de injeção][0xa11] ocorrem quando um atacante consegue enviar dados hostis para um interpretador. | As falhas relacionadas com injeção são muito comuns, em especial em código antigo. São encontradas frequentemente em consultas SQL, LDAP, XPath ou NoSQL, comandos do Sistema Operativo, processadores de XML, cabeçalhos de SMTP, linguagens de expressão e consultas ORM. Estas falhas são fáceis de descobrir aquando da análise do código. Scanners e fuzzers podem ajudar os atacantes a encontrar falhas de injeção. | A injeção pode resultar em perda ou corrupção de dados, falha de responsabilização, ou negação de acesso. A injeção pode, às vezes, levar ao controlo total do sistema. O impacto no negócio depende das necessidades de proteção da aplicação ou dos seus dados. |

## A Aplicação é Vulnerável?

Uma aplicação é vulnerável a este ataque quando:

* Os dados fornecidos pelo utilizador não são validados, filtrados ou limpos
  pela aplicação.
* Dados hostis são usados diretamente em consultas dinâmicas ou invocações não
  parametrizadas para um interpretador sem terem sido processadas de acordo com
  o seu contexto.
* Dados hostis são usados como parâmetros de consulta ORM, por forma a obter
  dados adicionais ou sensíveis.
* Dados hostis são usados diretamente ou concatenados em consultas SQL ou
  comandos, misturando a estrutura e os dados hostis em consultas dinâmicas,
  comandos ou procedimentos armazenados.

Algumas das injeções mais comuns são SQL, NoSQL, comandos do sistema operativo,
ORM, LDAP, Linguagens de Expressão (EL) ou injeção OGNL. O conceito é idêntico
entre todos os interpretadores. A revisão de código é a melhor forma de detetar
se a sua aplicação é vulnerável a injeções, complementada sempre com testes
automáticos que cubram todos os parâmetros, cabeçalhos, URL, _cookies_, JSON,
SOAP e dados de entrada para XML. As organizações podem implementar ferramentas
de análise estática ([SAST][0xa12]) e dinâmica ([DAST][0xa13]) de código no seu
processo de CI/CD por forma a identificar novas falhas relacionadas com injeção
antes de colocar as aplicações em ambiente de produção.

## Como Prevenir

Prevenir as injeções requer que os dados estejam separados dos comandos e das
consultas.

* Optar por uma API que evite por completo o uso do interpretador ou que ofereça
  uma interface parametrizável, ou então usar uma ferramenta ORM - Object
  Relational Mapping.
  **N.B.**: Quando parametrizados, os procedimentos armazenados podem ainda
  introduzir injeção de SQL se o PL/SQL ou T-SQL concatenar consulta e dados, ou
  executar dados hostis com EXECUTE IMMEDIATE ou exec().
* Validação dos dados de entrada do lado do servidor usando whitelists, isto não
  representa uma defesa completa uma vez que muitas aplicações necessitam de
  usar caracteres especiais, tais como campos de texto ou APIs para aplicações
  móveis.
* Para todas as consultas dinâmicas, processar os caracteres especiais usando
  sintaxe especial de processamento para o interpretador específico
  (_escaping_).

  **N.B.**: Estruturas de SQL tais como o nome das tabelas e colunas, entre
  outras, não podem ser processadas conforme descrito acima e por isso todos os
  nomes de estruturas fornecidos pelos utilizadores são perigosos. Este é um
  problema comum em software que produz relatórios.
* Usar o LIMIT e outros controlos de SQL dentro das consultas para prevenir a
  revelação não autorizada de grandes volumes de registos em caso de injeção de
  SQL.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação usa dados não confiáveis na construção da seguinte
consulta SQL vulnerável:

```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Cenário #2**: De forma semelhante, a confiança cega de uma aplicação em
frameworks pode resultar em consultas que são igualmente vulneráveis, (e.g.
Hibernate Query Language (HQL)):

```java
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Em ambos os casos, um atacante modifica o valor do parâmetro id no seu browser
para enviar: `' UNION SELECT SLEEP(10);--`. Por exemplo:

```
http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Isto altera o significado de ambas as consultas para que retornem todos os
registos da tabela "accounts". Ataques mais perigosos podem modificar dados ou
até invocar procedimentos armazenados.

## Referências

### OWASP

* [OWASP Proactive Controls: Parameterize Queries][0xa14]
* [OWASP ASVS: V5 Input Validation and Encoding][0xa15]
* [OWASP Testing Guide: SQL Injection][0xa16], [Command Injection][0xa17], [ORM
  injection][0xa18]
* [OWASP Cheat Sheet: Injection Prevention][0xa19]
* [OWASP Cheat Sheet: SQL Injection Prevention][0xa110]
* [OWASP Cheat Sheet: Injection Prevention in Java][0xa111]
* [OWASP Cheat Sheet: Query Parameterization][0xa112]
* [OWASP Cheat Sheet: Command Injection Defense][0xa113]

### Externas

* [CWE-77: Command Injection][0xa114]
* [CWE-89: SQL Injection][0xa115]
* [CWE-564: Hibernate Injection][0xa116]
* [CWE-917: Expression Language Injection][0xa117]
* [PortSwigger: Server-side template injection][0xa118]

[0xa11]: https://www.owasp.org/index.php/Injection_Flaws
[0xa12]: https://www.owasp.org/index.php/Source_Code_Analysis_Tools
[0xa13]: https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools
[0xa14]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries
[0xa15]: https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding
[0xa16]: https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)
[0xa17]: https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)
[0xa18]: https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007)
[0xa19]: https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet
[0xa110]: https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet
[0xa111]: https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java
[0xa112]: https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet
[0xa113]: https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications
[0xa114]: https://cwe.mitre.org/data/definitions/77.html
[0xa115]: https://cwe.mitre.org/data/definitions/89.html
[0xa116]: https://cwe.mitre.org/data/definitions/564.html
[0xa117]: https://cwe.mitre.org/data/definitions/917.html
[0xa118]: https://portswigger.net/kb/issues/00101080_serversidetemplateinjection

