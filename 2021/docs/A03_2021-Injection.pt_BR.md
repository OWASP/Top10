# A03:2021 – Injeção    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"} 

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:-------------------------:|:------------------------:|:--------------------------:|:-----------------------:|:----------------:|:---------------:|:--------------------:|:-------------:|
| 33            | 19.09%                    | 3.37%                    | 7.25                       | 7.15                    | 94.04%           | 47.90%          | 274,228              | 32,078        |

## Visão Geral

A Injeção desliza para a terceira posição. 94% das aplicações foram
testadas para alguma forma de injeção com uma taxa de incidência
máxima de 19%, uma taxa de incidência média de 3% e 274k ocorrências.
Notável _Common Weakness Enumerations_ (CWEs) incluídas são
*CWE-79: Cross-site Scripting*, *CWE-89: Injeção de SQL* e *CWE-73:
Controle Externo do Nome do Arquivo ou Caminho*.

## Descrição 

Uma aplicação é vulnerável a ataques quando:

- Os dados fornecidos pelo usuário não são validados, filtrados
    ou higienizados pelo aplicativo.

- Consultas dinâmicas ou chamadas não parametrizadas sem escape
    ciente do contexto são usadas diretamente no interpretador.

- Dados hostis são usados nos parâmetros de pesquisa de mapeamento
    relacional de objeto (ORM) para extrair registros confidenciais
    adicionais.

- Os dados fornecidos pelo usuário não são validados, filtrados ou
    higienizados pelo aplicativo.

- Consultas dinâmicas ou chamadas não parametrizadas sem escape ciente
    do contexto são usadas diretamente no interpretador.

- Dados hostis são usados nos parâmetros de pesquisa de mapeamento
    relacional de objeto (ORM) para extrair registros confidenciais adicionais.

- Dados hostis são usados diretamente ou concatenados. O SQL ou comando
    contém a estrutura e os dados maliciosos em consultas dinâmicas, comandos
    ou procedimentos armazenados.

Algumas das injeções mais comuns são SQL, NoSQL, comando OS, Mapeamento
Relacional de Objeto (ORM), LDAP e Linguagem de Expressão (EL) ou injeção
de Biblioteca de Navegação de Gráfico de Objeto (OGNL). O conceito é idêntico
entre todos os intérpretes. A revisão do código-fonte é o melhor método para
detectar se os aplicativos são vulneráveis a injeções. O teste automatizado
de todos os parâmetros, cabeçalhos, URL, cookies, JSON, SOAP e entradas
de dados XML são fortemente encorajados. As organizações podem incluir
ferramentas de teste de segurança de aplicações estáticos (SAST), dinâmicos (DAST)
e interativos (IAST) no pipeline de CI/CD para identificar as falhas de injeção
introduzidas antes da implantação da produção.

## Como Prevenir

Prevenir a injeção requer manter os dados separados dos comandos e consultas:

- A opção preferida é usar uma API segura, que evita usar o interpretador
    inteiramente, fornece uma interface parametrizada ou migra para uma
    ferramenta de Mapeamento Relacional de Objeto (ORMs).<br/>
    **Nota:** Mesmo quando parametrizados, os procedimentos armazenados
    ainda podem introduzir injeção de SQL se PL/SQL ou T-SQL concatenar
    consultas e dados ou executar dados hostis com EXECUTE IMMEDIATE ou exec().

- Use validação de entrada positiva ou "_safelist_" do lado do servidor. Esta não
    é uma defesa completa, pois muitos aplicativos requerem caracteres especiais,
    como áreas de texto ou APIs para aplicativos móveis.

- Para quaisquer consultas dinâmicas residuais, escape os caracteres especiais
    usando a sintaxe de escape específica para esse interpretador..<br/>
    **Nota:** Estruturas SQL, como nomes de tabelas, nomes de colunas e assim
    por diante, não podem ter escape e, portanto, nomes de estruturas fornecidos
    pelo usuário são perigosos. Este é um problema comum em software de
    elaboração de relatórios.

- Use LIMIT e outros SQL de controle em consultas para evitar a divulgação em
    massa de registros no caso de injeção de SQL.

## Exemplos de Cenários de Ataque

**Cenário #1:** Um aplicativo usa dados não confiáveis na construção
da seguinte chamada SQL vulnerável:
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Cenário #2:** Da mesma forma, a confiança cega em _frameworks_ de aplicaçãos
pode resultar em consultas que ainda são vulneráveis
(por exemplo, Hibernate Query Language (HQL)):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Em ambos os casos, o invasor modifica o valor do parâmetro ‘_id_’ em seu
navegador para enviar: _‘ or ‘1’=’1_. Por exemplo:
```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--
```

Isso muda o significado de ambas as consultas para retornar todos os registros da
tabela de contas. Ataques mais perigosos podem modificar ou excluir dados ou até
mesmo invocar procedimentos armazenados.

## Referências

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
    e [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Lista dos CWEs Mapeados

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
