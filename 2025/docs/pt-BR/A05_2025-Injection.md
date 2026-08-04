# A05:2025 Injeção ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Contexto

A categoria Injeção caiu duas posições, passando de #3 para #5 no ranking, mantendo sua posição relativa a A04:2025-Falhas Criptográficas e A06:2025-Design Inseguro. Injeção é uma das categorias mais testadas, com 100% das aplicações testadas para alguma forma de injeção. Ela apresentou o maior número de CVEs entre todas as categorias, com 37 CWEs mapeadas. Injeção inclui _Cross-site Scripting_ (alta frequência/baixo impacto), com mais de 30 mil CVEs, e _SQL Injection_ (baixa frequência/alto impacto), com mais de 14 mil CVEs. O número massivo de CVEs relatados para a CWE-79 (_Improper Neutralization of Input During Web Page Generation_ ou 'Cross-site Scripting') reduz o impacto ponderado médio desta categoria.

## Tabela de pontuação

<table>
  <tr>
   <td>CWEs Mapeadas 
   </td>
   <td>Taxa Máx. de Incidência
   </td>
   <td>Taxa Méd. de Incidência
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Média
   </td>
   <td>Exploit Ponderado Médio
   </td>
   <td>Impacto Ponderado Médio
   </td>
   <td>Total de Ocorrências
   </td>
   <td>Total de CVEs
   </td>
  </tr>
  <tr>
   <td>37
   </td>
   <td>13,77%
   </td>
   <td>3,08%
   </td>
   <td>100,00%
   </td>
   <td>42,93%
   </td>
   <td>7,15
   </td>
   <td>4,32
   </td>
   <td>1.404.249
   </td>
   <td>62.445
   </td>
  </tr>
</table>

## Descrição

Uma vulnerabilidade de injeção é uma falha na aplicação que permite que a entrada de um usuário não confiável seja enviada para um interpretador (ex: um navegador, banco de dados, linha de comando) e faz com que o interpretador execute partes dessa entrada como comandos.

Uma aplicação é vulnerável a ataques quando:

- Dados fornecidos pelo usuário não são validados, filtrados ou sanitizados pela aplicação.
- Consultas dinâmicas ou chamadas não parametrizadas sem escape sensível ao contexto são usadas diretamente no interpretador.
- Dados não sanitizados são usados em parâmetros de busca de mapeamento objeto-relacional (ORM) para extrair registros adicionais e sensíveis.
- Dados potencialmente hostis são usados diretamente ou concatenados. O SQL ou comando contém a estrutura e os dados maliciosos em consultas dinâmicas, comandos ou procedimentos armazenados (_stored procedures_).

Algumas das injeções mais comuns são SQL, NoSQL, comandos de SO, Mapeamento Objeto-Relacional (ORM), LDAP e Expression Language (EL) ou Object Graph Navigation Library (OGNL). O conceito é idêntico entre todos os interpretadores. A detecção é melhor alcançada por uma combinação de revisão de código-fonte junto com testes automatizados (incluindo _fuzzing_) de todos os parâmetros, _headers_, URL, _cookies_, JSON, SOAP e entradas de dados XML. A adição de ferramentas de teste de segurança de aplicação estática (SAST), dinâmica (DAST) e interativa (IAST) no _pipeline_ de CI/CD também pode ser útil para identificar falhas de injeção antes da implantação em produção.

Uma classe relacionada de vulnerabilidades de injeção tornou-se comum em LLMs. Estas são discutidas separadamente no [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/), especificamente em [LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).

## Como prevenir

A melhor maneira de prevenir a injeção requer manter os dados separados dos comandos e consultas:

- A opção preferencial é usar uma API segura, que evita totalmente o uso do interpretador, fornece uma interface parametrizada ou migra para ferramentas de Mapeamento Objeto-Relacional (ORMs).
  **Nota:** Mesmo quando parametrizadas, as _stored procedures_ ainda podem introduzir SQL Injection se o PL/SQL ou T-SQL concatenar consultas e dados ou executar dados hostis com `EXECUTE IMMEDIATE` ou `exec()`.

Quando não for possível separar os dados dos comandos, você pode reduzir as ameaças usando as seguintes técnicas:

- Use validação de entrada positiva no lado do servidor (_allow-list_). Esta não é uma defesa completa, pois muitas aplicações exigem caracteres especiais, como áreas de texto ou APIs para aplicações móveis.
- Para qualquer consulta dinâmica residual, use escape de caracteres especiais usando a sintaxe de escape específica para aquele interpretador.
  **Nota:** Estruturas SQL, como nomes de tabelas, nomes de colunas e assim por diante, não podem sofrer escape e, portanto, nomes de estruturas fornecidos pelo usuário são perigosos. Este é um problema comum em softwares de geração de relatórios.

**Aviso:** estas técnicas envolvem a análise (_parsing_) e o escape de strings complexas, o que as torna propensas a erros e pouco robustas diante de pequenas mudanças no sistema subjacente.

## Exemplos de cenários de ataque

**Cenário #1:** Uma aplicação usa dados não confiáveis na construção da seguinte chamada SQL vulnerável:

```java
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

Um atacante modifica o valor do parâmetro 'id' em seu navegador para enviar: `' OR '1'='1`. Por exemplo:

```
http://example.com/app/accountView?id=' OR '1'='1
```

Isso altera o significado da consulta para retornar todos os registros da tabela `accounts`. Ataques mais perigosos poderiam modificar ou excluir dados ou até mesmo invocar procedimentos armazenados.

**Cenário #2:** A confiança cega de uma aplicação em _frameworks_ pode resultar em consultas que ainda são vulneráveis. Por exemplo, em Hibernate Query Language (HQL):

```java
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

Um atacante fornece: `' OR custID IS NOT NULL OR custID='`. Isso ignora o filtro e retorna todas as contas. Embora o HQL tenha menos funções perigosas do que o SQL puro, ele ainda permite o acesso não autorizado a dados quando a entrada do usuário é concatenada em consultas.

**Cenário #3:** Uma aplicação passa a entrada do usuário diretamente para um comando do sistema operacional:

```java
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

Um atacante fornece `example.com; cat /etc/passwd` para executar comandos arbitrários no servidor.

## Referências

- [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
- [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
- [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection) e [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
- [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
- [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
- [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing)

## Lista de CWEs Mapeadas

- [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)
- [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
- [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)
- [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)
- [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)
- [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)
- [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
- [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)
- [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
- [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
- [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
- [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)
- [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)
- [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)
- [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)
- [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)
- [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)
- [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)
- [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)
- [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)
- [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
- [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
- [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)
- [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)
- [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)
- [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)
- [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)
- [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)
- [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)
- [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)
- [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
