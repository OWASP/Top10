# A01:2025 – Controle de Acesso Quebrado (Broken Access Control) ![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Contexto

Mantendo sua posição nº 1 no Top 10, foi constatado que 100% das aplicações testadas apresentavam alguma forma de controle de acesso quebrado. As CWEs notáveis incluídas são _CWE-200: Exposure of Sensitive Information to an Unauthorized Actor_, _CWE-201: Exposure of Sensitive Information Through Sent Data_, _CWE-918 Server-Side Request Forgery (SSRF)_ e _CWE-352: Cross-Site Request Forgery (CSRF)_. Esta categoria possui o maior número de ocorrências nos dados contribuídos e o segundo maior número de CVEs relacionadas.

## Tabela de Pontuação

<table>
  <tr>
   <td>CWEs Mapeadas 
   </td>
   <td>Taxa Máx. de Incidência
   </td>
   <td>Taxa Média de Incidência
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Média
   </td>
   <td>Exploit Médio Ponderado
   </td>
   <td>Impacto Médio Ponderado
   </td>
   <td>Total de Ocorrências
   </td>
   <td>Total de CVEs
   </td>
  </tr>
  <tr>
   <td>40
   </td>
   <td>20.15%
   </td>
   <td>3.74%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.04
   </td>
   <td>3.84
   </td>
   <td>1,839,701
   </td>
   <td>32,654
   </td>
  </tr>
</table>

## Descrição

O controle de acesso aplica políticas para que os usuários não possam agir fora de suas permissões pretendidas. As falhas normalmente levam à divulgação não autorizada de informações, modificação ou destruição de todos os dados, ou à execução de uma função de negócio fora dos limites do usuário. Vulnerabilidades comuns de controle de acesso incluem:

- Violação do princípio do menor privilégio (least privilege), comumente conhecido como "negar por padrão" (deny by default), onde o acesso deveria ser concedido apenas para capacidades, papéis ou usuários específicos, mas está disponível para qualquer pessoa.
- **Bypass** de verificações de controle de acesso ao modificar a URL (manipulação de parâmetros ou navegação forçada), o estado interno da aplicação ou a página HTML, ou ao utilizar uma ferramenta de ataque que modifica requisições de **API**.
- Permitir a visualização ou edição da conta de outra pessoa ao fornecer seu identificador exclusivo (**IDOR** – _Insecure Direct Object References_).
- Uma **API** acessível com falta de controles de acesso para POST, PUT e DELETE.
- Elevação de privilégio. Agir como um usuário sem estar logado ou obter privilégios além dos esperados para o usuário logado (ex: acesso de administrador).
- Manipulação de **metadados**, como o reuso (_replaying_) ou adulteração de um **token** de controle de acesso **JWT** (_JSON Web Token_), um **cookie** ou campo oculto manipulado para elevar privilégios, ou abuso da invalidação de **JWT**.
- Configuração incorreta de **CORS** que permite acesso à **API** a partir de origens não autorizadas ou não confiáveis.
- Navegação forçada (_force browsing_ ou adivinhação de URLs) para páginas autenticadas como um usuário não autenticado ou para páginas privilegiadas como um usuário comum.

## Como Prevenir

O controle de acesso só é eficaz quando implementado em código confiável no lado do servidor ou em **APIs** _serverless_, onde o **atacante** não pode modificar a verificação de controle de acesso ou os **metadados**.

- Exceto para recursos públicos, negue por padrão (_deny by default_).
- Implemente mecanismos de controle de acesso uma única vez e reutilize-os em toda a aplicação, incluindo a minimização do uso de _Cross-Origin Resource Sharing_ (**CORS**).
- Os modelos de controle de acesso devem reforçar a propriedade do registro, em vez de permitir que os usuários criem, leiam, atualizem ou excluam qualquer registro.
- Requisitos exclusivos de limites de negócio da aplicação devem ser impostos por modelos de domínio.
- Desative a listagem de diretórios do servidor web e garanta que **metadados** de arquivos (ex: `.git`) e arquivos de backup não estejam presentes nas raízes web (_web roots_).
- Registre (**log**) falhas de controle de acesso e alerte os administradores quando apropriado (ex: falhas repetidas).
- Implemente limites de taxa (_rate limits_) no acesso a **APIs** e controladores para minimizar o dano causado por ferramentas de ataque automatizadas.
- Identificadores de sessão com estado (_stateful_) devem ser invalidados no servidor após o logout. **Tokens JWT** sem estado (_stateless_) devem ter vida curta para minimizar a janela de oportunidade para um **atacante**. Para **JWTs** de longa duração, considere o uso de _refresh tokens_ e siga os padrões OAuth para revogar o acesso.
- Utilize conjuntos de ferramentas (_toolkits_) ou padrões bem estabelecidos que forneçam controles de acesso simples e declarativos.

Desenvolvedores e equipes de QA devem incluir testes funcionais de controle de acesso em seus testes unitários e de integração.

## Exemplos de Cenários de Ataque

**Cenário #1:** A aplicação utiliza dados não verificados em uma chamada SQL que acessa informações da conta:

```java
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```

Um **atacante** pode simplesmente modificar o parâmetro 'acct' no navegador para enviar qualquer número de conta desejado. Se não for corretamente verificado, o **atacante** pode acessar a conta de qualquer usuário.

```
https://example.com/app/accountInfo?acct=notmyacct
```

**Cenário #2:** Um **atacante** simplesmente força a navegação para URLs alvo. Direitos de administrador são necessários para acessar a página administrativa.

```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```

Se um usuário não autenticado conseguir acessar qualquer uma das páginas, trata-se de uma falha. Se um não-administrador conseguir acessar a página de administração, isso também é uma falha.

**Cenário #3:** Uma aplicação coloca todo o seu controle de acesso no front-end. Embora o **atacante** não consiga chegar a `[https://example.com/app/admin_getappInfo](https://example.com/app/admin_getappInfo)` devido ao código JavaScript executado no navegador, ele pode simplesmente executar:

```bash
$ curl https://example.com/app/admin_getappInfo
```

a partir da linha de comando.

## Referências

- [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
- [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
- [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
- [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## Lista de CWEs Mapeadas

- [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
- [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)
- [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)
- [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)
- [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)
- [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)
- [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)
- [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)
- [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)
- [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)
- [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)
- [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
- [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)
- [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
- [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)
- [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
- [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
- [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)
- [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)
- [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)
- [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)
- [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)
- [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
