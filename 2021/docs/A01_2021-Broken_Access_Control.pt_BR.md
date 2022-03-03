# A01:2021 – Quebra de Controle de Acesso    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:-------------------------:|:------------------------:|:--------------------------:|:-----------------------:|:----------------:|:---------------:|:--------------------:|:-------------:|
| 34            | 55.97%                    | 3.81%                    | 6.92                       | 5.93                    | 94.55%           | 47.72%          | 318,487              | 19,013        |

## Visão Geral

Saindo da quinta posição, 94% dos aplicativos foram testados para
alguma forma de controle de acesso quebrado com a taxa de incidência média
de 3,81% e tem o maior número de ocorrências no conjunto de dados contribuído
com mais de 318 mil. Notável _Common Weakness Enumerations_ (CWEs) incluídas são
*CWE-200: Exposição de Informações Confidenciais a um Ator Não Autorizado*, *CWE-201:
Exposição de Informações Confidenciais por meio de Dados Enviados* e *CWE-352:
requisições forjadas entre sites*.

## Descrição

O controle de acesso impõe a política de modo que os usuários não possam
agir fora de suas permissões pretendidas. As falhas normalmente levam
à divulgação, modificação ou destruição de informações não autorizadas
de todos os dados ou ao desempenho de uma função comercial fora dos
limites do usuário. Vulnerabilidades comuns de controle de acesso incluem:

- Violação do princípio de privilégio mínimo ou negação por padrão,
    onde o acesso deve ser concedido apenas para determinados recursos,
    funções ou usuários, mas está disponível para qualquer pessoa.

- Ignorar verificações de controle de acesso modificando a URL
    (adulteração de parâmetros ou navegação forçada), o estado interno
    do aplicativo, a página HTML ou usando uma ferramenta de ataque que
    modifica as requisições de API.

- Permitir a visualização ou edição da conta de outrem, mediante a
    disponibilização do seu identificador único (referências diretas
    não seguras a objetos).

- Acessando API sem controles de acesso para POST, PUT e DELETE.

- Elevação de privilégio. Agir como um usuário sem estar logado
    ou agir como um administrador quando logado como um usuário.

- Manipulação de metadados, como reproduzir ou adulterar um token
    de controle de acesso _JSON Web Token_ (JWT), um cookie ou campo
    oculto manipulado para elevar privilégios ou abusar da invalidação de JWT.

- A configuração incorreta do CORS permite o acesso à API de origens
    não autorizadas / não confiáveis.

- Força a navegação para páginas autenticadas como um usuário não
    autenticado ou para páginas privilegiadas como um usuário padrão.

## Como Prevenir

O controle de acesso só é eficaz em código confiável do lado do servidor ou API sem servidor,
em que o invasor não pode modificar a verificação de controle de acesso ou metadados.

- Exceto para recursos públicos, negar por padrão.

- Implemente mecanismos de controle de acesso uma vez e reutilize-os em todo o aplicativo,
    incluindo a minimização do uso de _Cross-Origin Resource Sharing_ (CORS).

- Os controles de acesso ao modelo devem impor a propriedade do registro em vez de
    aceitar que o usuário possa criar, ler, atualizar ou excluir qualquer registro.

- Os requisitos de limite de negócios de aplicativos exclusivos devem ser
    impostos por modelos de domínio.

- Desative a lista de diretórios do servidor da web e certifique-se de que os
    metadados do arquivo (por exemplo, o _.git_) e os arquivos de backup não
    estejam presentes nas raízes da web (_web roots_).

- Registrar falhas de controle de acesso e alertar os administradores quando
    apropriado (por exemplo, falhas repetidas).

- Limite de taxa o acesso da API e do controlador para minimizar os danos
    do conjunto de ferramentas de ataque automatizado.

- Os identificadores de sessão com estado devem ser invalidados no servidor
    após o logout. Os tokens JWT sem estado devem ter vida curta, para que a
    janela de oportunidade para um invasor seja minimizada. Para JWTs de
    longa duração, é altamente recomendável seguir os padrões OAuth para revogar o acesso.

Os desenvolvedores e a equipe de QA devem incluir uma unidade de controle de
acesso funcional e testes de integração.

## Exemplos de Cenários de Ataque

**Cenário #1:** O aplicativo usa dados não verificados em uma chamada SQL que
está acessando informações da conta:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

Um invasor simplesmente modifica o parâmetro 'acct' do navegador para enviar
o número de conta que desejar. Se não for verificado corretamente, o invasor
pode acessar a conta de qualquer usuário.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Cenário #2:** Um invasor simplesmente força a navegação para URLs de destino.
Direitos de administrador são necessários para acessar a página de administrador.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```
Se um usuário não autenticado pode acessar qualquer página, é uma falha.
Se um não administrador pode acessar a página de administração, isso é uma falha.

## Referências

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## Lista dos CWEs Mapeados

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
