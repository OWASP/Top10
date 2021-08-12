# A5:2017 Quebra de Controle de Acesso

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 2 | Prevalência 2 \| Detectabilidade 2 | Técnico 3 \| Negócio |
| A exploração do controle de acesso é uma habilidade básica dos atacantes. As ferramentas [SAST](https://owasp.org/www-community/Source_Code_Analysis_Tools) e [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) podem detectar a ausência de controle de acesso, mas não pode verificar se é funcional quando está presente. O controle de acesso é detectável usando meios manuais, ou possivelmente por automação para a ausência de controles de acesso em certos frameworks.| As vulnerabilidades de controle de acesso são comuns devido à falta de detecção automatizada e à falta de testes funcionais efetivos pelos desenvolvedores de aplicação. A detecção de controle de acesso normalmente não é compatível com testes estáticos ou dinâmicos automatizados. | O impacto técnico são os atacantes que atuam como usuários ou administradores, usuários que usam funções privilegiadas, ou criam, acessam, atualizam ou excluem todos os registros. O impacto comercial depende das necessidades de proteção de sua aplicação e dados. |

## A Aplicação Está Vulnerável?

O controle de acesso impõe uma política que os usuários não podem atuar fora das suas permissões pretendidas. As falhas geralmente levam à divulgação não autorizada de informações, modificações ou destruição de todos os dados, ou a realização de uma função de negócio fora dos limites do usuário. As vulnerabilidades comuns de controle de acesso incluem:

* Contornar verificações de controle de acesso modificando a URL, o estado interno da aplicação ou página HTML, ou simplesmente usando uma ferramenta de ataque de API personalizada.
* Permitir que a chave primária seja alterada para o registro de outros usuários, como visualizar ou editar a conta de outra pessoa.
* Elevação de privilégio. Atuando como um usuário sem estar logado, ou atuando como um administrador quando conectado como usuário.
* Manipulação de metadados, como reproduzir ou adulterar um token de controle de acesso JWT ou um cookie ou campo oculto manipulado para elevar privilégios ou abusar da invalidação JWT.
* A configuração errada do CORS permite o acesso não autorizado à API.
* Forçar a navegação para páginas autenticadas como um usuário não autenticado ou para páginas privilegiadas como um usuário padrão ou acessando API com controles de acesso ausentes para POST, PUT e DELETE.

## Como Prevenir

O controle de acesso só é efetivo se for aplicado no código confiável do servidor ou na API server-less, onde o atacante não pode modificar a verificação de controle de acesso ou os metadados.

* Com exceção de recursos públicos, negar por padrão. 
* Implementar mecanismos de controle de acesso uma vez e reutilizá-los durante toda a aplicação, incluindo CORS. 
* Os controles de acesso ao Model devem impor a posse do registro, em vez de aceitar que o usuário possa criar, ler, atualizar ou excluir qualquer registro. 
* Requisitos únicos de limites de negócios de aplicações devem ser aplicados por modelos de domínio. 
* Desative a listagem do diretório do servidor web e assegure-se de que os metadados do arquivo (por exemplo, .git) e os arquivos de backup não estejam presentes na raiz de pastas web. 
* Registre as falhas de controle de acesso, alerte administradores quando apropriado (por exemplo, falhas repetidas). 
* Limite a taxa de acesso às APIs e acesso ao controlador para minimizar os danos causados pela ferramentas de ataque automatizados. 
* Os tokens JWT devem ser invalidados no servidor após o fim de sessão. 
* Desenvolvedores e funcionários de QA devem incluir testes funcionais de controle de acesso unitários e integrados.

## Exemplo de Cenários de Ataque

**Cenário #1**: O aplicativo usa dados não verificados em uma chamada SQL que está acessando informações de conta:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery( );
```

Um atacante simplesmente modifica o parâmetro 'acct' no navegador para enviar qualquer número de conta que eles desejem. Se não for verificado corretamente, o invasor pode acessar a conta de qualquer usuário.

`https://example.com/app/accountInfo?acct=notmyacct`

**Cenário #2**: Um atacante simplesmente faz uma busca forçada por URLs. Os direitos de administrador são necessários para acessar a página de administração.

```
  https://example.com/app/getappInfo
  https://example.com/app/admin_getappInfo
```
Se um usuário não autenticado puder acessar qualquer uma das páginas, é uma falha. Se um não administrador puder acessar a página de administração, isso é uma falha.

## Referências

### OWASP

* [OWASP Proactive Controls: Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V4-Access-Control.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

### Externas

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
