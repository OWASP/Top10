# A5:2017 Quebra de Controlo de Acessos

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 2 | Prevalência: 2 \| Deteção: 2 | Técnico: 3 \| Negócio ? |
| O abuso do controlo de acessos é uma competência base dos atacantes. Ferramentas automáticas como [SAST][0xa51] e [DAST][0xa52] podem detetar a ausência, mas não validar o funcionamento do controlo de acessos quando presente. A deteção do controlo de acessos envolve processos manuais. | As falhas de controlo de acessos são comuns devido à falta de processos automáticos de deteção e à falta de testes funcionais realizados pelos programadores. A deteção de controlo de acessos não é fácil de realizar recorrendo a testes automáticos tanto estáticos como dinâmicos. | O impacto técnico reside no facto dos atacantes poderem atuar como utilizadores ou administradores legítimos, utilizadores usarem funções privilegiadas ou criar, aceder, atualizar ou apagar todos os registos. O impacto no negócio depende da necessidade de proteção dos dados. |

## A Aplicação é Vulnerável?

O controlo de acessos garante que os utilizadores não podem agir além das
permissões que lhe foram atribuídas. Falhas no controlo de acessos levam
tipicamente à divulgação não autorizada de informação, modificação ou destruição
de todos os dados, ou á execução de funções de negócio fora dos limites do
utilizador. As vulnerabilidades comuns incluem:

* Ultrapassar as verificações de controlo de acesso modificando o URL, estado
  interno da aplicação, página HTML, ou através da utilização de ferramenta para
  ataque a APIs.
* Permitir a alteração da chave primária para um registo doutro utilizador,
  permitindo visualizar ou editar a conta deste.
* Elevação de privilégios. Atuar como um utilizador sem autenticação, ou como
  administrador tendo um perfil de utilizador regular.
* Manipulação de metadados, e.g. repetição ou adulteração do _JSON Web Token_
  (JWT) de controlo de acesso, cookie ou campo escondido para elevação de
  privilégios.
* Acesso não autorizado a uma API devido a má configuração da política de
  partilha de recursos entre origens (CORS).
* Forçar a navegação para páginas autenticadas como um utilizador não
  autenticado, ou para páginas privilegiadas como um utilizador normal, assim
  como utilizar uma API sem o devido controlo de acessos para operações POST,
  PUT e DELETE.

## Como Prevenir

O controlo de acessos é apenas efetivo se realizado por código confiável a
correr no servidor ou pelas APIs em arquiteturas serverless, em que o atacante
não pode modificar a validação do controlo de acessos nem os metadados.

* Com a exceção dos recursos públicos, o acesso deve ser negado por omissão.
* Implementar mecanismos de controlo de acesso uma única vez, reutilizando-os ao
  longo da aplicação, incluindo CORS.
* Modelar controlo de acesso que assegure a propriedade dos registos, por
  oposição ao modelo que aceita que um utilizador possa criar, ler, atualizar ou
  apagar qualquer registo.
* As regras de negócio específicas duma aplicação, devem ser assegurados por
  modelos de domínio.
* Desativar a listagem de diretórios no servidor e assegurar que nenhum metadado
  está presente na raiz do servidor web (e.g. .git).
* Registar falhas de controlo de acesso e alertar os administradores sempre que
  necessário (e.g. falhas repetidas).
* Limitar o acesso à API e controladores por forma a minimizar o impacto de
  ataque com recurso a ferramentas automáticas.
* Invalidar _JSON Web Tokens_ (JWT) após o _logout_.
* Incluir testes unitários e de integração para as funcionalidades de controlo
  de acessos.

## Exemplos de Cenários de Ataque

**Cenário #1**: A aplicação usa dados não verificados numa chamada SQL que acede
a informação da conta:

```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
```

Um atacante, de forma simples, modifica o parâmetro acct no seu navegador para
enviar um qualquer outro número de conta à sua escolha. Se o parâmetro não for
devidamente verificado, o atacante pode aceder à conta de qualquer utilizador.

* `https://example.com/app/accountInfo?acct=notmyacct`

**Cenário #2**: Um atacante força a navegação para determinados URL alvo. O
acesso à página de administração requer permissões de administrador.

* `https://example.com/app/getappInfo`
* `https://example.com/app/admin_getappInfo`

Se um utilizador não autenticado puder aceder a essa página, então existe uma
falha. Da mesma forma, se um não-administrador puder aceder à página de
administração, existe igualmente uma falha.

## Referências

### OWASP

* [OWASP Proactive Controls: Access Controls][0xa53]
* [OWASP Application Security Verification Standard: V4 Access Control][0xa54]
* [OWASP Testing Guide: Authorization Testing][0xa55]
* [OWASP Cheat Sheet: Access Control][0xa56]

### Externas

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path
  Traversal')][0xa57]
* [CWE-284: Improper Access Control (Authorization)][0xa58]
* [CWE-285: Improper Authorization][0xa59]
* [CWE-639: Authorization Bypass Through User-Controlled Key][0xa510]
* [Portswigger: Exploiting CORS misconfiguration][0xa511]

[0xa51]: https://owasp.org/www-community/Source_Code_Analysis_Tools
[0xa52]: https://owasp.org/www-community/Vulnerability_Scanning_Tools
[0xa53]: https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls
[0xa54]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md
[0xa55]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README
[0xa56]: https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
[0xa57]: https://cwe.mitre.org/data/definitions/22.html
[0xa58]: https://cwe.mitre.org/data/definitions/284.html
[0xa59]: https://cwe.mitre.org/data/definitions/285.html
[0xa510]: https://cwe.mitre.org/data/definitions/639.html
[0xa511]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

