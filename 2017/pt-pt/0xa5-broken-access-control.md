# A5:2017 Quebra de Controlo de Acessos

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Abuso 2 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| O abuso do controlo de acessos é uma competências base dos atacantes. Ferramentas automáticas como SAST e DAST podem detetar a ausência, mas não validar o funcionamento do controlo de acessos quando presente. A deteção do controlo de acessos envolve processos manuais. | As falhas de controlo de acessos são comuns devido à falta de processos automáticos de deteção e à falta de testes funcionais realizados pelos programadores. A deteção de controlo de acessos não é fácil de realizar recorrendo a testes automáticos tanto estáticos como dinâmicos. | O impacto técnico reside no facto dos atacantes poderem atuar como utilizadores ou administradores legítimos, utilizadores usarem funções priviligiadas ou criar, aceder, atualizar ou apagar todos os registos. O impacto no negócio depende na necessidade de proteção dos dados. |

## A Aplicação é Vulnerável?

O controlo de acessos garante que os utilizadores não podem agir além das
permissões que lhe foram atribuídas. Falhas no controlo de acessos levam
tipicamente à divulgação não autorizada de informação, modificação ou destruição
de todos os dados, ou á execução de funções de negócio fora dos limites do
utilizador. As vulnerabilidades comuns incluem:

* Ultrapassar as verificações de controlo de acesso modificando o URL, estado
  interno da aplicação, ou página HTML, ou através da utilização de ferramenta
  para ataque a APIs.
* Permitir a alteração da chave primária para um registo doutro utilizador,
  permitindo visualizar ou editar a conta deste.
* Elevação de privilégios. Atuar como um utilizador sem ter feito o processo de
  "login", ou atuar como administrador mesmo tendo perfil de utilizador regular.
* Manipulação de meta-informação, tais como repetição ou adulteração do JSON Web
  Token (JWT) de controlo de acesso, cookie ou campo escondido para elevação de
  privilégios.
* Acesso não autorizado a uma API devido a má configuração da política de
  partilha de recursos entre origens (CORS).
* Forçar a navegação para páginas autenticadas como um utilizador
  não-autenticado, ou para páginas priviligiadas como um utilizador normal, asim
  como utilizar uma API sem o devido controlo de acessos para operações POST,
  PUT e DELETE.

## Como Prevenir

O controlo de acessos é apenas efetivo se realizado por código confiável a
correr no servidor ou pelas APIs em arquiteturas serverless, em que o atacante
não pode modificar a validação do controlo de acessos nem a meta-informação.

* Com a excepção dos recursos públicos, o acesso deve ser negado por omissão.
* Implementar mecanismos de controlo de acesso uma única vez, reutilizando-os ao
  longo da aplicação, incluíndo CORS.
* Modelar controlo de acesso que assegure a propriedade dos registos, por
  oposição ao modelo que aceita que um utilizador possa criar, ler, actualizar
  ou apagar qualquer registo.
* As regras de negócio específicas duma aplicação, devem ser assegurados por
  modelos de domínio.
* Desativar a listagem de diretorias no servidor e assegurar que nenhuma
  meta-informação está presente na raíz do servidor web (e.g. `.git`).
* Registar falhas de controlo de acesso e alertar os administradores sempre que
  necessário (e.g. falhas repetidas).
* Limitar o acesso à API e controladores por forma a minimizar o impacto de
  ataque com recurso a ferramentas automáticas.
* Invalidar JSON Web Tokens (JWT) após o logout.
* Incluir testes unitários e de integração para as funcionalidades de controlo
  de acessos.

## Exemplos de Cenários de Ataque

**Cenário #1**: A aplicação usa dados não verificados numa chamada SQL que acede
a informação da conta:

```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
```

Um atacante, de forma simples, modifica o parâmetro `acct` no seu navegador para
enviar um qualquer outro número de conta à sua escolha. Se o parâmetro não for
devidamente verificado, o atacante pode aceder à conta de qualquer utilizador.

* `http://example.com/app/accountInfo?acct=notmyacct`

**Cenário #2**: Um atacante força a navegação para determinados URL alvo. O
acesso à pàgina de administração requer permissões de administrador.

* `http://example.com/app/getappInfo`
* `http://example.com/app/admin_getappInfo`

Se um utilizador não autenticado puder aceder a essa página, então existe uma
falha. Da mesma forma, se um não-administrador puder aceder à página de
administração, existe igualmente uma falha.

## Referências

### OWASP

* [OWASP Proactive Controls: Access Controls][1]
* [OWASP Application Security Verification Standard: V4 Access Control][2]
* [OWASP Testing Guide: Authorization Testing][3]
* [OWASP Cheat Sheet: Access Control][4]

### Externas

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path
  Traversal')][5]
* [CWE-284: Improper Access Control (Authorization)][6]
* [CWE-285: Improper Authorization][7]
* [CWE-639: Authorization Bypass Through User-Controlled Key][8]
* [Portswigger: Exploiting CORS misconfiguration][9]

[1]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls
[2]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home
[3]: https://www.owasp.org/index.php/Testing_for_Authorization
[4]: https://www.owasp.org/index.php/Access_Control_Cheat_Sheet
[5]: https://cwe.mitre.org/data/definitions/22.html
[6]: https://cwe.mitre.org/data/definitions/284.html
[7]: https://cwe.mitre.org/data/definitions/285.html
[8]: https://cwe.mitre.org/data/definitions/639.html
[9]: http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html

