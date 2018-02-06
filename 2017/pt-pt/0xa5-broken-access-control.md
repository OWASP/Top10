# A5:2017 Quebra de Controlo de Acessos

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 2 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| A exploração do controlo de acesso é uma das principais competências dos profissionais de testes de intrusão. Ferramentas SAST e DASTpodem detectar a ausência de controlo de acessos, mas não conseguem verificar a funcionalidade dos mesmos. O controlo de acessos é detectável através de meios manuais, ou possivelmente através da automação da detecção da ausência de controlos de acesso em determinadas frameworks. | As fraquezas de controlo de acessos são comuns devido à falta de detecção automática, e a falta de testes funcionais realizados pelos programadores. A detecção de controlo de acessos não é fácil de realizar recorrendo a testes automatizados estáticos ou dinâmicos. | O impacto técnico reside em atacantes anónimo poderem actuar como utilizadores ou administradores legítimos, utilizadores usarem funções priviligiadas, ou criar, aceder, actualizar ou apagar todos os registos. |

##Está a Aplicação Vulnerável?

O controlo de acessos força a política de forma a que os utilizadores não possam agir fora das suas permissões atribuídas. As falhas levam tipicamente ao acesso não autorizado ou revelação de informação, modificação ou destruição de todos os dados, ou execução de funções de negócio fora dos limites do utilizador. Vulnerabilidades comuns de controlo de acesso incluem:

* Ultrapassar as verificações de controlo de acesso através da modificação da URL, estado interno de uma aplicação, ou página HTML, ou através de uma ferramenta customizada que realiza pedidos a uma API.
* Permitir que a chave primária possa ser alterada para um registo de outro utilizador, tal como visualizar ou editar a conta de outro utilizador.
* Escalar privilégios. Actuar como um utilizador sem ter feito o processo de "login", ou actuar como um administrador quando apenas efectuou "login" como utilizador.
* Manipulação de Metainformação, tal como a repetição ou alteração de um token JWT de controlo de acesso ou um cookie ou campo escondido manipulado para elevar privilégios.
* Imprórpia configuração do CORS permite acesso não-autorizado a uma API.
* Forçar a navegação para páginas autenticadas como um utilizador não-autenticado, ou para páginas priviligiadas como um utilizador normal ou API não forçando controlo de acessos para POST, PUT e DELETE.

## Como Prevenir?

O controlo de acesso é apenas efectivo se for forçado em código de confiança do lado do servidor ou API, em que o atacante não possa modificar o controlo de acesso nem a metainformação.

* Com a excepção de recursos públicos, negue por defeito.
Implementar mecanismos de controlo de acesso uma vez e reutilizar os mesmos ao longo da aplicação.
* Modelar os controlos de acesso que assegurem a posse dos registos, por oposição ao modelo que aceita que um utilizador possa criar, ler, actualizar ou apagar qualquer registo.
* Os controlos de acesso de domínio são únicos para cada aplicação, mas os requisitos limitados dos negócios devem ser assegurados por modelos de domínio.
* Desactivar a listagem de directorias no servidor, e assegurar que metainformação dos ficheiros (p.e. .git) não está presente na raíz de servidores web.
* Registar falhas de controlo de acesso, alertar os administradores sempre que necessário (p.e. falhas repetidas).
* Limitar o acesso à API e controlador para minimizar o impacto de ataque automatizado de ferramentas.
* Programadores e equipa de garantia da qualidade deve incluir unidade de controlo de acesso funcional e testes de integração.

## Exemplos de Cenários de Ataque

**Cenário #1**: A aplicação usa dados não verificados numa chamada SQL que acede a informação da conta:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery( );
```

Um atacante simplesmente modifica o parâmetro 'acct' no browser web para enviar um número de conta qualquer que deseje. Se não for devidamente verificado, o atacante pode aceder a qualquer conta de qualquer utilizador.

* `http://example.com/app/accountInfo?acct=notmyacct`

**Cenário #2**:  Um atacante simplesmente força a navegação para uma determinada URL alvo. Direitos de administração são requeridos para aceder à página de administração.

* `http://example.com/app/getappInfo`
* `http://example.com/app/admin_getappInfo`

Se um utilizador não autenticado puder aceder a essa página, temos uma falha. Se um não administrador puder aceder à página de administração, temos uma falha.

## Referências

### OWASP

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Authorization Testing](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Externas

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')]()
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [Portswigger: Exploiting CORS misconfiguration](http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
