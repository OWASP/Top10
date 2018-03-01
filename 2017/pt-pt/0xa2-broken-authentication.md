# A2:2017 Quebra de Autenticação

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Abuso 3 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| Os atacantes têm acesso a centenas de milhões de combinações de nomes de utilizador e palavras-passe válidas para preenchimento de credenciais, listas de contas administrativas padrão, ferramentas automatizadas para ataques de força bruta e ataque de dicionário. Ataques ao sistema de gestão de sessões são geralmente compreendidos, em particular no que diz respeito a tokens de sessão que não expiram. | A prevalência da quebra de autenticação está muito disseminada devido ao desenho e implementação de muitos controlos de gestão de identidades e acesso. A gestão de sessão é o alicerce da autenticação e controlo de acesso, estando presente em todas as aplicações que guardam estado. Os atacantes podem detetar quebras de autenticação através de processos manuais, abusando das mesmas com recurso a ferramentas automáticas com listas de palavras-passe e ataques de dicionário. | Os atacantes apenas têm que ganhar acesso a algumas contas, ou a uma conta de administrador para comprometer o sistema. Dependendo do domínio da aplicação, isto pode permitir a lavagem de dinheiro, fraudes na segurança social e roubo de identidade; ou revelação de informação altamente sensível. |

## A Aplicação é Vulnerável?

A confirmação da identidade do utilizador, autenticação e gestão da sessão são
críticas para a defesa contra ataques relacionados com autenticação.

A sua aplicação poderá ter problemas na autenticação se:

* Permite ataques automatizados tais como [credential stuffing][1] (teste
  exaustivo), em que o atacante possui uma lista de nomes de utilizadores e
  palavras-passe válidos.
* Permite ataques de força bruta ou outro tipo de ataques automatizados.
* Permite palavras-passe padrão, fracas ou conhecidas, tais somo "Password1" ou
  "admin/admin".
* Usa processos fracos ou ineficazes de recuperação de credenciais e de
  recuperação de palavra-passe, tais como "perguntas baseadas em conhecimento",
  que podem não ser seguras.
* A utilização de palavras-passe em claro, encriptadas, ou com resumos (_hash_)
  fracos (veja [A3:2017 Exposição de Dados Sensíveis][2]).
* Não possua autenticação multi-factor ou que a mesma não funcione
  correctamente.
* Expõe os identificadores de sessão no URL (e.g. quando o URLs é re-escrito).
* Não ronova os identificadores de sessão após o processo de "login" ter sido
  bem sucedido.
* Não invalida convenientemente os identificadores de sessão. As sessões do
  utilizador ou os tokens de autenticação (em particular os de "single sign-on"
  (SSO)) não são invalidados convenientemente durante o processo de "logout" ou
  após um período de inatividade.

## Como Prevenir?

* Sempre que possível, implementar autenticação multi-factor por forma a
  prevenir ataques automatizado de [credential stuffing][1], força bruta e
  reutilização de credenciais roubadas.
* Não disponibilizar a aplicação com credenciais pré-definidas, em especial para
  utilizadores com perfil de administrador.
* Implementar verificações de palavras-chave fracas, tais como comparar as
  palavras-passe novas ou alteradas com a lista [das Top 10000 piores
  palavras-passe][3].
* Alinhar o comprimento da palavra-passe, complexidade e políticas de
  rotatividade com o guia [NIST 800-63 B na secção 5.1.1 para Memorized
  Secrets][4] ou outras políticas modernas para palavras-passe, baseadas em
  evidências.
* Assegurar que o registo, recuperação de credenciais, e caminhos da API estão
  preparados para resistirem a ataques de enumeração de contas usando as mesmas
  mensagens para todos os resultados.
* Limitar o número máximo de tentativas de login falhadas ou atrasar
  progressivamente esta operação. Registar todas as falhas de autenticação e
  alertar os administradores sempre que forem detetados ataques de teste
  exaustivo de palavras-passe, força bruta ou outros.
* Usar, no servidor, um gestor de sessões seguro que gere novos identificadores
  de sessão aleatórios e com elevado nível de entropia após o login. Os
  identificadores de sessão não devem constar do URL e devem ser guardados de
  forma segura e invalidados após o logout, por inatividade e ao fim dum período
  de tempo fixo.

## Exemplos de Cenários de Ataque

**Cenário #1**: [o teste exaustivo de credenciais, ou credential stuffing][5],
que consiste na utilização de [listas de palavras-passe conhecidas][6], é um
ataque comum. Se uma aplicação não implementar um automatismo de proteção contra
ameaças ou teste exaustivo de credenciais, esta pode ser usada como um oráculo
de palavras-pase para determinar se as credenciais são válidas.

**Cenário #2**: A maioria dos ataques de autenticação ocorrem devido ao fato de
se usarem as palavras-passe como único factor. Outrora consideradas boas
práticas, a rotatividade das palavras-passe e a complexidade das mesmas são hoje
vistas como factores para encorajar os utilizadores a usar e reutilizar
palavras-passe fracas. Recomenda-se às organizações deixarem de usar estas
práticas (NIST 800-63) e passarem a usar autenticação multi-factor.

**Cenário #3**: O tempo de expiração das sessões não é definido de forma
correcta. Um utilizador utiliza um computador público para aceder a uma
aplicação. Ao invés de fazer logout o utilizado simplesmente fecha o separador
do navegador e vai-se embora. Um atacante usa o mesmo computar uma hora depois e
o utilizador está ainda autenticado.

## Referências

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls][7]
* [OWASP Application Security Verification Standard: V2 Authentication][8]
* [OWASP Application Security Verification Standard: V3 Session Management][9]
* [OWASP Testing Guide: Identity][10] and [Authentication][11]
* [OWASP Cheat Sheet: Authentication][12]
* [OWASP Cheat Sheet: Credential Stuffing][13]
* [OWASP Cheat Sheet: Forgot Password][14]
* [OWASP Cheat Sheet: Password Storage][15]
* [OWASP Cheat Sheet: Session Management][16]

### Externas

* [NIST 800-63b: 5.1.1 Memorized Secrets - for thorough, modern, evidence based
  advice on authentication][17]
* [CWE-287: Improper Authentication][18]
* [CWE-384: Session Fixation][19]

[1]: https://www.owasp.org/index.php/Credential_stuffing
[2]: 0xa3-sensitive-data-disclosure.md
[3]: https://github.com/danielmiessler/SecLists/tree/master/Passwords
[4]: https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret
[5]: https://www.owasp.org/index.php/Credential_stuffing
[6]: https://github.com/danielmiessler/SecLists
[7]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls
[8]: https://www.owasp.org/index.php/ASVS_V2_Authentication
[9]: https://www.owasp.org/index.php/ASVS_V3_Session_Management
[10]: https://www.owasp.org/index.php/Testing_Identity_Management
[11]: https://www.owasp.org/index.php/Testing_for_authentication
[12]: https://www.owasp.org/index.php/Authentication_Cheat_Sheet
[13]: https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet
[14]: https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet
[15]: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
[16]: https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
[17]: https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret
[18]: https://cwe.mitre.org/data/definitions/287.html
[19]: https://cwe.mitre.org/data/definitions/384.html

