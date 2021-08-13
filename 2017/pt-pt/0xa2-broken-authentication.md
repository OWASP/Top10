# A2:2017 Quebra de Autenticação


| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 3 | Prevalência: 2 \| Deteção: 2 | Técnico: 3 \| Negócio ? |
| Os atacantes têm acesso a uma infinidade de combinações de nome de utilizador e palavras-passe válidas para ataques de _credential stuffing_ (teste exaustivo), força bruta e de dicionário bem como acesso a contas padrão de administração. Ataques à gestão de sessão são genericamente compreendidos em particular tokens que não expiram. | A quebra de autenticação está bastante difundida devido ao desenho e implementação de muitos controlos de identificação e acesso. A gestão de sessão é o alicerce da autenticação e controlo de acesso, estando presente em todas as aplicações que guardam estado. Os atacantes podem detetar quebras de autenticação através de processos manuais, abusando com recurso a ferramentas automáticas com listas de palavras-passe e ataques de dicionário. | Os atacantes apenas têm de ganhar acesso a algumas contas, ou a uma conta de administrador para comprometer o sistema. Dependendo do domínio da aplicação, isto pode permitir a lavagem de dinheiro, fraudes na segurança social e roubo de identidade; ou revelação de informação altamente sensível. |

## A Aplicação é Vulnerável?

A confirmação da identidade do utilizador, autenticação e gestão da sessão são
críticas para a defesa contra ataques relacionados com autenticação.

A sua aplicação poderá ter problemas na autenticação se:

- Permite ataques automatizados tais como [credential stuffing][0xa21] ou força
  bruta.
- Permite palavras-passe padrão, fracas ou conhecidas, tais como "Password1" ou
  "admin/admin".
- Usa processos fracos ou ineficazes de recuperação de credenciais e recuperação
  de palavra-passe e.g. "perguntas baseadas em conhecimento", que podem não ser
  seguras.
- Usa as palavras-passe em claro, encriptação ou resumos (hash) fracas (veja
  [A3:2017 Exposição de Dados Sensíveis][0xa22]).
- Não possui autenticação multi-fator ou o mesmo não funciona corretamente.
- Expõe os identificadores de sessão no URL (e.g. quando o endereço é
  reescrito).
- Não renova os identificadores de sessão após o processo de autenticação ter
  sido bem sucedido.
- Não invalida convenientemente os identificadores de sessão. As sessões do
  utilizador ou os tokens de autenticação (em particular os de single sign-on
  (SSO)) não são invalidados convenientemente durante o processo de término de
  sessão (logout) ou após um período de inatividade.

## Como Prevenir

- Sempre que possível, implementar autenticação multi-fator por forma a prevenir
  ataques automatizados de _credential stuffing_, força bruta e reutilização de
  credenciais roubadas.
- Não disponibilizar a aplicação com credenciais pré-definidas, em especial para
  utilizadores com perfil de administrador.
- Implementar verificações de palavras-chave fracas, tais como comparar as
  palavras-passe novas ou alteradas com a lista das [Top 10000 piores
  palavras-passe][0xa23].
- Seguir as recomendações do guia NIST 800-63 B na secção 5.1.1 para Memorized
  Secrets ou outras políticas modernas para palavras-passe, baseadas em
  evidências.
- Assegurar que o registo, recuperação de credenciais e API estão preparados
  para resistir a ataques de enumeração de contas usando as mesmas mensagens
  para todos os resultados (sucesso/insucesso).
- Limitar o número máximo de tentativas de autenticação falhadas ou atrasar
  progressivamente esta operação. Registar todas as falhas e alertar os
  administradores quando detetados ataques de teste exaustivo, força bruta ou
  outros.
- Usar, no servidor, um gestor de sessões seguro que gere novos identificadores
  de sessão aleatórios e com elevado nível de entropia após a autenticação. Os
  identificadores de sessão não devem constar no URL, devem ser guardados de
  forma segura e invalidados após o _logout_, por inatividade e ao fim dum
  período de tempo fixo.

## Exemplos de Cenários de Ataque

**Cenário #1**: [credential stuffing][0xa21] é um ataque comum que consiste na
utilização de listas de palavras-passe conhecidas. Se uma aplicação não
implementar um automatismo de proteção contra o teste exaustivo de credenciais,
esta pode ser usada como um oráculo de palavras-passe para determinar se as
credenciais são válidas.

**Cenário #2**: A maioria dos ataques de autenticação ocorrem devido ao fato de
se usarem as palavras-passe como único fator. Outrora consideradas boas
práticas, a rotatividade das palavras-passe e a complexidade das mesmas são hoje
vistas como fatores para encorajar os utilizadores a usar e reutilizar
palavras-passe fracas. Recomenda-se às organizações deixarem de usar estas
práticas (NIST 800-63) e passarem a usar autenticação multi-fator.

**Cenário #3**: O tempo de expiração das sessões não é definido de forma
correta. Um utilizador utiliza um computador público para aceder a uma
aplicação. Ao invés de fazer logout o utilizador simplesmente fecha o separador
do navegador e vai-se embora. Um atacante usa o mesmo computador uma hora depois
e o utilizador está ainda autenticado.

## Referências

### OWASP

- [OWASP Proactive Controls: Implement Identity and Authentication Controls][0xa27]
- [OWASP Application Security Verification Standard: V2 Authentication][0xa28]
- [OWASP Application Security Verification Standard: V3 Session Management][0xa29]
- [OWASP Testing Guide: Identity][0xa210] e [Authentication][0xa211]
- [OWASP Cheat Sheet: Authentication][0xa212]
- [OWASP Cheat Sheet: Credential Stuffing][0xa213]
- [OWASP Cheat Sheet: Forgot Password][0xa214]
- [OWASP Cheat Sheet: Password Storage][0xa215]
- [OWASP Cheat Sheet: Session Management][0xa216]

### Externas

- [NIST 800-63b: 5.1.1 Memorized Secrets - for thorough, modern, evidence based
  advice on authentication][0xa217]
- [CWE-287: Improper Authentication][0xa218]
- [CWE-384: Session Fixation][0xa219]

[0xa21]: https://owasp.org/www-community/attacks/Credential_stuffing
[0xa22]: 0xa3-sensitive-data-disclosure.md
[0xa23]: https://github.com/danielmiessler/SecLists/tree/master/Passwords
[0xa24]: https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret
[0xa25]: https://owasp.org/www-community/attacks/Credential_stuffing
[0xa26]: https://github.com/danielmiessler/SecLists
[0xa27]: https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity
[0xa28]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md
[0xa29]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V3-Session-management.md
[0xa210]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README
[0xa211]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README
[0xa212]: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
[0xa213]: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
[0xa214]: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
[0xa215]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[0xa216]: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
[0xa217]: https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret
[0xa218]: https://cwe.mitre.org/data/definitions/287.html
[0xa219]: https://cwe.mitre.org/data/definitions/384.html

