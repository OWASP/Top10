# A2:2017 Quebra de Autenticação

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 3 | Prevalência 2 \| Detectabilidade 2 | Técnico 3 \| Negócio |
| Os atacantes têm acesso a centenas de milhões de combinações de nomes de usuário e senha válidos para preenchimento de credenciais, listas de contas administrativas padrão, força bruta automatizada e ferramentas de ataque de dicionário. Os ataques de gerenciamento de sessões são bem compreendidos, particularmente em relação aos tokens de sessão não expirados. | A prevalência de quebra de autenticação é generalizada devido ao design e implementação da maioria dos controles de identidade e de acesso. O gerenciamento de sessões é o base de autenticação e controles de acesso, e está presente em todos os aplicativos que possuem estado. Os atacantes podem detectar a quebra de autenticação usando meios manuais e explorá-los usando ferramentas automatizadas com listas de senhas e ataques de dicionário. | Os atacantes só precisam ter acesso a algumas contas, ou apenas uma conta de administrador para comprometer o sistema. Dependendo do domínio do aplicativo, isso pode permitir lavagem de dinheiro, fraude de CPF e roubo de identidade, ou divulgar informações altamente sensíveis legalmente protegidas. |

## A Aplicação Está Vulnerável?

A confirmação da identidade, autenticação e gerenciamento de sessão do usuário é fundamental para proteger contra ataques relacionados à autenticação.

Podem haver pontos fracos de autenticação se a sua aplicação:

- Permite ataques automatizados, como [teste exaustivo de credenciais, ou *credential stuffing*](https://owasp.org/www-community/attacks/Credential_stuffing), onde o atacante possui uma lista de nomes de usuário e senhas válidos.
- Permite ataque de força bruta ou outros ataques automatizados.
- Permite senhas padrão, fracas ou bastante conhecidas, como "Password1" ou "admin/admin".
- Utiliza processos de recuperação de credenciais ou de recuperação de senhas fracos ou ineficazes, tais como "respostas baseadas em conhecimento", que não podem ser consideradas seguras.
- Usa senhas em texto simples, criptografadas ou com hash muito fracos (veja **A3:2017-Exposição de dados sensíveis**).
- Não possua autenticação multi-fator ou a mesma não funciona corretamente.
- Expõe IDs de sessão na URL (por exemplo, reescrita de URL).
- Não rotaciona os IDs de sessão após um login bem-sucedido.
- Não invalida devidamente as IDs da Sessão. As sessões de usuário ou os tokens de autenticação (particularmente tokens de single sign-on (SSO)) não são devidamente invalidados durante o logout ou um período de inatividade.

## Como Prevenir?

- Sempre que possível, implemente a autenticação multi-fator para evitar ataques automatizados de preenchimento de credenciais, força bruta e de credenciais roubadas.
- Não envie ou implante com quaisquer credenciais padrão, particularmente para usuários administradores.
- Implementar verificações de senha fracas, como testar senhas novas ou alteradas em uma lista das [Top 10000 piores senhas](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
- Alinhe o comprimento da senha, a complexidade e as políticas de rotação com as diretrizes do NIST 800-63 B na seção 5.1.1 para [Segredos Memorizados](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) ou outras políticas modernas de senha baseadas em evidências.
- Assegure-se de que o registro de novas contas, a recuperação de credenciais e os caminhos até as APIs sejam endurecidos contra ataques de enumeração de conta usando as mesmas mensagens para todos os resultados.
- Limite ou retarde de forma progressiva as tentativas de login falhadas. Logar todas as falhas e alertar os administradores quando o preenchimento de credenciais, a força bruta, e outros ataques forem detectados.
- Use um gerenciador de sessão seguro, no lado do servidor, que gere uma nova ID de sessão aleatória com alta entropia após o login. IDs de sessão não devem estar na URL, e devem ser armazenadas de forma segura e invalidadas após o logout, tempo ocioso e tempo limite absolutos.

## Exemplos de Cenários de Ataque

**Cenário #1**: [Teste exaustivo de credenciais ou *credential stuffing*](https://owasp.org/www-community/attacks/Credential_stuffing), o uso de [listas de senhas conhecidas](https://github.com/danielmiessler/SecLists), é um ataque comum. Se uma aplicação não implementar proteções de ameaças ou de preenchimento automatizados de  credenciais, a aplicação pode ser usada como um oráculo de senha para determinar se as credenciais são válidas.

**Cenário #2**: A maioria dos ataques de autenticação ocorrem devido ao uso contínuo de senhas como único fator. Uma vez consideradas as melhores práticas, a troca de senha e os requisitos de complexidade são vistos como incentivo aos usuários a usar e reutilizar senhas fracas. As organizações são recomendadas para parar essas práticas por NIST 800-63 e usar autenticação multi-fator.

**Cenário #3**: Os tempos limite da sessão da aplicação não estão configurados corretamente. Um usuário usa um computador público para acessar a aplicação. Em vez de selecionar "logout", o usuário simplesmente fecha a guia do navegador e se afasta. Um atacante usa o mesmo navegador uma hora depois e o usuário ainda está autenticado.

## Referências

### OWASP

- [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)
- [OWASP Application Security Verification Standard: V2 Authentication](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
- [OWASP Application Security Verification Standard: V3 Session Management](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V3-Session-management.md)
- [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README)
 and [Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

### Externos

- [NIST 800-63b: 5.1.1 Memorized Secrets - for thorough, modern, evidence based advice on authentication.](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
