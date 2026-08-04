# A07:2025 Falhas de Autenticação ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## Contexto

Falhas de Autenticação mantém sua posição em #7 com uma leve mudança no nome para refletir com mais precisão as 36 CWEs nesta categoria. Apesar dos benefícios de _frameworks_ padronizados, esta categoria manteve sua classificação de 2021. CWEs notáveis incluídas são _CWE-259 Use of Hard-coded Password_, _CWE-297: Improper Validation of Certificate with Host Mismatch_, _CWE-287: Improper Authentication_, _CWE-384: Session Fixation_ e _CWE-798 Use of Hard-coded Credentials_.

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
   <td>36
   </td>
   <td>15,80%
   </td>
   <td>2,92%
   </td>
   <td>100,00%
   </td>
   <td>37,14%
   </td>
   <td>7,69
   </td>
   <td>4,44
   </td>
   <td>1.120.673
   </td>
   <td>7.147
   </td>
  </tr>
</table>

## Descrição

Esta vulnerabilidade está presente quando um atacante é capaz de enganar um sistema para reconhecer um usuário inválido ou incorreto como legítimo. Pode haver fraquezas de autenticação se a aplicação:

- Permite ataques automatizados, como _credential stuffing_, onde o atacante possui uma lista vazada de nomes de usuário e senhas válidos. Recentemente, esse tipo de ataque foi expandido para incluir ataques de senha híbridos (também conhecidos como ataques de _password spray_), onde o atacante usa variações ou incrementos de credenciais vazadas para ganhar acesso — por exemplo, tentando Password1!, Password2!, Password3! e assim por diante.
- Permite _brute force_ ou outros ataques automatizados por scripts que não são bloqueados rapidamente.
- Permite senhas padrão, fracas ou bem conhecidas, como o nome de usuário "admin" com a senha "admin" ou a senha "Password1".
- Permite que usuários criem novas contas com credenciais que já se sabe terem sido comprometidas em vazamentos.
- Permite o uso de processos de recuperação de credenciais e "esqueci minha senha" fracos ou ineficazes, como "perguntas baseadas em conhecimento", que não podem ser tornadas seguras.
- Usa repositórios de dados de senhas em texto puro, criptografados ou com _hashes_ fracos (veja [A04:2025-Falhas Criptográficas](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)).
- Possui autenticação multifator (MFA) ausente ou ineficaz.
- Permite o uso de _fallbacks_ fracos ou ineficazes caso a autenticação multifator não esteja disponível.
- Expõe o identificador de sessão na URL, em um campo oculto ou em outro local inseguro que seja acessível ao cliente.
- Reutiliza o mesmo identificador de sessão após um login bem-sucedido.
- Não invalida corretamente as sessões de usuário ou _tokens_ de autenticação (principalmente _tokens_ de Single Sign-On (SSO)) durante o logout ou após um período de inatividade.
- Não valida corretamente o escopo e o público-alvo (_audience_) das credenciais fornecidas.

## Como prevenir

- Sempre que possível, implemente e force o uso de autenticação multifator (MFA) para prevenir _credential stuffing_ automatizado, _brute force_ e ataques de reutilização de credenciais roubadas.
- Sempre que possível, incentive e habilite o uso de gerenciadores de senhas para ajudar os usuários a fazerem escolhas melhores.
- Não envie ou implante o sistema com credenciais padrão, particularmente para usuários administradores.
- Implemente verificações de senhas fracas, como testar senhas novas ou alteradas contra uma lista das 10.000 piores senhas.
- Durante a criação de novas contas e alterações de senha, valide-as contra listas de credenciais conhecidas como vazadas (ex: usando [haveibeenpwned.com](https://haveibeenpwned.com)).
- Alinhe as políticas de comprimento, complexidade e rotação de senhas com as [diretrizes do National Institute of Standards and Technology (NIST) 800-63b, seção 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) para Segredos Memorizados ou outras políticas de senha modernas baseadas em evidências.
- Não force seres humanos a rotacionar senhas, a menos que você suspeite de uma violação. Se suspeitar de violação, force a redefinição de senha imediatamente.
- Garanta que as rotas de registro, recuperação de credenciais e caminhos de API sejam endurecidos contra ataques de enumeração de contas, usando as mesmas mensagens para todos os resultados ("Nome de usuário ou senha inválidos.").
- Limite ou atrase progressivamente as tentativas de login malsucedidas, mas tome cuidado para não criar um cenário de negação de serviço (DoS). Registre todas as falhas em logs e alerte os administradores quando ataques de _credential stuffing_, _brute force_ ou outros forem detectados ou suspeitos.
- Use um gerenciador de sessão seguro e nativo no lado do servidor que gere um novo ID de sessão aleatório com alta entropia após o login. Identificadores de sessão não devem estar na URL, devem ser armazenados de forma segura em um _cookie_ seguro e invalidados após logout, inatividade e expiração absoluta (_timeout_).
- Idealmente, use um sistema pronto e bem estabelecido para lidar com autenticação, identidade e gerenciamento de sessão. Transfira esse risco sempre que possível, comprando e utilizando um sistema testado e endurecido.
- Verifique o uso pretendido das credenciais fornecidas; por exemplo, para JWTs, valide as _claims_ `aud`, `iss` e os escopos.

## Exemplos de cenários de ataque

**Cenário #1:** O _credential stuffing_ — o uso de listas de combinações conhecidas de nomes de usuário e senhas — é agora um ataque muito comum. Mais recentemente, descobriu-se que atacantes "incrementam" ou ajustam senhas com base no comportamento humano comum. Por exemplo, alterando 'Winter2025' para 'Winter2026', ou 'ILoveMyDog6' para 'ILoveMyDog7'. Esse ajuste de tentativas de senha é chamado de ataque de _credential stuffing_ híbrido ou ataque de _password spray_, e eles podem ser ainda mais eficazes do que a versão tradicional. Se uma aplicação não implementa defesas contra ameaças automatizadas (_brute force_, scripts ou _bots_) ou _credential stuffing_, a aplicação pode ser usada como um "oráculo de senhas" para determinar se as credenciais são válidas e obter acesso não autorizado.

**Cenário #2:** A maioria dos ataques de autenticação bem-sucedidos ocorre devido ao uso contínuo de senhas como o único fator de autenticação. Outrora consideradas melhores práticas, as exigências de rotação e complexidade de senhas encorajam os usuários tanto a reutilizar senhas quanto a usar senhas fracas. Recomenda-se que as organizações interrompam essas práticas conforme a norma NIST 800-63 e forcem o uso de autenticação multifator em todos os sistemas importantes.

**Cenário #3:** Os tempos de expiração de sessão (_timeouts_) da aplicação não estão implementados corretamente. Um usuário utiliza um computador público para acessar uma aplicação e, em vez de selecionar "logout", simplesmente fecha a aba do navegador e vai embora. Outro exemplo é quando uma sessão de Single Sign-On (SSO) não pode ser encerrada por um Single Logout (SLO). Ou seja, um único login autentica você no seu leitor de e-mails, sistema de documentos e sistema de chat, por exemplo. Mas o logout acontece apenas no sistema atual. Se um atacante usar o mesmo navegador após a vítima pensar que deslogou com sucesso, mas ainda estiver autenticada em algumas das aplicações, ele poderá acessar a conta da vítima. O mesmo problema pode ocorrer em escritórios e empresas quando uma aplicação sensível não foi devidamente encerrada e um colega tem acesso (temporário) ao computador desbloqueado.

## Referências

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)

## Lista de CWEs Mapeadas

- [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)
- [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)
- [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)
- [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)
- [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)
- [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)
- [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)
- [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)
- [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)
- [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)
- [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)
- [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)
- [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)
- [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)
- [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)
- [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)
- [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)
- [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)
- [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)
- [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)
- [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)
- [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)
- [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)
