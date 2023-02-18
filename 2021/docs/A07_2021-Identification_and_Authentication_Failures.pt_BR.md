# A07:2021 – Falhas de identificação e autenticação    ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 7.40                 | 6.50                | 79.51%       | 45.72%       | 132,195           | 3,897      |

## Visão Geral

Anteriormente conhecida como *Quebra de Autenticação*, esta categoria caiu
da segunda posição e agora inclui Fraquezas e
Enumerações Comuns (CWEs) relacionadas à identificação de falhas. 
CWEs notáveis incluídos são: 
*CWE-297: Validação inadequada de certificado com inconsistência de host*,
*CWE-287: Autenticação inadequada*, e
*CWE-384: Fixação de sessão*.

## Descrição 

Confirmação da identidade, autenticação e sessão do usuário
gerenciamento é fundamental para proteger contra autenticação relacionada
ataques. Pode haver pontos fracos de autenticação se o aplicativo:

- Permite ataques automatizados, como preenchimento de credenciais, onde o
     invasor tem uma lista de nomes de usuários e senhas válidos.

- Permite força bruta ou outros ataques automatizados.

- Permite senhas padrão, fracas ou conhecidas, como "Senha1" ou "admin/admin".

- Usa recuperação de credenciais fraca ou ineficaz e esqueci a senha
     processos, como "respostas baseadas em conhecimento", que não podem ser feitas
     de modo seguro.

- Usa armazenamento de dados e senhas em texto simples, criptografadas ou com hash fraco (consulte
    [A02:2021-Falhas Criptográficas](A02_2021-Cryptographic_Failures.pt_BR.md)).

- Possui multifator de autenticação ausente ou ineficaz.

- Expõe o identificador de sessão na URL.

- Reutiliza o identificador de sessão após o login bem-sucedido.

- Não invalida corretamente IDs de sessão. Sessões de usuário ou
     tokens de autenticação (principalmente tokens de logon único (SSO)) não são
     devidamente invalidado durante o logout ou um período de inatividade.

## Como Prevenir

- Sempre que possível, implemente a autenticação multifator para evitar
     preenchimento automatizado de credenciais, força bruta e credenciais roubadas

- Não permita ou implante nenhuma credencial padrão, especialmente para
     usuários administradores.

- Implementar verificações de senha fraca, como testar novas ou alteradas
     contra a lista das 10.000 piores senhas.

- Alinhe o comprimento da senha, a complexidade e as políticas de rotação com
     Instituto Nacional de Padrões e Tecnologia (NIST)
     as diretrizes do 800-63b na seção 5.1.1 para segredos memorizados ou outras
     políticas de senha modernas e baseadas em evidências.

- Certifique-se de que o registro, a recuperação de credenciais e os caminhos da API sejam
     protegido contra ataques de enumeração de contas usando a mesma mensagens para todos os resultados.

- Limite ou atrase cada vez mais as tentativas de login com falha, mas tome cuidado para não criar um cenário de negação de serviço. Registrar todas as falhas e alertar os administradores quando o preenchimento de credenciais, 
     força bruta ou outros ataques são detectados.

- Use um gerenciador de sessão integrado, seguro do lado do servidor que gere um
     novo ID de sessão aleatória com alta entropia após o login. Identificador de sessão
     não deve estar na URL, deve ser armazenado com segurança e invalidado após o logout.

## Exemplos de Cenários de Ataque

**Cenário 1:** O preenchimento de credenciais, que consiste no uso de listas de senhas conhecidas, é um ataque comum. 
Suponha que um aplicativo não implemente proteção automatizada contra ameaças ou preenchimento de credenciais. 
Nesse caso, o aplicativo pode ser usado como um oráculo de senhas para determinar se as credenciais são válidas.

**Cenário 2:** A maioria dos ataques de autenticação ocorre devido ao uso contínuo de senhas como único fator. 
Antes considerada uma boa prática, a rotação de senhas e os requisitos de complexidade encorajam os usuários a usar e reutilizar senhas fracas. As organizações são recomendadas a interromper essas práticas conforme a norma NIST 800-63 e usar autenticação de múltiplos fatores.

**Cenário 3:** Os tempos limite da sessão do aplicativo não estão definidos corretamente. 
Um usuário usa um computador público para acessar um aplicativo. 
Em vez de selecionar "sair", o usuário simplesmente fecha a aba do navegador e sai. 
Uma hora depois, um atacante usa o mesmo navegador, e o usuário ainda está autenticado.

## Referências

- [OWASP Proactive Controls: Implement Digital Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

- [OWASP Application Security Verification Standard: V2 authentication](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Application Security Verification Standard: V3 Session Management](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Authentication](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

- [OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

- NIST 800-63b: 5.1.1 Memorized Secrets

## Lista dos CWEs Mapeados

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)
