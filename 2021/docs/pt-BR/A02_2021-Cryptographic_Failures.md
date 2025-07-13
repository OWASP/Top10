# A02:2021 – Falhas Criptográficas    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:-------------------------:|:------------------------:|:--------------------------:|:-----------------------:|:----------------:|:---------------:|:--------------------:|:-------------:|
| 29            | 46.44%                    | 4.49%                    |7.29                        | 6.81                    |  79.33%          | 34.85%          | 233,788              | 3,075         |

## Visão Geral

Subindo uma posição para #2, anteriormente conhecido como *Exposição de Dados
Sensíveis*, que é mais um sintoma amplo do que uma causa raiz,
o foco está nas falhas relacionadas à criptografia (ou falta dela).
O que muitas vezes leva à exposição de dados confidenciais. Notável _Common Weakness
Enumerations_ (CWEs) incluídas são *CWE-259: Uso de Senha no Código*,
*CWE-327: Algoritmo Criptográfico Quebrado ou Arriscado* e *CWE-331 Entropia Insuficiente*.

## Descrição 

A primeira coisa é determinar as necessidades de proteção dos dados
em trânsito e armazenados. Por exemplo, senhas, número de cartão de crédito,
registros de saúde, informações pessoas e segredos de negócios que requerem
proteção extra, principalmente se esses dados se enquadrarem nas leis de
privacidade, alguns exemplos são a da Europa General Data Protection Regulation
(GDPR) ou regulamentos de proteção de dados financeiros, como PCI Data Security
Standard (PCI DSS). Para todos esses dados:

- Todos os dados são transmitidos em texto não criptografado? Isso diz respeito a
    protocolos como HTTP, SMTP, FTP também usando atualizações TLS como STARTTLS.
    O tráfego externo da Internet é perigoso. Verifique todo o tráfego interno,
    por exemplo, entre balanceadores de carga, servidores da web ou sistemas _back-end_.

- Algum algoritmo ou protocolo criptográfico antigo ou fraco é usado por padrão ou
    em código mais antigo?

- As chaves criptográficas padrão em uso, são chaves criptográficas geradas fracas
    ou reutilizadas, faltando o gerenciamento ou rotação de chaves adequado?
    As chaves criptográficas são verificadas nos repositórios de código-fonte?

- A criptografia não é aplicada, por exemplo, há alguma diretiva de segurança
    de cabeçalhos HTTP (navegador) ou cabeçalhos ausentes?

- O certificado do servidor recebido e a cadeia de confiança estão devidamente validados? 

- Os vetores de inicialização são ignorados, reutilizados ou não gerados
    suficientemente seguros para o modo criptográfico de operação? Está em uso um modo
    de operação inseguro, como o ECB? A criptografia é usada quando a criptografia
    autenticada é a mais apropriada?

- As senhas estão sendo usadas como chaves criptográficas na ausência de uma função
    de derivação de chave de base de senha?

- A aleatoriedade é usada para fins criptográficos que não foram projetados para atender
    aos requisitos criptográficos? Mesmo se a função correta for escolhida, ela precisa
    ser propagada pelo desenvolvedor e, se não, o desenvolvedor sobrescreveu a forte
    funcionalidade de propagação incorporada a ela com uma semente que carece de
    entropia/imprevisibilidade suficiente?

- Estão em uso funções hash obsoletas, como MD5 ou SHA1, ou funções hash não criptográficas
    usadas quando funções hash criptográficas são necessárias?

- Estão em uso métodos de preenchimento criptográfico obsoletos, como PKCS número 1 v1.5?

- As mensagens de erro criptográficas ou as informações do canal lateral podem ser exploradas,
    por exemplo, na forma de ataques oracle de preenchimento?

Consulte ASVS Crypto (V7), Data Protection (V9) e SSL/TLS (V10)

## Como Prevenir

Faça o seguinte, no mínimo, e consulte as referências:

- Classifique os dados processados, armazenados ou transmitidos por um aplicativo.
    Identifique quais dados são confidenciais de acordo com as leis de privacidade, requisitos
    regulamentares ou necessidades de negócios.

- Não armazene dados confidenciais desnecessariamente. Descarte-o o mais rápido possível ou use
    tokenização compatível com PCI DSS ou mesmo truncamento. Os dados não retidos não podem ser roubados.

- Certifique-se de criptografar todos os dados confidenciais armazenados.

- Certifique-se de que algoritmos, protocolos e senhas de padrão forte e atualizados estejam
    em vigor; use o gerenciamento de senhas adequado.

- Criptografe todos os dados em trânsito com protocolos seguros, como TLS com cifras de sigilo
    de encaminhamento (FS), priorização de cifras pelo servidor e parâmetros seguros. Aplique
    a criptografia usando diretivas como HTTP Strict Transport Security (HSTS).

- Desative o armazenamento em cache para respostas que contenham dados confidenciais.

- Aplique os controles de segurança necessários de acordo com a classificação de dados.

- Não use protocolos legados, como FTP e SMTP, para transportar dados confidenciais.

- Armazene senhas usando fortes funções de hash adaptáveis e saltadas com um fator de
    trabalho (fator de atraso), como Argon2, scrypt, bcrypt ou PBKDF2.

- Os vetores de inicialização devem ser escolhidos de acordo com o modo de
    operação. Para muitos modos, isso significa usar um CSPRNG (gerador de
    números pseudo-aleatórios criptograficamente seguro). Para modos que requerem
    um nonce, o vetor de inicialização (IV) não precisa de um CSPRNG. Em todos os
    casos, o IV nunca deve ser usado duas vezes para uma chave fixa.

- Sempre use criptografia autenticada em vez de apenas criptografia.

- As chaves devem ser geradas de forma criptograficamente aleatória e armazenadas
    na memória como um _array_ de _bytes_. Se uma senha for usada, ela deve ser
    convertida em uma chave por meio de uma função de derivação de chave de
    base de senha apropriada.

- Certifique-se de que a aleatoriedade criptográfica seja usada quando apropriado
    e que não tenha sido usada uma semente de uma forma previsível ou com baixa entropia.
    A maioria das APIs modernas não exige que o desenvolvedor propague o CSPRNG para obter segurança.

- Evite funções criptográficas e esquemas de preenchimento obsoletos, como MD5, SHA1, PKCS número 1 v1.5.

- Verifique de forma independente a eficácia das configurações.

## Exemplos de Cenários de Ataque

**Cenário #1**: Um aplicativo criptografa números de cartão de crédito
em um banco de dados usando criptografia automática de banco de dados.
No entanto, esses dados são automaticamente descriptografados quando
recuperados, permitindo que uma falha de injeção de SQL recupere
números de cartão de crédito em texto não criptografado.

**Cenário #2**: Um site não usa ou impõe TLS para todas as páginas
ou oferece suporte a criptografia fraca. Um invasor monitora o tráfego
de rede (por exemplo, em uma rede sem fio insegura), faz o downgrade
de conexões de HTTPS para HTTP, intercepta solicitações e rouba o cookie
de sessão do usuário. O invasor então reproduz esse cookie e sequestra
a sessão (autenticada) do usuário, acessando ou modificando os dados
privados do usuário. Em vez do acima, eles podem alterar todos os dados
transportados, por exemplo, o destinatário de uma transferência de dinheiro.

**Cenário #3**: O banco de dados de senha usa hashes sem saltos ou simples
para armazenar as senhas de todos. Uma falha de _upload_ de arquivo permite
que um invasor recupere o banco de dados de senhas. Todos os hashes sem saltos
podem ser expostos com uma _rainbow table_ de hashes pré-calculados. Hashes
geradas por funções de hash simples ou rápidas podem ser quebrados por GPUs,
mesmo se forem saltadas.

## Referências

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)


## Lista dos CWEs Mapeados

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
