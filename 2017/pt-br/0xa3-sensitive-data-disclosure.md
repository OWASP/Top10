# A3:2017 Exposição de Dados Sensíveis

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 2 | Prevalência 3 \| Detectabilidade 2 | Técnico 3 \| Negócio |
| Atacantes tipicamente não quebram criptofia diretamente. Em vez disso, eles roubam as chaves, executam ataques man-in-the-middle ou roubam dados em texto puro do servidor, enquanto estão em trânsito ou do cliente do usuário, ex.: navegador. Normalmente é necessário um ataque manual. Bancos de dados de senha recuperados anteriormente poderiam ser atacados por força bruta ou quebrados por GPUs. | Ao longo dos últimos anos, este tem sido o ataque impactante mais comum. A falha mais comum é simplesmente não criptografar dados confidenciais. Quando o criptografia é empregada, geração e gerenciamento de chaves fracas, algoritmos, protocolos e usos de cifra fracos são comuns, particularmente para dados em repouso, técnicas de hashing de senha fracas. Para dados em trânsito os pontos fracos do servidor são fáceis de detectar, mas difíceis para os dados em repouso. A explorabilidade de ambos varia. | A falha freqüentemente compromete todos os dados que deveriam ter sido protegidos. Normalmente, essas informações incluem dados de informações pessoais sensíveis (PII) tais como registros de saúde, dados pessoais, dados pessoais, cartões de crédito, que muitas vezes requer proteção conforme definido por leis ou regulamentos, como as leis de privacidade da UE (GDPR) ou as leis locais de privacidade. |

## A Aplicação Está Vulnerável?

A primeira coisa é determinar as necessidades de proteção de dados em trânsito e em repouso. Por exemplo, as senhas, números de cartão de crédito, registros de saúde, informações pessoais e segredos comerciais requerem proteção extra, especialmente se esses dados estiverem abrangidos pelas leis de privacidade, ex.: Regulamentação Geral de Proteção de Dados da UE (GDPR), ou regulamentos, ex.: proteção financeira de dados, como PCI Data Security Standard (PCI DSS). Para todos esses dados:

* Existe algum dado sendo transmitido em texto puro? Isto diz respeito a qualquer protocolo como http, smtp, ftp. O tráfego de internet externo é especialmente perigoso, mas verifique também todo o tráfego interno, como entre balanceadores de carga, gateways, servidores web ou sistemas back-end.
* Is sensitive data stored in clear text, including backups?
* Algum dados sensível é armazenado em texto puro, incluindo backups?
* Algum algoritmo criptográfico antigo ou fraco é usado por padrão ou em código antigo?
* Estão sendo usadas chaves de criptografia padrão, chaves de criptografia fracas geradas ou reutilizadas, ou o falta algum gerenciamento de chaves ou de troca delas?
* A criptografia não é aplicada, por exemplo, existe alguma diretiva ou cabeçalho de segurança de *user agent* (navegador) faltando?
* O *user agent* (por exemplo, aplicativo, cliente de email) não verifica se o certificado do servidor recebido é válido.

Ver ASVS [Crypto (V7), Data Protection (V9) and SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS).

## Como Prevenir

Faça o seguinte, no mínimo, e consulte as referências:

* Classifique dados processados, armazenados ou transmitidos por uma aplicação. Identifique quais dados são sensíveis de acordo com as leis de privacidade, requisitos regulamentares ou necessidades do negócio.
* Aplique controles de acordo com a classificação.
* Não armazene dados sensíveis desnecessariamente. Descarte-os o mais rápido possível ou use tokenização compatível com PCI DSS ou mesmo truncamento. Dados que não são retidos não podem ser roubados.
* Certifique-se de criptografar todos os dados sensíveis em repouso.
* Certifique-se de que os algoritmos, protocolos, chaves e gerenciamento de chaves apropriados estão atualizados e fortes.
* Criptografe todos os dados em trânsito com protocolos seguros, como TLS, com cifra *perfect forward secrecy* (PFS), prioridade de cifra do servidor e parâmetros seguros. Aplique criptografia usando diretivas como HTTP Strict Transport Security (HSTS).
* Desativar o cache para respostas que contenham dados confidenciais.
* Armazene senhas usando funções de hashing com salt fortes e adaptativas com um fator de trabalho (fator de atraso), como [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) ou [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Verifique independentemente a eficácia das suas configurações.

## Examplo de Cenários de Ataque

**Cenário #1**: Uma aplicação criptografa números de cartão de crédito em um banco de dados usando criptografia automática do próprio banco. No entanto, esses dados são descriptografados automaticamente quando recuperados, permitindo que uma falha de injeção SQL obtenha números de cartão de crédito em texto aberto.

**Cenário #2**: Um site não usa ou aplica TLS para todas as páginas ou suporta criptografia fraca. Um atacante monitora o tráfego de rede, tira o TLS (por exemplo, em uma rede sem fio aberta), intercepta solicitações e rouba o cookie de sessão do usuário. O atacante então reproduz este cookie e seqüestra a sessão (autenticada) do usuário, acessando ou modificando os dados privados do usuário. Em vez do anterior, podem alterar todos os dados transportados, por exemplo, o destinatário de uma transferência de dinheiro.

**Cenário #3**: O banco de dados de senhas usa hashes sem salt ou hashes simples para armazenar senhas de todos. Uma falha de upload de arquivo permite que um invasor obtenha o banco de dados de senha. Todos os hashes sem salt podem ser expostos com uma *rainbow table* de hashes pré-calculados. Hashes gerados por funções de hash simples ou rápidas podem ser quebrados por GPUs, mesmo que possuam salts.

## Referências

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard: V7, 9, 10](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password Storage](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Cheat Sheet: Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Externas

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
