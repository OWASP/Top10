# A3:2017 Exposição de Dados Sensíveis

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança           | Impactos               |
| -- | -- | -- |
| Access Lvl \| Exploitability 2 | Prevalence 3 \| Detectability 2 | Technical 3 \| Business |
| Atacantes tipicamente não quebram criptofia diretamente. Em vez disso, eles roubam as chaves, executam ataques man-in-the-middle ou roubam dados em texto puro do servidor, enquanto estão em trânsito ou do cliente do usuário, ex.: navegador. Normalmente é necessário um ataque manual. Bancos de dados de senha recuperados anteriormente poderiam ser atacados por força bruta ou quebrados por GPUs. | Ao longo dos últimos anos, este tem sido o ataque impactante mais comum. A falha mais comum é simplesmente não criptografar dados confidenciais. Quando o criptografia é empregada, geração e gerenciamento de chaves fracas, algoritmos, protocolos e usos de cifra fracos são comuns, particularmente para dados em repouso, técnicas de hashing de senha fracas. Para dados em trânsito os pontos fracos do servidor são fáceis de detectar, mas difíceis para os dados em repouso. A explorabilidade de ambos varia. | A falha freqüentemente compromete todos os dados que deveriam ter sido protegidos. Normalmente, essas informações incluem dados de informações pessoais sensíveis (PII) tais como registros de saúde, dados pessoais, dados pessoais, cartões de crédito, que muitas vezes requer proteção conforme definido por leis ou regulamentos, como as leis de privacidade da UE (GDPR) ou as leis locais de privacidade. |

## A Aplicação Está Vulnerável?

A primeira coisa é determinar as necessidades de proteção de dados em trânsito e em repouso. Por exemplo, as senhas, números de cartão de crédito, registros de saúde, informações pessoais e segredos comerciais requerem proteção extra, especialmente se esses dados estiverem abrangidos pelas leis de privacidade, ex.: Regulamentação Geral de Proteção de Dados da UE (GDPR), ou regulamentos, ex.: proteção financeira de dados, como PCI Data Security Standard (PCI DSS). Para todos esses dados:

* Existe algum dado sendo transmitido em texto puro? Isto diz respeito a qualquer protocolo como http, smtp, ftp. O tráfego de internet externo é especialmente perigoso, mas verifique também todo o tráfego interno, como entre balanceadores de carga, gateways, servidores web ou sistemas back-end.
* Is sensitive data stored in clear text, including backups?
* Algum dados sensível é armazenado em texto puro, incluindo backups?
* Algum algoritmo criptográfico antigo ou fraco é usado por padrão ou em código antigo?

* Are default crypto keys in use, weak crypto keys generated or re-used, or is proper key management or rotation missing?
* Estão sendo usadas chaves de criptografia padrão, chaves de criptografia fracas geradas ou reutilizadas, ou o falta algum gerenciamento de chaves ou de troca delas?
* Is encryption not enforced, e.g. are any user agent (browser) security directives or headers missing?
* A criptografia não é aplicada, por exemplo, existe alguma diretiva ou cabeçalho de segurança de 'user agent' (navegador) faltando?
* O 'user agent' (por exemplo, aplicativo, cliente de email) não verifica se o certificado do servidor recebido é válido.


Ver ASVS [Crypto (V7), Data Protection (V9) and SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS).

## Como Prevenir

Do the following, at a minimum and consult the references:

* Classify data processed, stored or transmitted by an application. Identify which data is sensitive according privacy laws, regulatory requirements, or business needs.
* Apply controls as per the classification.
* Don't store sensitive data unnecessarily. Discard it as soon as possible or use PCI DSS compliant tokenization or even truncation. Data that is not retained cannot be stolen.
* Make sure to encrypt all sensitive data at rest.
* Ensure up-to-date and strong standard algorithms, protocols, keys and proper key management is in place.
* Encrypt all data in transit with secure protocols such as TLS with perfect forward secrecy (PFS) ciphers, cipher prioritization by the server, and secure parameters. Enforce encryption using directives like HTTP Strict Transport Security (HSTS).
* Disable caching for response that contain sensitive data.
* Store passwords using strong adaptive and salted hashing functions with a work factor (delay factor), such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) or [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Verify independently the effectiveness of your settings.

## Example Attack Scenarios

**Scenario #1**: An application encrypts credit card numbers in a database using automatic database encryption. However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text. 

**Scenario #2**: A site doesn't use or enforce TLS for all pages or supports weak encryption. An attacker monitors network traffic, strips the TLS (e.g. at an open wireless network), intercepts requests, and steals the user's session cookie. The attacker then replays this cookie and hijacks the user's (authenticated) session, accessing or modifying the user's private data. Instead of the above they could alter all transported data, e.g. the recipient of a money transfer.

**Scenario #3**: The password database uses unsalted or simple hashes to store everyone's passwords. A file upload flaw allows an attacker to retrieve the password database. All the unsalted hashes can be exposed with a rainbow table of pre-calculated hashes. Hashes generated by simple or fast hash functions may be cracked by GPUs, even if they were salted.

## References

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard: V7, 9, 10](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password Storage](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Cheat Sheet: Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### External

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
