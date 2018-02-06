# A3:2017 Exposição de Dados Sensíveis

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 2 | Prevalência 3 \| Deteção 2 | Técnica 3 \| Negócio |
| Até mesmo atacantes anónimos não atacam e quebram directamente a criptografia. Eles quebram outra coisa qualquer, tais como roubar chaves, efectuar ataques de homem no meio, roubar dados em claro do servidor, quando estiver em transito, ou no cliente do utilizador, p.e. no browser web. É necessário algum tipo de ataque manual. | Ao longo dos últimos anos, este tem sido o ataque com maior impacto. A falha mais comum é simplesmente não encriptar dados sensíveis. Quando a criptografia é aplicada, geração fraca de chaves e má gestão das mesmas, e utilização de algoritmos criptográficos fracos é comum, em particular técnicas fracas de geração de resumos de palavras-passe. Para dados em trânsito, as fraquezas do lado do servidor são fáceis de detectar, mas díficil para dados em repouso. Ambas com uma nível de exploração muito variável. | As falhas comprometem frequentemente todos os dados que deveriam ser protegidos. Tipicamente, esta informação inclui informação pessoal sensível (*Personal Identifiable Information* - PII) tal como registos de saúde, credenciais, dados pessoais, cartões de crédito, que frequentemente requerem protecção definidas por leis ou regulamentos, tais como o RGPD EU (norma europeia - Regulamento Geral para a Protecção de Dados) ou leis locais de privacidade. |

## Está a Aplicação Vulnerável?

A primeira coisa é determinar as necessidades de protecção dos dados em trânsito e em repouso. Por exemplo, palavras-passe, números de cartões de crédito, registos de saúde, e informação pessoal requerem proteção extra, em particular se os dados forem abrangidos pela regulamentação europeia RGPD, regulamentos ou leis locais de privacidade, tais como o PCI *Data Security Standard* (PCI DSS), ou leis de registos de saúde, tais como o *Health Insurance Portability Act* (HIPAA). Para todos estes dados:

* Existem alguns dados do site que sejam transmitidos em claro, interna ou externamente? O tráfego Internet é especialmente perigoso, mas de balanceadores de carda para servidores web e de servidores web para sistemas de backend, pode ser problemático.
* Existe dados sensíveis armazenados em claro, incluindo cópias de segurança?
* Estão a ser usados algoritmos criptográficos antigos ou fracos no código actual ou antigo? (ver **A6:2017 Security Misconfiguration**)
* Estão a ser usadas chaves criptográficas por defeito, estão a ser geradas ou re-utilizadas chaves criptográficas fracas, ou não estão a ser geridas convenientemente nem existe rotatividade?
* Não está a encriptação a ser forçada, p.e. existem algumas directivas de segurança ou cabeçalhos do agente do utilizador (browser web) que não estejam presentes?

Ver as áreas do ASVS [Crypto (V7), Data Protection (V9) and SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS).

## Como Prevenir?

Efectuar o seguinto, ou pelo menos consultar as referências:

* Classificar is dados processados, armazenados ou transmitidos por um sistema. Aplicar controlos de acordo com a classificação.
Rever as leis ou regulamentos de provacidade aplicados a dados sensíveis, e proteger os mesmos de acordo com as orbrigações regulamentares.
* Não armazene dados sensíveis desnecessariamente. Descarte-os os mais depressa possível ou use técnicas de criação de "tokens" e truncagem alinhados com o PCI DSS. Dados que não sejam retidos não podem ser roubados.
* Tenha a certeza que encriptam todos os dados sensíveis em repouso.
* Encripte todod os dados em trânsitp, usando por exemplo TLS. Force isto usando directivas como o HTTP Strict Transport Security ([HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)).
* Assegure o uso de algoritmos fortes e actualizadas para cifras, parâmetros, protocolos e chaves que sejam usados e que mecanismos apropriados de gestão de chaves estão em uso. Considere a utilização de [módulos criptográficos](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search).
* Armazene palavras-passe usando usando algoritmos fortes e adaptativos específicos para proteção de palavras-passe, tais como o [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) e [PBKDF2](https://wikipedia.org/wiki/PBKDF2) com um factor de complexidade suficiente para prevenir contra ataques de quebra por GPU.
* Desabilitar a cache para respostas que contenham dados sensíveis.
* Verificar de forma independente a eficácia das suas configurações.

## Exemplos de Cenários de Ataque

**Cenário #1**:  Uma aplicação encripta os números dos cartões de crédito numa base de dados usando a criptografia da própria base de dados. No entanto, estes dados são automaticamente decifrados quando são consultados na base dados, permitindo que um ataque de injeção de SQL possa obter os números dos cartões de crédito em claro. 

**Cenário #2**: Um site web não força a utilização de TLS para todas as páginas, ou se o faz usa encriptação fraca. Um atacante pode simplesmente monitorizar o tráfego na rede, intercepta o TLS (como numa rede sem fios aberta), e rouba o cookie de sessão do utilizador. O atacante pode reutilizar este cookie e assim raptar a sessão (autenticada) do utilizador, acedendo e modificando os dados privados do utilizador. Em alternativa pode alterar os dados em trânsito, p.e. o destinatário de uma transferência bancária.

**Cenário #3**: A base de dados de palavras-passe usa resumos sem "salt" para armazenar as palavras passes de todos os utilizadores. Uma fraqueza de carregamento de ficheiros permite obter a base de dados de palavras-passe. Todos estes resumos podem ser expostos com uma tabela arco-iris ou usando resumos pré-calculados.

## Referências

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard: V9, V10, V11](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password Storage](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)
* [OWASP Cheat Sheet: Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project), [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Externas

* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html)
