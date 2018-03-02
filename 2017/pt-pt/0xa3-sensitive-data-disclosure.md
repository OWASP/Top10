# A3:2017 Exposição de Dados Sensíveis

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Abuso 2 | Prevalência 3 \| Deteção 2 | Técnica 3 \| Negócio |
| Tipicamente os atacantes não quebram directamente a criptografia. Ao invés, roubam chaves, executam ataques Man-in-the-Middle ou roubam dados sem qualquer tipo de proteção armazenados no servidor, em trânsito ou mesmo do dispositivo do cliente e.g. navegador. Normalmente é necessário um ataque manual. Bases de dados de palavras-chave previamente subtraídas podem ser atacadas por força bruta ou quebradas por GPUs | Ao longo dos últimos anos este tem sido o ataque com maior impacto. A falha mais comum é simplesmente a falta de encriptação de dados sensíveis. Quando a criptografia é aplicada, é comum a geração de chaves fracas e a sua má gestão, é também comum a utilização de algoritmos criptográficos, protocolos e cifra fracos. Para dados em trânsito, as vulnerabilidades no servidor são geralmente fáceis de detectar, mas díficil para dados em repouso. A complexidade de abuso destas vulnerabilidades é muito variável. | As falhas comprometem frequentemente todos os dados que deveriam estar protegidos. Tipicamente, esta informação inclui informação pessoal sensível (_Personal Identifiable Information_ - PII) tal como registos de saúde, credenciais, dados pessoais, cartões de crédito, que frequentemente requerem protecção definidas por leis ou regulamentos, tais como o RGPD EU ou leis locais de privacidade. |

## A Aplicação é Vulnerável?

A primeira coisa a fazer é determinar as necessidades de protecção dos dados em
trânsito e quando em repouso. Por exemplo, palavras-passe, números de cartões de
crédito, registos de saúde, informação pessoal e segredos de negócio requerem
proteção extra, em particular se os dados forem abrangidos por legislação sobre
proteção de dados e.g. norma Europeia RGPD - Regulamento Geral para a Proteção
de Dados, ou regulamentos e.g. proteção de dados financeiros PCI Data Security
Standard (PCI DSS). Para todos estes dados:

* Existem dados transmitidos em claro? Isto é transversal a qualquer protocolo
  e.g. HTTP, SMTP, FTP. O tráfego Internet é especialmente perigoso, mas deve
  verificar também o tráfego interno e.g. entre balanceadores, _gateways_,
  servidores web ou servidores aplicacionais.
* Existem dados sensíveis armazenados em claro, incluindo cópias de segurança?
* Estão a ser usados algoritmos criptográficos antigos ou fracos no código
  actual ou antigo?
* Estão a ser usadas chaves criptográficas padrão, estão a ser geradas ou
  re-utilizadas chaves criptográficas fracas, ou não estão a ser geridas
  convenientemente nem existe rotatividade?
* A encriptação não está a ser forçada e.g. existem algumas directivas de
  segurança ou cabeçalhos do agente do utilizador (navegador web) que não
  estejam presentes?
* O agente do utilizador e.g. aplicação, cliente de email, não está a verificar
  a validade do certificado do servidor?

Ver as áreas do ASVS [Crypto (V7), Data Protection (V9) and SSL/TLS(V10)][1].

## Como Prevenir?

No mínimo realizar os seguintes passos e consultar as referências:

* Classificar os dados processados, armazenados ou transmitidos por uma
  aplicação. Identificar que dados são sensíveis de acordo com a legislação de
  proteção de dados, requisitos regulamentares ou necessidades do negócio.
* Aplicar controlos de acordo com a classificação.
* Não armazene dados sensíveis desnecessariamente. Descarte-os o mais depressa
  possível ou use técnicas de criação de "tokens" e truncagem. Dados que não são
  retidos não podem ser roubados.
* Garanta que todos os dados em repouso são encriptados.
* Assegure o uso de algoritmos, protocolos e chaves fortes, _standard_ e atuais,
  assim como mecanismos apropriados de gestão das chaves em uso.
* Encripte todos os dados em trânsito usando protocolos seguros como TLS
  combinado com cifras que permitam _Perfect Forward Secrecy_ (PFS),
  prioritização das cifras pelo servidor e pârametros seguros. Force o uso de
  encriptação recorrendo a diretivas como [HTTP Strict Transport Security
  (HSTS)][2].
* Desative a _cache_ para respostas que contenham dados sensíveis.
* Armazene palavras-passe usando algoritmos fortes e adaptativos e funções de
  resumo (_hashing_) que suportem `salt` e `work factor` (`delay factor`), tais
  como: [Argon2][3], [scrypt][4], [bcrypt][5] e [PBKDF2][6].
* Verificar de forma independente a eficácia das suas configurações.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação encripta os números dos cartões de crédito numa
base de dados usando a criptografia da própria base de dados. No entanto, estes
dados são automaticamente decifrados quando são consultados na base dados,
permitindo que um ataque de injeção de SQL possa obter os números dos cartões de
crédito em claro. 

**Cenário #2**: Um site web não força a utilização de TLS para todas as páginas,
ou se o faz usa encriptação fraca. Um atacante pode simplesmente monitorizar o
tráfego na rede, remove o TLS (como numa rede sem fios aberta), intercepta os
pedidos e rouba o cookie de sessão do utilizador. O atacante pode reutilizar
este cookie e assim raptar a sessão (autenticada) do utilizador, acedendo e
modificando os dados privados deste. Em alternativa pode alterar os
dados em trânsito, e.g. o destinatário de uma transferência bancária.

**Cenário #3**: A base de dados de palavras-passe usa resumos sem `salt` para
armazenar as palavras passes de todos os utilizadores. Uma falha no carregamento
de ficheiros permite ao atacante obter a base de dados de palavras-passe. Todos
estes resumos podem ser expostos usando um _rainbow table_ ou resumos
pré-calculados. Resumos gerados por funções simples ou rápidas pode ser
quebrados por GPUs, mesmo que tenha sido usado um `salt`.

## Referências

* [OWASP Proactive Controls: Protect Data][7]
* [OWASP Application Security Verification Standard: V9, V10, V11][8]
* [OWASP Cheat Sheet: Transport Layer Protection][9]
* [OWASP Cheat Sheet: User Privacy Protection][10]
* [OWASP Cheat Sheet: Password Storage][11]
* [OWASP Cheat Sheet: Cryptographic Storage][12]
* [OWASP Security Headers Project][13], [Cheat Sheet: HSTS][14]
* [OWASP Testing Guide: Testing for weak cryptography][15]

### Externas

* [CWE-359: Exposure of Private Information - Privacy Violation][16]
* [CWE-220: Exposure of sens. information through data queries][17]
* [CWE-310: Cryptographic Issues][18]
* [CWE-312: Cleartext Storage of Sensitive Information][19]
* [CWE-319: Cleartext Transmission of Sensitive Information][20]
* [CWE-326: Weak Encryption][21]

[1]: https://www.owasp.org/index.php/ASVS
[2]: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet
[3]: https://www.cryptolux.org/index.php/Argon2
[4]: https://wikipedia.org/wiki/Scrypt
[5]: https://wikipedia.org/wiki/Bcrypt
[6]: https://wikipedia.org/wiki/PBKDF2
[7]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data
[8]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project
[9]: https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet
[10]: https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet
[11]: https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
[12]: https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet
[13]: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
[14]: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet
[15]: https://www.owasp.org/index.php/Testing_for_weak_Cryptography
[16]: https://cwe.mitre.org/data/definitions/359.html
[17]: https://cwe.mitre.org/data/definitions/220.html
[18]: https://cwe.mitre.org/data/definitions/310.html
[19]: https://cwe.mitre.org/data/definitions/312.html
[20]: https://cwe.mitre.org/data/definitions/319.html
[21]: https://cwe.mitre.org/data/definitions/326.html

