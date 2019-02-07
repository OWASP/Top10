# A3:2017 Exposição de Dados Sensíveis

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Abuso 2 | Prevalência 3 \| Deteção 2 | Técnica 3 \| Negócio |
| Ao invés de atacar diretamente a criptografia, os atacantes tendem a roubar chaves, executar ataques MitM ou roubar dados em claro do servidor, em trânsito ou no cliente e.g. navegador. Normalmente isto requer ataque manual. Palavras-passe previamente obtidas podem ser atacadas por força bruta usando processadores gráficos (GPUs) | Nos últimos anos este tem sido o ataque com maior impacto. A falha mais comum prende-se com a falta de encriptação de dados sensíveis. Quando a criptografia é aplicada, é comum a geração de chaves fracas e a sua má gestão, utilização de algoritmos criptográficos, protocolos e cifra fracos. Para dados em trânsito, as vulnerabilidades no servidor são geralmente fáceis de detetar, mas díficil para dados em repouso. A complexidade para abusar destas vulnerabilidades é muito variável. | Com frequência esta falha compromete dados que deveriam estar protegidos, tipicamente informação pessoal sensível (PII) como registos médicos, credenciais, dados pessoais, cartões de crédito, protegida ao abrigo de legislação como EU GDPR ou leis locais. |

## A Aplicação é Vulnerável?

Importa determinar as necessidades de protecção dos dados em trânsito e quando
em repouso. Palavras-passe, números de cartões de crédito, registos de saúde,
informação pessoal e segredos de negócio requerem proteção extra, em particular
quando sujeitos a legislação como Regulamento Geral para a Proteção de Dados
(RGPD) ou PCI Data Security Standard (PCI DSS). Para todos estes dados:

* Existem dados transmitidos em claro? Isto é válido para qualquer protocolo
  e.g. HTTP, SMTP, FTP bem como tráfego Internet e interno entre balanceadores,
  gateways, servidores web ou servidores aplicacionais.
* Existem dados sensíveis armazenados em claro, incluindo cópias de segurança?
* Estão a ser usados algoritmos criptográficos antigos ou fracos no código
  actual ou antigo?
* Estão a ser usadas/geradas/re-utilizadas chaves criptográficas padrão ou
  fracas, ou não estão a ser geridas convenientemente nem existe rotatividade?
* A encriptação não está a ser forçada e.g. directivas de segurança ou
  cabeçalhos do agente do utilizador em falta? 
* O agente do utilizador e.g. cliente de email, não está a verificar a validade
  do certificado do servidor?

Ver as secções [Crypto (V7)][22], [Data Protection (V9)][23] e
[SSL/TLS(V10)][24] do ASVS.

## Como Prevenir

Verifique os seguintes passos e consulte as referências:

* Classificar os dados processados, armazenados ou transmitidos por uma
  aplicação. Identificar quais são sensíveis de acordo com a legislação de
  proteção de dados, requisitos regulamentares ou necessidades do negócio.
* Aplicar controlos de acordo com a classificação.
* Não armazene dados sensíveis desnecessariamente. Descarte-os o mais depressa
  possível ou use técnicas de criação de "tokens" e truncagem.
* Garanta que todos os dados em repouso são encriptados.
* Assegure o uso de algoritmos, protocolos e chaves fortes, standard e atuais,
  bem como a correta gestão das chaves.
* Encripte todos os dados em trânsito usando protocolos seguros como TLS
  combinado com cifras que permitam Perfect Forward Secrecy (PFS), prioritização
  das cifras pelo servidor e pârametros seguros. Force o uso de encriptação
  recorrendo a diretivas como [HTTP Strict Transport Security (HSTS)][14].
* Desative a cache para respostas que contenham dados sensíveis.
* Armazene palavras-passe usando algoritmos tais como: [Argon2][3], [scrypt][4],
  [bcrypt][5] ou [PBKDF2][6].
* Verificar de forma independente a eficácia das suas configurações.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação delega a encriptação dos números de cartão de
crédito para a base de dados, no entanto estes dados são automaticamente
decifrados quando são consultados na base de dados permitindo que um ataque de
injeção de SQL possa obter os dados em claro.

**Cenário #2**: Um site não usa TLS em todas as páginas, ou usa encriptação
fraca. Monitorizando o tráfego da rede (e.g. WiFi aberta), o atacante pode
remover o TLS, interceptar os pedidos e roubar e reutilizar o cookie de sessão o
qual, estando autenticado, lhe permite modificar os dados privados do
utilizador. Em alternativa os dados podem ser modificados em trânsito, e.g.
destinatário de uma transferência bancária.

**Cenário #3**: A base de dados de palavras-passe usa resumos sem salt para
armazenar as palavras passes de todos os utilizadores. Uma falha no carregamento
de ficheiros permite ao atacante obter a base de dados de palavras-passe. Todos
estes resumos podem ser expostos usando um rainbow table ou resumos
pré-calculados. Resumos gerados por funções simples ou rápidas pode ser
quebrados por GPUs, mesmo que tenha sido usado um salt.

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
[22]: https://www.owasp.org/index.php/ASVS_V7_Cryptography
[23]: https://www.owasp.org/index.php/ASVS_V9_Data_Protection
[24]: https://www.owasp.org/index.php/ASVS_V10_Communications
