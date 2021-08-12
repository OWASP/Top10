# A3:2017 Exposição de Dados Sensíveis

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 2 | Prevalência: 3 \| Deteção: 2 | Técnico: 3 \| Negócio ? |
| Ao invés de atacar diretamente a criptografia, os atacantes tendem a roubar chaves, executar ataques MitM ou roubar dados em claro do servidor, em trânsito ou no cliente e.g. navegador. Normalmente isto requer ataque manual. Palavras-passe previamente obtidas podem ser atacadas por força bruta usando processadores gráficos (GPUs) | Nos últimos anos este tem sido o ataque com maior impacto. A falha mais comum prende-se com a falta de encriptação de dados sensíveis. Quando a criptografia é aplicada, é comum a geração de chaves fracas e a sua má gestão, utilização de algoritmos criptográficos, protocolos e cifra fracos. Para dados em trânsito, as vulnerabilidades no servidor são geralmente fáceis de detetar, mas díficil para dados em repouso. A complexidade para abusar destas vulnerabilidades é muito variável. | Com frequência esta falha compromete dados que deveriam estar protegidos, tipicamente informação pessoal sensível (PII) como registos médicos, credenciais, dados pessoais, cartões de crédito, os quais devem requerem proteção de acordo com a legislação e regulamentação como EU GDPR ou leis locais. |

## A Aplicação é Vulnerável?

Importa determinar as necessidades de protecção dos dados em trânsito e quando
em repouso. Palavras-passe, números de cartões de crédito, registos de saúde,
informação pessoal e segredos de negócio requerem proteção extra, em particular
quando sujeitos a legislação como Regulamento Geral para a Proteção de Dados
(RGPD) ou PCI Data Security Standard (PCI DSS). Para todos estes dados:

* Existem dados transmitidos em claro? Isto é válido para qualquer protocolo
  e.g. HTTP, SMTP, FTP bem como tráfego Internet e interno entre balanceadores,
  _gateways_, servidores web ou servidores aplicacionais.
* Existem dados sensíveis armazenados em claro, incluindo cópias de segurança?
* Estão a ser usados algoritmos criptográficos antigos ou fracos no código atual
  ou antigo?
* Estão a ser usadas/geradas/reutilizadas chaves criptográficas padrão ou
  fracas, ou não estão a ser geridas convenientemente nem existe rotatividade?
* A encriptação não está a ser forçada e.g. diretivas de segurança ou cabeçalhos
  do agente do utilizador em falta? 
* O agente do utilizador e.g. cliente de email, não está a verificar a validade
  do certificado do servidor?

Ver as secções [Crypto (V6)][0xa31], [Data Protection (V8)][0xa32] e
[SSL/TLS(V10)][0xa33] do ASVS.

## Como Prevenir

Verifique os seguintes passos e consulte as referências:

* Classificar os dados processados, armazenados ou transmitidos por uma
  aplicação. Identificar quais são sensíveis de acordo com a legislação de
  proteção de dados, requisitos regulamentares ou necessidades do negócio.
* Aplicar controlos de acordo com a classificação.
* Não armazene dados sensíveis desnecessariamente. Descarte-os o mais depressa
  possível ou use técnicas de criação de tokens e truncagem.
* Garanta que todos os dados em repouso são encriptados.
* Assegure o uso de algoritmos, protocolos e chaves fortes, standard e atuais,
  bem como a correta gestão das chaves.
* Encripte todos os dados em trânsito usando protocolos seguros como TLS
  combinado com cifras que permitam Perfect Forward Secrecy (PFS), prioritização
  das cifras pelo servidor e parâmetros seguros. Force o uso de encriptação
  recorrendo a diretivas como [HTTP Strict Transport Security (HSTS)][0xa34].
* Desative a cache para respostas que contenham dados sensíveis.
* Armazene palavras-passe usando algoritmos tais como: [Argon2][0xa35],
  [scrypt][0xa36], [bcrypt][0xa37] ou [PBKDF2][0xa38].
* Verificar de forma independente a eficácia das suas configurações.

## Exemplos de Cenários de Ataque

**Cenário #1**: Uma aplicação delega a encriptação dos números de cartão de
crédito para a base de dados, no entanto estes dados são automaticamente
decifrados quando são consultados na base de dados permitindo que um ataque de
injeção de SQL possa obter os dados em claro.

**Cenário #2**: Um site não usa TLS em todas as páginas, ou usa encriptação
fraca. Monitorizando o tráfego da rede (e.g. WiFi aberta), o atacante pode
remover o TLS, interceptar os pedidos, roubar e reutilizar o _cookie_ de sessão
o qual, estando autenticado, lhe permite modificar os dados privados do
utilizador. Em alternativa os dados podem ser modificados em trânsito, e.g.
destinatário de uma transferência bancária.

**Cenário #3**: A base de dados de palavras-passe usa resumos (_hash_) sem
_salt_ para armazenar as palavras-passe de todos os utilizadores. Uma falha no
carregamento de ficheiros permite ao atacante obter toda a base de dados. Todos
estes resumos (_hash_) sem qualquer tipo de _salt_ podem ser expostos usando uma
_rainbow table_ ou resumos pré-calculados. Resumos (_hash_) gerados por funções
simples ou rápidas podem ser quebrados por GPUs, mesmo que tenha sido usado um
_salt_.

## Referências

* [OWASP Proactive Controls: Protect Data][0xa37]
* [OWASP Application Security Verification Standard: V9, V10, V11][0xa38]
* [OWASP Cheat Sheet: Transport Layer Protection][0xa39]
* [OWASP Cheat Sheet: User Privacy Protection][0xa310]
* [OWASP Cheat Sheet: Password Storage][0xa311]
* [OWASP Cheat Sheet: Cryptographic Storage][0xa312]
* [OWASP Security Headers Project][0xa313], [Cheat Sheet: HSTS][0xa314]
* [OWASP Testing Guide: Testing for weak cryptography][0xa315]

### Externas

* [CWE-359: Exposure of Private Information - Privacy Violation][0xa316]
* [CWE-220: Exposure of sens. information through data queries][0xa317]
* [CWE-310: Cryptographic Issues][0xa318]
* [CWE-312: Cleartext Storage of Sensitive Information][0xa319]
* [CWE-319: Cleartext Transmission of Sensitive Information][0xa320]
* [CWE-326: Weak Encryption][0xa321]

[0xa31]: https://owasp.org/www-project-application-security-verification-standard/
[0xa32]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
[0xa33]: https://github.com/p-h-c/phc-winner-argon2
[0xa34]: https://wikipedia.org/wiki/Scrypt
[0xa35]: https://wikipedia.org/wiki/Bcrypt
[0xa36]: https://wikipedia.org/wiki/PBKDF2
[0xa37]: https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere
[0xa38]: https://owasp.org/www-project-application-security-verification-standard/
[0xa39]: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
[0xa310]: https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html
[0xa311]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
[0xa312]: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
[0xa313]: https://owasp.org/www-project-secure-headers/
[0xa314]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
[0xa315]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README
[0xa316]: https://cwe.mitre.org/data/definitions/359.html
[0xa317]: https://cwe.mitre.org/data/definitions/220.html
[0xa318]: https://cwe.mitre.org/data/definitions/310.html
[0xa319]: https://cwe.mitre.org/data/definitions/312.html
[0xa320]: https://cwe.mitre.org/data/definitions/319.html
[0xa321]: https://cwe.mitre.org/data/definitions/326.html
[0xa322]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x14-V6-Cryptography.md
[0xa323]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x16-V8-Data-Protection.md
[0xa324]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x17-V9-Communications.md

