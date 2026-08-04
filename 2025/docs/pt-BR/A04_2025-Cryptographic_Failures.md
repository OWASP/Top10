# A04:2025 – Falhas Criptográficas (Cryptographic Failures) ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Contexto

Descendo duas posições para o 4º lugar, esta fraqueza foca em falhas relacionadas à falta de criptografia, criptografia insuficientemente forte, vazamento de chaves criptográficas e erros correlatos. Três das CWEs (_Common Weakness Enumerations_) mais comuns neste risco envolveram o uso de geradores de números pseudoaleatórios fracos: _CWE-327 Use of a Broken or Risky Cryptographic Algorithm_, _CWE-331: Insufficient Entropy_, _CWE-1241: Use of Predictable Algorithm in Random Number Generator_ e _CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)_.

## Tabela de Pontuação

<table>
  <tr>
   <td>CWEs Mapeadas 
   </td>
   <td>Taxa Máx. de Incidência
   </td>
   <td>Taxa Média de Incidência
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Média
   </td>
   <td>Exploit Médio Ponderado
   </td>
   <td>Impacto Médio Ponderado
   </td>
   <td>Total de Ocorrências
   </td>
   <td>Total de CVEs
   </td>
  </tr>
  <tr>
   <td>32
   </td>
   <td>13.77%
   </td>
   <td>3.80%
   </td>
   <td>100.00%
   </td>
   <td>47.74%
   </td>
   <td>7.23
   </td>
   <td>3.90
   </td>
   <td>1,665,348
   </td>
   <td>2,185
   </td>
  </tr>
</table>

## Descrição

De modo geral, todos os dados em trânsito devem ser criptografados na [camada de transporte](https://en.wikipedia.org/wiki/Transport_layer) ([camada OSI](https://en.wikipedia.org/wiki/OSI_model) 4). Obstáculos anteriores, como desempenho de CPU e gerenciamento de chaves privadas/certificados, são agora lidados por CPUs que possuem instruções projetadas para acelerar a criptografia (ex: [suporte a AES](https://en.wikipedia.org/wiki/AES_instruction_set)) e pelo gerenciamento de chaves e certificados simplificado por serviços como o [LetsEncrypt.org](https://LetsEncrypt.org), com grandes provedores de nuvem oferecendo serviços de gerenciamento ainda mais integrados para suas plataformas específicas.

Além de proteger a camada de transporte, é importante determinar quais dados precisam de criptografia em repouso (_at rest_), bem como quais dados precisam de criptografia extra em trânsito (na [camada de aplicação](https://en.wikipedia.org/wiki/Application_layer), camada OSI 7). Por exemplo, senhas, números de cartão de crédito, registros de saúde, informações pessoais e segredos de negócio exigem proteção extra, especialmente se esses dados estiverem sujeitos a leis de privacidade, como a Lei Geral de Proteção de Dados (LGPD) no Brasil ou o GDPR na UE, ou regulamentações como o PCI Data Security Standard (PCI DSS). Para todos esses dados:

- Algum algoritmo ou protocolo criptográfico antigo ou fraco é usado por padrão ou em código legado?
- Chaves criptográficas padrão estão em uso, chaves fracas são geradas, chaves são reutilizadas ou falta um gerenciamento e rotação de chaves adequados?
- Chaves criptográficas foram enviadas (_checked into_) para repositórios de código-fonte?
- A criptografia não é imposta? Por exemplo, faltam diretivas de segurança ou **headers** HTTP (no navegador)?
- O certificado do servidor recebido e a cadeia de confiança são validados corretamente?
- Vetores de inicialização (IVs) são ignorados, reutilizados ou não são gerados de forma suficientemente segura para o modo de operação criptográfico? Um modo de operação inseguro, como ECB, está em uso? A criptografia simples é usada quando a criptografia autenticada seria mais apropriada?
- Senhas estão sendo usadas como chaves criptográficas na ausência de uma função de derivação de chave baseada em senha (_password-based key derivation function_)?
- É utilizada aleatoriedade que não foi projetada para atender a requisitos criptográficos? Mesmo que a função correta seja escolhida, ela precisa de uma semente (_seed_) definida pelo desenvolvedor? E se não, o desenvolvedor sobrescreveu a funcionalidade de semente forte nativa por uma semente que carece de entropia/imprevisibilidade suficiente?
- Funções de **hash** obsoletas, como MD5 ou SHA1, estão em uso, ou funções de **hash** não criptográficas são usadas quando funções criptográficas são necessárias?
- Mensagens de erro criptográficas ou informações de canal lateral (_side channel_) são exploráveis, por exemplo, na forma de ataques de _padding oracle_?
- O algoritmo criptográfico pode sofrer _downgrade_ ou ser ignorado (_bypass_)?

Veja as referências ASVS: Criptografia (V11), Comunicação Segura (V12) e Proteção de Dados (V14).

## Como Prevenir

Faça o seguinte, no mínimo, e consulte as referências:

- Classifique e rotule os dados processados, armazenados ou transmitidos por uma aplicação. Identifique quais dados são sensíveis de acordo com as leis de privacidade, requisitos regulatórios ou necessidades de negócio.
- Armazene suas chaves mais sensíveis em um HSM (_Hardware Security Module_) físico ou baseado em nuvem.
- Use implementações bem confiáveis de algoritmos criptográficos sempre que possível.
- Não armazene dados sensíveis desnecessariamente. Descarte-os o mais rápido possível ou use **tokenização** compatível com PCI DSS ou mesmo truncamento. Dados que não são retidos não podem ser roubados.
- Certifique-se de criptografar todos os dados sensíveis em repouso.
- Garanta que algoritmos, protocolos e chaves padrão, fortes e atualizados estejam em vigor; utilize um gerenciamento de chaves adequado.
- Criptografe todos os dados em trânsito apenas com protocolos >= TLS 1.2, com cifras de sigilo direto (_forward secrecy_ - FS), descontinue o suporte a cifras CBC (_cipher block chaining_) e suporte algoritmos de troca de chaves quânticas. Para HTTPS, imponha a criptografia usando HSTS (_HTTP Strict Transport Security_). Verifique tudo com uma ferramenta.
- Desative o cache para respostas que contenham dados sensíveis. Isso inclui cache em sua CDN, servidor web e qualquer cache de aplicação (ex: Redis).
- Aplique os controles de segurança exigidos conforme a classificação de dados.
- Não utilize protocolos não criptografados, como FTP e STARTTLS. Evite usar SMTP para transmitir dados confidenciais.
- Armazene senhas usando funções de **hash** adaptativas e salgadas (_salted_) com um fator de trabalho (fator de atraso), como Argon2, yescrypt, scrypt ou PBKDF2-HMAC-SHA-512. Para sistemas legados que usam bcrypt, obtenha mais orientações no [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Os vetores de inicialização (IVs) devem ser escolhidos de forma apropriada para o modo de operação. Isso pode significar o uso de um CSPRNG (_cryptographically secure pseudo-random number generator_). Para modos que exigem um _nonce_, o IV não precisa de um CSPRNG. Em todos os casos, o IV nunca deve ser usado duas vezes para uma chave fixa.
- Sempre use criptografia autenticada em vez de apenas criptografia.
- As chaves devem ser geradas de forma criptograficamente aleatória e armazenadas na memória como arrays de bytes. Se uma senha for usada, ela deve ser convertida em uma chave por meio de uma função de derivação de chave baseada em senha apropriada.
- Garanta que a aleatoriedade criptográfica seja usada onde apropriado e que não tenha sido semeada de forma previsível ou com baixa entropia. A maioria das **APIs** modernas não exige que o desenvolvedor semeie o CSPRNG para ser seguro.
- Evite funções criptográficas, métodos de construção de blocos e esquemas de preenchimento (_padding_) obsoletos, como MD5, SHA1, modo CBC e PKCS#1 v1.5.
- Garanta que as definições e configurações atendam aos requisitos de segurança, fazendo com que sejam revisadas por especialistas em segurança, ferramentas projetadas para esse fim, ou ambos.
- Você precisa se preparar agora para a criptografia pós-quântica (PQC), veja a referência (ENISA), para que sistemas de alto risco estejam seguros o mais tardar até o final de 2030.

## Exemplos de Cenários de Ataque

**Cenário #1**: Um site não usa ou não impõe TLS para todas as páginas ou suporta criptografia fraca. Um **atacante** monitora o tráfego de rede (ex: em uma rede sem fio insegura), rebaixa (_downgrade_) as conexões de HTTPS para HTTP, intercepta requisições e rouba o **cookie** de sessão do usuário. O **atacante**, então, replica esse **cookie** e sequestra a sessão (autenticada) do usuário, acessando ou modificando seus dados privados. Em vez disso, ele poderia alterar todos os dados transportados, como o destinatário de uma transferência de dinheiro.

**Cenário #2**: O banco de dados de senhas usa **hashes** sem sal (_unsalted_) ou simples para armazenar as senhas de todos. Uma falha de upload de arquivos permite que um **atacante** recupere o banco de dados de senhas. Todos os **hashes** sem sal podem ser expostos com uma _rainbow table_ de **hashes** pré-calculados. **Hashes** gerados por funções simples ou rápidas podem ser quebrados por GPUs, mesmo que tenham sido salgados.

## Referências

- [OWASP Proactive Controls: C2: Use Cryptography to Protect Data](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
- [OWASP Application Security Verification Standard (ASVS):](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
- [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
- [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
- [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

## Lista de CWEs Mapeadas

- [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)
- [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)
- [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)
- [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)
- [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)
- [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)
- [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)
- [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
- [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)
- [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)
- [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)
- [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)
- [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)
- [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)
- [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)
- [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)
- [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)
- [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)
- [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
- [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)
- [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)
- [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)
- [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
