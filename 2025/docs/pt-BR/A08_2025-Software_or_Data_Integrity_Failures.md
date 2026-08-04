# A08:2025 Falhas de Integridade de Software ou Dados ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Contexto

Falhas de Integridade de Software ou Dados continua em #8, com uma leve alteração esclarecedora no nome (de "Software _and_ Data..." para "Software _or_ Data..."). Esta categoria foca na falha em manter limites de confiança e verificar a integridade de artefatos de software, código e dados em um nível inferior às Falhas na Cadeia de Suprimentos de Software. Esta categoria foca em assumir pressupostos relacionados a atualizações de software e dados críticos sem verificar sua integridade. Enumerações de Fraquezas Comuns (CWEs) notáveis incluem _CWE-829: Inclusion of Functionality from Untrusted Control Sphere_, _CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes_ e _CWE-502: Deserialization of Untrusted Data_.

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
   <td>14
   </td>
   <td>8,98%
   </td>
   <td>2,75%
   </td>
   <td>78,52%
   </td>
   <td>45,49%
   </td>
   <td>7,11
   </td>
   <td>4,79
   </td>
   <td>501.327
   </td>
   <td>3.331
   </td>
  </tr>
</table>

## Descrição

Falhas de integridade de software e dados referem-se a códigos e infraestruturas que não protegem contra códigos ou dados inválidos ou não confiáveis que são tratados como íntegros e válidos. Um exemplo disso ocorre quando uma aplicação depende de plugins, bibliotecas ou módulos de fontes, repositórios e redes de entrega de conteúdo (CDNs) não confiáveis. Um _pipeline_ de CI/CD inseguro, que não consome nem fornece verificações de integridade de software, pode introduzir o potencial de acesso não autorizado, código malicioso ou comprometimento do sistema. Outro exemplo é um CI/CD que extrai código ou artefatos de locais não confiáveis e/ou não os verifica antes do uso (através de assinatura digital ou mecanismo similar). Por fim, muitas aplicações agora incluem funcionalidade de atualização automática, onde atualizações são baixadas sem verificação de integridade suficiente e aplicadas à aplicação previamente confiável. Atacantes poderiam potencialmente fazer o _upload_ de suas próprias atualizações para serem distribuídas e executadas em todas as instalações. Outro exemplo ocorre quando objetos ou dados são codificados ou serializados em uma estrutura que um atacante pode visualizar e modificar, tornando a aplicação vulnerável à desserialização insegura.

## Como prevenir

- Utilize assinaturas digitais ou mecanismos similares para verificar se o software ou dado provém da fonte esperada e não foi alterado.
- Garanta que bibliotecas e dependências, como npm ou Maven, estejam consumindo apenas repositórios confiáveis. Se você tiver um perfil de risco mais elevado, considere hospedar um repositório interno de itens conhecidos e aprovados (_vetted_).
- Garanta que haja um processo de revisão para alterações de código e configuração para minimizar a chance de que códigos ou configurações maliciosas sejam introduzidos em seu _pipeline_ de software.
- Garanta que seu _pipeline_ de CI/CD possua segregação, configuração e controle de acesso adequados para assegurar a integridade do código que flui pelos processos de compilação (_build_) e implantação (_deploy_).
- Garanta que dados serializados não assinados ou não criptografados não sejam recebidos de clientes não confiáveis e usados posteriormente sem algum tipo de verificação de integridade ou assinatura digital para detectar adulteração ou repetição (_replay_) dos dados serializados.

## Exemplos de cenários de ataque

**Cenário #1 Inclusão de Funcionalidade Web de Fonte Não Confiável:** Uma empresa utiliza um provedor de serviços externo para fornecer funcionalidade de suporte. Por conveniência, possui um mapeamento de DNS de `minhaEmpresa.ProvedorSuporte.com` para `suporte.minhaEmpresa.com`. Isso significa que todos os _cookies_, incluindo _cookies_ de autenticação configurados no domínio `minhaEmpresa.com`, serão enviados para o provedor de suporte. Qualquer pessoa com acesso à infraestrutura do provedor de suporte pode roubar os _cookies_ de todos os seus usuários que visitaram `suporte.minhaEmpresa.com` e realizar um ataque de sequestro de sessão (_session hijacking_).

**Cenário #2 Atualização sem assinatura:** Muitos roteadores domésticos, decodificadores de TV (_set-top boxes_), firmwares de dispositivos e outros não verificam atualizações via firmware assinado. Firmware não assinado é um alvo crescente para atacantes e a expectativa é que a situação piore. Esta é uma preocupação importante, pois muitas vezes não há mecanismo de remediação além de corrigir em uma versão futura e esperar que as versões anteriores deixem de ser usadas.

**Cenário #3 Uso de Pacote de Fonte Não Confiável:** Um desenvolvedor tem dificuldade em encontrar a versão atualizada de um pacote que está procurando, então ele o baixa não do gerenciador de pacotes regular e confiável, mas de um site qualquer na internet. O pacote não está assinado e, portanto, não há oportunidade de garantir a integridade. O pacote inclui código malicioso.

**Cenário #4 Desserialização Insegura:** Uma aplicação React chama um conjunto de microserviços Spring Boot. Sendo programadores funcionais, eles tentaram garantir que seu código fosse imutável. A solução encontrada foi serializar o estado do usuário e passá-lo de um lado para o outro em cada requisição. Um atacante percebe a assinatura de objeto Java "rO0" (em base64) e utiliza o [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) para obter execução remota de código (RCE) no servidor da aplicação.

## Referências

- [OWASP Cheat Sheet: Software Supply Chain Security](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Deserialization](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
- [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
- [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
- [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
- [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)
- [Insecure Deserialization by Tenendo](https://tenendo.com/insecure-deserialization/)

## Lista de CWEs Mapeadas

- [CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [CWE-427 Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)
- [CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-506 Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
- [CWE-509 Replicating Malicious Code (Virus or Worm)](https://cwe.mitre.org/data/definitions/509.html)
- [CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)
- [CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)
- [CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)
- [CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CWE-926 Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html)
