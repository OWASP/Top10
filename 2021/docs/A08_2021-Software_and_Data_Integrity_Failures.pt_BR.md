# A08:2021 – Falhas de Software e Integridade de Dados    ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 6.94                 | 7.94                | 75.04%       | 45.35%       | 47,972            | 1,152      |

## Visão Geral

Uma nova categoria para 2021 se concentra em fazer suposições relacionadas a atualizações de software, 
dados críticos e pipelines de CI/CD sem verificar a integridade. 
Um dos impactos mais importantes ponderados pelos dados do 
Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS). 
As Notáveis Enumerações de Fraquezas Comuns (CWEs) incluem:
*CWE-829: Inclusão de funcionalidade de esfera de controle não confiável*,
*CWE-494: Download de código sem verificação de integridade*, e
*CWE-502: Desserialização de dados não confiáveis*.

## Descrição

Falhas na integridade de software e dados estão relacionadas a código e infraestrutura que não protegem contra violações de integridade. Um exemplo disso é quando um aplicativo depende de plugins, bibliotecas ou módulos de fontes, repositórios e redes de entrega de conteúdo (CDNs) não confiáveis. 
Um pipeline de CI/CD inseguro pode introduzir a possibilidade de acesso não autorizado, código malicioso ou comprometimento do sistema. Por último, muitos aplicativos agora incluem funcionalidade de atualização automática, onde as atualizações são baixadas sem verificação de integridade suficiente e aplicadas ao aplicativo previamente confiável. 
Atacantes podem potencialmente fazer upload de suas próprias atualizações para serem distribuídas e executadas em todas as instalações. Outro exemplo é quando objetos ou dados são codificados ou serializados em uma estrutura que um atacante pode ver e modificar, o que torna a deserialização insegura.

## Como Prevenir

- Use assinaturas digitais ou mecanismos similares para verificar se o software ou os dados são provenientes da fonte esperada e não foram alterados.

- Certifique-se de que as bibliotecas e dependências, como npm ou Maven, estão consumindo repositórios confiáveis. Se você tiver um perfil de risco mais alto, considere hospedar um repositório interno conhecido como bom que foi examinado.

- Certifique-se de que uma ferramenta de segurança da cadeia de suprimentos de software, como OWASP Dependency Check ou OWASP CycloneDX, é usada para verificar se os componentes não contêm vulnerabilidades conhecidas.

- Certifique-se de que haja um processo de revisão para mudanças de código e configuração para minimizar a chance de que código ou configuração maliciosos possam ser introduzidos no seu pipeline de software.

- Certifique-se de que seu pipeline de CI/CD tenha uma segregação adequada, configuração e controle de acesso para garantir a integridade do código que flui através dos processos de construção e implantação.

- Certifique-se de que dados serializados não assinados ou não criptografados não sejam enviados a clientes não confiáveis sem algum tipo de verificação de integridade ou assinatura digital para detectar adulteração ou retransmissão dos dados serializados.

## Exemplos de Cenários de Ataque

**Cenário nº 1 Atualização sem assinatura:** Muitos roteadores domésticos, set-top boxes, firmware de dispositivos e outros não verificam as atualizações por meio de firmware assinado. Firmware não assinado é um alvo crescente para ataques e espera-se que piore ainda mais. Isso é uma grande preocupação, pois muitas vezes não há mecanismo de remediação a não ser corrigir em uma versão futura e esperar que as versões anteriores sejam descontinuadas.

**Cenário #2 Atualização maliciosa do SolarWinds**: Estados-nações são conhecidos por atacar mecanismos de atualização, com um recente ataque notável sendo o ataque SolarWinds Orion. A empresa que desenvolve o software tinha processos de integridade de construção e atualização seguros. Ainda assim, eles foram subvertidos, e por vários meses, a empresa distribuiu uma atualização maliciosa altamente direcionada para mais de 18.000 organizações, das quais cerca de 100 foram afetadas. Esse é um dos mais amplos e significativos violações desse tipo na história.

**Cenário #3 Desserialização Insegura:** Uma aplicação React chama um conjunto de microsserviços Spring Boot. Sendo programadores funcionais, eles tentaram garantir que seu código seja imutável. A solução que encontraram é serializar o estado do usuário e passá-lo de volta e para frente em cada solicitação. Um atacante percebe a assinatura do objeto Java "rO0" (em base64) e usa a ferramenta Java Serial Killer para obter execução remota de código no servidor de aplicação.

## Referências

- \[OWASP Cheat Sheet: Software Supply Chain Security\](Em breve)

- \[OWASP Cheat Sheet: Secure build and deployment\](Em breve)

- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) 
 
- [OWASP Cheat Sheet: Deserialization](<https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

- [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

- [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

- [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)

- [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## Lista dos CWEs Mapeados

[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
