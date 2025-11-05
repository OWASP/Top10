# A04:2021 – Design Inseguro   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} 

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:-------------------------:|:------------------------:|:--------------------------:|:-----------------------:|:----------------:|:---------------:|:--------------------:|:-------------:|
| 40            | 24.19%                    | 3.00%                    | 6.46                       | 6.78                    | 77.25%           | 42.51%          | 262,407              | 2,691         |

## Visão Geral

Uma nova categoria para 2021 concentra-se nos riscos relacionados a falhas de design e arquitetura,
com uma chamada para mais uso de modelagem de ameaças (_threat modeling_), padrões de design seguros
e arquiteturas de referência. Como uma comunidade, precisamos ir além de "_shift-left_" no espaço
de codificação para atividades antes da codificação que são críticas para os princípios
de _Secure by Design_. Notáveis Common Weakness Enumerations (CWEs) incluídas são
*CWE-209: Geração de Mensagem de Erro Contendo Informações Confidenciais*,
*CWE-256: Armazenamento Desprotegido de Credenciais*, *CWE-501: Violação de Limites de Confiança*
e *CWE-522: Credenciais Insuficientemente Protegidas*.

## Descrição

O design inseguro é uma categoria ampla que representa diferentes pontos fracos, expressos como
"design de controle ausente ou ineficaz". O design inseguro não é a fonte de todas as outras 10
categorias principais de risco de segurança. Há uma diferença entre design inseguro e implementação insegura.
Nós diferenciamos entre falhas de design e defeitos de implementação por um motivo, eles têm diferentes
causas raízes e remediação. Um design seguro ainda pode ter defeitos de implementação que levam a
vulnerabilidades que podem ser exploradas. Um design inseguro não pode ser corrigido por uma implementação
perfeita, pois, por definição, os controles de segurança necessários nunca foram criados para a defesa
contra ataques específicos. Um dos fatores que contribuem para um design inseguro é a falta de perfis
de risco de negócios inerentes ao software ou sistema que está sendo desenvolvido e, portanto,
a falha em determinar o nível de design de segurança necessário.

### Gerenciamento de Requisitos e Recursos

Colete e negocie os requisitos de negócios para uma aplicação com a empresa, incluindo os requisitos de proteção relativos à confidencialidade, integridade, disponibilidade e autenticidade de todos os ativos de dados e a lógica de negócios esperada. Leve em consideração a exposição da sua aplicação e se você precisa de segregação de tenants (além do controle de acesso). Compile os requisitos técnicos, incluindo requisitos de segurança funcionais e não funcionais. Planeje e negocie o orçamento cobrindo todo o projeto, construção, teste e operação, incluindo atividades de segurança.

### Design Seguro

O design seguro é uma cultura e metodologia que avalia constantemente as ameaças e garante que o
código seja desenvolvido e testado de forma robusta para evitar métodos de ataque conhecidos.
A Modelagem de Ameaças deve ser integrada às sessões de refinamento (ou atividades semelhantes);
procure por mudanças nos fluxos de dados e controle de acesso ou outros controles
de segurança. No desenvolvimento da história do usuário, determine o fluxo correto e os
estados de falha, certifique-se de que sejam bem compreendidos e aceitos pelas partes responsáveis e
afetadas. Analise suposições e condições para fluxos esperados e de falha, assegure-se de que eles
ainda sejam precisos e desejáveis. Determine como validar as suposições e fazer cumprir as condições
necessárias para comportamentos adequados. Certifique-se de que os resultados sejam documentados na
história do usuário. Aprenda com os erros e ofereça incentivos positivos para promover melhorias. O
design seguro não é um _add-on_ nem uma ferramenta que você pode adicionar ao software.

### Ciclo de Vida de Desenvolvimento Seguro
O software seguro requer um ciclo de vida de desenvolvimento seguro, alguma forma de padrão
de projeto seguro, metodologia de _paved road_, bibliotecas de componentes protegidos, ferramentas
e modelagem de ameaças. Procure seus especialistas em segurança no início de um projeto de software,
durante todo o projeto e durante a manutenção de seu software. Considere aproveitar o
[OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) para ajudar a estruturar
seus esforços de desenvolvimento de software seguro.

## Como Prevenir

- Estabeleça e use um ciclo de vida de desenvolvimento seguro
    com profissionais de AppSec para ajudar a avaliar e projetar
    controles relacionados à segurança e privacidade.

- Estabeleça e use bibliotecas de padrões de projeto seguros ou
    componentes de _paved road_ prontos para usar.

- Use Modelagem de Ameaças para autenticação crítica, controle de acesso,
    lógica de negócios e fluxos de chaves.

- Integre a linguagem e os controles de segurança às histórias de usuários.

- Integre verificações de plausibilidade em cada camada da sua
    aplicação (do front-end ao back-end).

- Escreva testes de unidade e integração para validar se todos os fluxos críticos
    são resistentes ao modelo de ameaça. Compile casos de uso de sucesso e casos de uso
    indevido para cada camada da sua aplicação.

- Separe as camadas de nível no sistema e nas camadas de rede, dependendo
    das necessidades de exposição e proteção.

- Separe os _tenants_ de maneira robusta por design em todas as camadas.

- Limite o consumo de recursos por usuário ou serviço.

## Exemplos de Cenários de Ataque

**Cenário #1:** Um fluxo de trabalho de recuperação de credencial pode incluir
"perguntas e respostas" (confirmação positiva), o que é proibido pelo NIST 800-63b,
o OWASP ASVS e o OWASP Top 10. Perguntas e respostas não podem ser consideradas
evidências de identidade, pois mais de uma pessoa pode saber as respostas,
é por isso que eles são proibidos. Esse código deve ser removido e
substituído por um design mais seguro.

**Cenário #2:** Uma rede de cinemas permite descontos para reservas de grupos
e tem um máximo de quinze participantes antes de exigir um depósito.
Os invasores podem modelar esse fluxo e testar se conseguem reservar
seiscentos lugares e todos os cinemas de uma só vez em algumas solicitações,
causando uma enorme perda de receita.

**Cenário #3:** O site de comércio eletrônico de uma rede de varejo não
tem proteção contra bots executados por cambistas que compram placas
de vídeo de última geração para revender sites de leilão. Isso cria
uma publicidade terrível para os fabricantes de placas de vídeo
e proprietários de redes de varejo, além de sofrer com os
entusiastas que não podem obter essas placas a qualquer preço.
O design anti-bot cuidadoso e as regras de lógica de domínio,
como compras feitas dentro de alguns segundos de disponibilidade,
podem identificar compras não autênticas e rejeitar tais transações.

## Referências

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## Lista dos CWEs Mapeados

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)
