# A06:2025 Design Inseguro ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}

## Contexto

O Design Inseguro caiu duas posições, passando de #4 para #6 no ranking, sendo ultrapassado por **[A02:2025-Configuração Insegura](A02_2025-Security_Misconfiguration.md)** e **[A03:2025-Falhas na Cadeia de Suprimentos de Software](A03_2025-Software_Supply_Chain_Failures.md)**. Esta categoria foi introduzida em 2021 e temos observado melhorias notáveis na indústria em relação à modelagem de ameaças e uma maior ênfase em design seguro. Esta categoria foca em riscos relacionados a falhas de design e arquitetura, com um apelo para o maior uso de modelagem de ameaças, padrões de design seguro (_secure design patterns_) e arquiteturas de referência. Isso inclui falhas na lógica de negócio de uma aplicação, por exemplo, a falta de definição de mudanças de estado indesejadas ou inesperadas dentro de uma aplicação. Como comunidade, precisamos ir além do "shift-left" no espaço da codificação para atividades pré-código, como a escrita de requisitos e o design da aplicação, que são críticos para os princípios de _Secure by Design_ (veja, por exemplo, **[Estabelecendo um Programa de AppSec Moderno: Fase de Planejamento e Design](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**). Enumerações de Fraquezas Comuns (CWEs) notáveis incluem _CWE-256: Armazenamento Não Protegido de Credenciais, CWE-269 Gerenciamento Inadequado de Privilégios, CWE-434 Upload Irrestrito de Arquivo com Tipo Perigoso, CWE-501: Violação de Limite de Confiança e CWE-522: Credenciais Protegidas de Forma Insuficiente._

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
   <td>39
   </td>
   <td>22,18%
   </td>
   <td>1,86%
   </td>
   <td>88,76%
   </td>
   <td>35,18%
   </td>
   <td>6,96
   </td>
   <td>4,05
   </td>
   <td>729.882
   </td>
   <td>7.647
   </td>
  </tr>
</table>

## Descrição

O design inseguro é uma categoria ampla que representa diferentes fraquezas, expressas como "design de controle ausente ou ineficaz". O design inseguro não é a origem de todas as outras categorias de risco do Top Ten. Observe que existe uma diferença entre design inseguro e implementação insegura. Diferenciamos falhas de design de defeitos de implementação por um motivo: eles possuem causas raízes diferentes, ocorrem em momentos diferentes do processo de desenvolvimento e possuem remediações distintas. Um design seguro ainda pode apresentar defeitos de implementação que levam a vulnerabilidades passíveis de exploração. Já um design inseguro não pode ser corrigido por uma implementação perfeita, uma vez que os controles de segurança necessários para defender contra ataques específicos nunca foram criados. Um dos fatores que contribui para o design inseguro é a falta de perfil de risco de negócio (_business risk profiling_) inerente ao software ou sistema sendo desenvolvido e, consequentemente, a falha em determinar qual nível de design de segurança é necessário.

Três partes fundamentais para ter um design seguro são:

- Coleta de Requisitos e Gerenciamento de Recursos
- Criação de um Design Seguro
- Manutenção de um Ciclo de Vida de Desenvolvimento Seguro (SDLC)

### Requisitos e Gerenciamento de Recursos

Colete e negocie os requisitos de negócio para uma aplicação com as partes interessadas, incluindo os requisitos de proteção relativos à confidencialidade, integridade, disponibilidade e autenticidade de todos os ativos de dados e a lógica de negócio esperada. Leve em conta o quão exposta sua aplicação estará e se você precisa de segregação de instâncias (_tenants_) — além daquelas necessárias para o controle de acesso. Compile os requisitos técnicos, incluindo requisitos de segurança funcionais e não funcionais. Planeje e negocie o orçamento cobrindo todo o design, construção, testes e operação, incluindo atividades de segurança.

### Design Seguro

O design seguro é uma cultura e metodologia que avalia constantemente as ameaças e garante que o código seja projetado e testado de forma robusta para prevenir métodos de ataque conhecidos. A modelagem de ameaças deve ser integrada às sessões de refinamento (ou atividades similares); busque por mudanças nos fluxos de dados e no controle de acesso ou outros controles de segurança. No desenvolvimento da _user story_, determine o fluxo correto e os estados de falha, garantindo que sejam bem compreendidos e acordados pelas partes responsáveis e impactadas. Analise suposições e condições para fluxos esperados e de falha para garantir que permaneçam precisos e desejáveis. Determine como validar as suposições e impor as condições necessárias para comportamentos adequados. Garanta que os resultados sejam documentados na _user story_. Aprenda com os erros e ofereça incentivos positivos para promover melhorias. O design seguro não é um acessório nem uma ferramenta que você possa adicionar ao software.

### Ciclo de Vida de Desenvolvimento Seguro

Software seguro exige um ciclo de vida de desenvolvimento seguro, um padrão de design seguro, uma metodologia de "estrada pavimentada" (_paved road_), uma biblioteca de componentes seguros, ferramentas apropriadas, modelagem de ameaças e pós-mortems de incidentes que sejam usados para melhorar o processo. Entre em contato com seus especialistas em segurança no início de um projeto de software, ao longo de todo o projeto e para a manutenção contínua do software. Considere utilizar o [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/) para ajudar a estruturar seus esforços de desenvolvimento de software seguro.

Frequentemente, a autorresponsabilidade dos desenvolvedores é subestimada. Promova uma cultura de conscientização, responsabilidade e mitigação proativa de riscos. Trocas regulares sobre segurança (ex: durante sessões de modelagem de ameaças) podem gerar uma mentalidade para incluir a segurança em todas as decisões importantes de design.

## Como prevenir

- Estabeleça e utilize um ciclo de vida de desenvolvimento seguro com profissionais de AppSec para ajudar a avaliar e projetar controles relacionados à segurança e privacidade.
- Estabeleça e utilize uma biblioteca de padrões de design seguro ou componentes de "estrada pavimentada" (_paved road_).
- Utilize a modelagem de ameaças para partes críticas da aplicação, como autenticação, controle de acesso, lógica de negócio e fluxos principais.
- Utilize a modelagem de ameaças como uma ferramenta educacional para gerar uma mentalidade de segurança.
- Integre linguagem e controles de segurança nas _user stories_.
- Integre verificações de plausibilidade em cada camada da sua aplicação (do frontend ao backend).
- Escreva testes de unidade e integração para validar que todos os fluxos críticos são resistentes ao modelo de ameaças. Compile casos de uso (_use-cases_) **e** casos de abuso (_misuse-cases_) para cada camada da sua aplicação.
- Segregue as camadas do sistema e da rede, dependendo da exposição e das necessidades de proteção.
- Segregue instâncias (_tenants_) de forma robusta por design em todas as camadas.

## Exemplos de cenários de ataque

**Cenário #1:** Um fluxo de recuperação de credenciais pode incluir "perguntas e respostas", o que é proibido pelo NIST 800-63b, pelo OWASP ASVS e pelo OWASP Top 10. Perguntas e respostas não podem ser confiáveis como prova de identidade, pois mais de uma pessoa pode saber as respostas. Tal funcionalidade deve ser removida e substituída por um design mais seguro.

**Cenário #2:** Uma rede de cinemas permite descontos para reservas em grupo e possui um máximo de quinze participantes antes de exigir um depósito. Atacantes poderiam modelar as ameaças deste fluxo e testar se conseguem encontrar um vetor de ataque na lógica de negócio da aplicação, por exemplo, reservando seiscentos assentos em todos os cinemas de uma só vez em poucas requisições, causando uma perda massiva de receita.

**Cenário #3:** O site de e-commerce de uma rede varejista não possui proteção contra _bots_ operados por cambistas (_scalpers_) que compram placas de vídeo de alto desempenho para revender em sites de leilão. Isso gera uma publicidade terrível para os fabricantes de placas de vídeo e para os proprietários da rede varejista, além de um rancor duradouro com os entusiastas que não conseguem obter essas placas por preço algum. Um design anti-bot cuidadoso e regras de lógica de domínio, como identificar compras feitas em poucos segundos após a disponibilidade, poderiam identificar compras inautênticas e rejeitar tais transações.

## Referências

- [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
- [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
- [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
- [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
- [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
- [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## Lista de CWEs Mapeadas

- [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
- [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)
- [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
- [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)
- [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)
- [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
- [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)
- [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)
- [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)
- [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
- [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)
- [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)
- [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
- [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)
- [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
- [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)
- [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)
- [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)
- [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)
- [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
- [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)
- [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)
- [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
- [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
- [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
- [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
- [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)
- [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)
