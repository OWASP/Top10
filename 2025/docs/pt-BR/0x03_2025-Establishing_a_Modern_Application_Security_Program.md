# Estabelecendo um Programa Moderno de Segurança de Aplicações

As listas OWASP Top Ten são documentos de conscientização, destinados a dar visibilidade aos riscos mais críticos de cada tópico que abordam. Elas não pretendem ser uma lista completa, mas apenas um ponto de partida. Em versões anteriores desta lista, prescrevemos o início de um programa de segurança de aplicações como a melhor forma de evitar esses riscos e muitos outros. Nesta seção, abordaremos como iniciar e construir um programa moderno de segurança de aplicações.

Se você já possui um programa de segurança de aplicações, considere realizar uma avaliação de maturidade utilizando o [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) ou o DSOMM (DevSecOps Maturity Model). Esses modelos de maturidade são abrangentes e exaustivos, podendo ser usados para ajudá-lo a entender onde focar melhor seus esforços para expandir e amadurecer seu programa. **Observação:** você não precisa fazer tudo o que está no OWASP SAMM ou no DSOMM para realizar um bom trabalho; eles servem para guiá-lo e oferecer diversas opções. Não foram feitos para oferecer padrões inalcançáveis ou descrever programas inacessíveis financeiramente. Eles são amplos para oferecer a você muitas ideias e opções.

Se você está começando um programa do zero, ou se considera o OWASP SAMM ou o DSOMM "demais" para o seu time no momento, revise os conselhos a seguir.

### 1. Estabeleça uma Abordagem de Portfólio Baseada em Risco:

- Identifique as necessidades de proteção do seu portfólio de aplicações sob uma perspectiva de negócio. Isso deve ser impulsionado, em parte, por leis de privacidade e outras regulamentações relevantes para o ativo de dados que está sendo protegido.
- Estabeleça um [modelo comum de classificação de risco](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) com um conjunto consistente de fatores de probabilidade e impacto que reflitam a tolerância ao risco da sua organização.
- Meça e priorize todas as suas aplicações e APIs adequadamente. Adicione os resultados ao seu [Configuration Management Database (CMDB)](https://de.wikipedia.org/wiki/Configuration_Management_Database).
- Estabeleça diretrizes de garantia para definir adequadamente a cobertura e o nível de rigor exigido.

### 2. Viabilize com uma Fundação Forte:

- Estabeleça um conjunto de políticas e padrões focados que forneçam uma linha de base (_baseline_) de segurança de aplicações para todas as equipes de desenvolvimento seguirem.
- Defina um conjunto comum de controles de segurança reutilizáveis que complementem essas políticas e padrões, fornecendo orientações de design e desenvolvimento sobre seu uso.
- Estabeleça um currículo de treinamento em segurança de aplicações que seja obrigatório e direcionado a diferentes funções e tópicos de desenvolvimento.

### 3. Integre a Segurança aos Processos Existentes:

- Defina e integre atividades de implementação e verificação segura aos processos operacionais e de desenvolvimento existentes.
- As atividades incluem modelagem de ameaças (_threat modeling_), design seguro e revisão de design, codificação segura e revisão de código, testes de intrusão (_penetration testing_) e remediação.
- Forneça especialistas no assunto (_SMEs_) e serviços de suporte para que as equipes de desenvolvimento e de projeto tenham sucesso.
- Revise seu ciclo de vida de desenvolvimento de sistemas (_SDLC_) atual e todas as atividades, ferramentas, políticas e processos de segurança de software e, em seguida, documente-os.
- Para novos softwares, adicione uma ou mais atividades de segurança a cada fase do _SDLC_. Abaixo, oferecemos sugestões do que pode ser feito. Garanta que essas novas atividades sejam realizadas em cada novo projeto ou iniciativa de software; dessa forma, você saberá que cada novo pedaço de software será entregue com uma postura de segurança aceitável para sua organização.
- Selecione suas atividades para garantir que seu produto final atenda a um nível de risco aceitável para sua organização.
- Para softwares existentes (às vezes chamados de legado), você desejará ter um plano de manutenção formal; procure ideias de como manter aplicações seguras na seção chamada 'Operações e Gerenciamento de Mudanças'.

### 4. Educação em Segurança de Aplicações:

- Considere iniciar um programa de _security champions_ ou um programa de educação geral em segurança para seus desenvolvedores (às vezes chamado de programa de _advocacy_ ou conscientização de segurança) para ensiná-los tudo o que você gostaria que eles soubessem. Isso os manterá atualizados, ajudará a saber como realizar seu trabalho de forma segura e tornará a cultura de segurança onde você trabalha mais positiva. Frequentemente, isso também melhora a confiança entre as equipes e cria uma relação de trabalho mais feliz. A OWASP apoia você nisso com o [OWASP Security Champions Guide](https://securitychampions.owasp.org/), que está sendo expandido passo a passo.
- O Projeto de Educação da OWASP fornece materiais de treinamento para ajudar a educar desenvolvedores em segurança de aplicações web. Para aprendizado prático sobre vulnerabilidades, experimente o [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/) ou o [OWASP WebGoat](https://owasp.org/www-project-webgoat/). Para manter-se atualizado, participe de uma [Conferência OWASP AppSec](https://owasp.org/events/), treinamentos em conferências ou reuniões de um [Chapter OWASP](https://owasp.org/chapters/) local.

### 5. Forneça Visibilidade para a Gestão:

- Gerencie com métricas. Direcione melhorias e decisões de financiamento com base em métricas e dados de análise capturados. As métricas incluem a adesão a práticas e atividades de segurança, vulnerabilidades introduzidas, vulnerabilidades mitigadas, cobertura de aplicações, densidade de defeitos por tipo e contagem de instâncias, etc.
- Analise dados das atividades de implementação e verificação para procurar a causa raiz e padrões de vulnerabilidade, visando impulsionar melhorias estratégicas e sistêmicas em toda a empresa. Aprenda com os erros e ofereça incentivos positivos para promover melhorias.

---

## Estabeleça e Use Processos de Segurança Repetíveis e Controles de Segurança Padrão

### Fase de Requisitos e Gerenciamento de Recursos:

- Colete e negocie os requisitos de negócio para uma aplicação com a área de negócios, incluindo os requisitos de proteção em relação à confidencialidade, autenticidade, integridade e disponibilidade de todos os ativos de dados, além da lógica de negócio esperada.
- Compile os requisitos técnicos, incluindo requisitos de segurança funcionais e não funcionais. A OWASP recomenda o uso do [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) como guia para definir os requisitos de segurança de sua(s) aplicação(ões).
- Planeje e negocie o orçamento que cubra todos os aspectos de design, construção, testes e operação, incluindo atividades de segurança.
- Adicione atividades de segurança ao cronograma do seu projeto.
- Apresente-se como o representante de segurança no _kick-off_ do projeto, para que saibam com quem falar.

### Solicitação de Propostas (RFP) e Contratação:

- Negocie os requisitos com desenvolvedores internos ou externos, incluindo diretrizes e requisitos de segurança em relação ao seu programa de segurança, por exemplo: _SDLC_, melhores práticas.
- Avalie o cumprimento de todos os requisitos técnicos, incluindo uma fase de planejamento e design.
- Negocie todos os requisitos técnicos, incluindo design, segurança e acordos de nível de serviço (_SLA_).
- Adote modelos e checklists, como o [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex).<br>**Nota:** _O anexo é baseado na lei de contratos dos EUA, portanto, consulte assessoria jurídica qualificada antes de usar o modelo._

### Fase de Planejamento e Design:

- Negocie o planejamento e o design com os desenvolvedores e partes interessadas internas, como especialistas em segurança.
- Defina a arquitetura de segurança, controles, contramedidas e revisões de design apropriadas às necessidades de proteção e ao nível de ameaça esperado. Isso deve ser apoiado por especialistas em segurança.
- Em vez de adaptar a segurança em suas aplicações e APIs posteriormente, é muito mais econômico projetar a segurança desde o início. A OWASP recomenda os [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) e os [OWASP Proactive Controls](https://top10proactive.owasp.org/) como um bom ponto de partida para orientações sobre como projetar a segurança incluída desde o princípio.
- Realize modelagem de ameaças (_threat modeling_); veja [OWASP Cheat Sheet: Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).
- Ensine conceitos e padrões de design seguro aos seus arquitetos de software e peça que os adicionem aos seus projetos sempre que possível.
- Examine os fluxos de dados com seus desenvolvedores.
- Adicione _user stories_ de segurança ao lado de todas as suas outras _user stories_.

### Ciclo de Vida de Desenvolvimento Seguro:

- Para melhorar o processo que sua organização segue ao construir aplicações e APIs, a OWASP recomenda o [OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/). Este modelo ajuda as organizações a formular e implementar uma estratégia para segurança de software adaptada aos riscos específicos enfrentados pela organização.
- Forneça treinamento de codificação segura para seus desenvolvedores de software e qualquer outro treinamento que você considere útil para criar aplicações mais robustas e seguras.
- Revisão de código; veja [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).
- Dê ferramentas de segurança aos seus desenvolvedores e ensine-os a usá-las, especialmente scanners de análise estática (_SAST_), análise de composição de software (_SCA_), segredos (_secrets_) e [Infraestrutura como Código (IaC)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html).
- Crie _guardrails_ para seus desenvolvedores, se possível (salvaguardas técnicas para direcioná-los a escolhas mais seguras).
- Construir controles de segurança fortes e utilizáveis é difícil. Ofereça padrões seguros (_secure defaults_) sempre que possível e crie "_paved roads_" (tornar o caminho mais fácil também o caminho mais seguro para fazer algo, a escolha preferencial óbvia) sempre que possível. Os [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) são um bom ponto de partida para desenvolvedores, e muitos frameworks modernos já vêm com controles de segurança padrão e eficazes para autorização, validação, prevenção de CSRF, etc.
- Forneça plugins de _IDE_ relacionados à segurança para seus desenvolvedores e incentive seu uso.
- Forneça uma ferramenta de gerenciamento de segredos (_secret management_), licenças e documentação sobre como usá-la.
- Forneça uma IA privada para uso, idealmente configurada com um servidor RAG repleto de documentação de segurança útil, _prompts_ que sua equipe escreveu para melhores resultados e um servidor MCP que chame as ferramentas de segurança escolhidas por sua organização. Ensine-os a usar a IA de forma segura, porque eles vão usá-la de qualquer maneira.

### Estabeleça Testes Contínuos de Segurança de Aplicações:

- Teste as funções técnicas e a integração com a arquitetura de TI e coordene os testes de negócio.
- Crie casos de teste de "uso" e "abuso" sob perspectivas técnicas e de negócio.
- Gerencie os testes de segurança de acordo com os processos internos, as necessidades de proteção e o nível de ameaça assumido pela aplicação.
- Forneça ferramentas de teste de segurança (_fuzzers_, _DAST_, etc.), um local seguro para testar e treinamento sobre como usá-las, OU realize os testes por eles OU contrate um testador.
- Se você exigir um alto nível de garantia, considere um teste de intrusão formal, bem como testes de estresse e testes de desempenho.
- Trabalhe com seus desenvolvedores para ajudá-los a decidir o que precisam corrigir nos relatórios de bugs e garanta que seus gestores deem tempo para que isso seja feito.

### Implantação (_Rollout_):

- Coloque a aplicação em operação e migre de aplicações usadas anteriormente, se necessário.
- Finalize toda a documentação, incluindo o banco de dados de gerenciamento de mudanças (CMDB) e a arquitetura de segurança.

### Operações e Gerenciamento de Mudanças:

- As operações devem incluir diretrizes para a gestão de segurança da aplicação (ex: gestão de patches).
- Aumente a conscientização de segurança dos usuários e gerencie conflitos entre usabilidade vs. segurança.
- Planeje e gerencie mudanças, ex: migrar para novas versões da aplicação ou outros componentes como SO, _middleware_ e bibliotecas.
- Garanta que todas as aplicações estejam em seu inventário, com todos os detalhes importantes documentados. Atualize toda a documentação, incluindo no CMDB e na arquitetura de segurança, controles e contramedidas, incluindo quaisquer _runbooks_ ou documentação de projeto.
- Execute registro de logs, monitoramento e alertas para todas as aplicações. Adicione se estiver faltando.
- Crie processos para atualizações e correções (_patching_) eficazes e eficientes.
- Crie cronogramas de varredura regular (idealmente dinâmica, estática, segredos, IaC e análise de composição de software).
- _SLAs_ para correção de bugs de segurança.
- Forneça uma maneira para funcionários (e idealmente também seus clientes) reportarem bugs.
- Estabeleça uma equipe treinada de resposta a incidentes que entenda como são os ataques de software e utilize ferramentas de observabilidade.
- Execute ferramentas de bloqueio ou blindagem para deter ataques automatizados.
- Endurecimento (_hardening_) anual (ou mais frequente) de configurações.
- Teste de intrusão pelo menos anual (dependendo do nível de garantia exigido para sua aplicação).
- Estabeleça processos e ferramentas para o endurecimento e proteção de sua cadeia de suprimentos de software.
- Estabeleça e atualize o planejamento de continuidade de negócios e recuperação de desastres que inclua suas aplicações mais importantes e as ferramentas usadas para mantê-las.

### Desativação de Sistemas:

- Quaisquer dados exigidos devem ser arquivados. Todos os outros dados devem ser apagados de forma segura.
- Desative a aplicação com segurança, incluindo a exclusão de contas, funções e permissões não utilizadas.
- Defina o estado de sua aplicação como "desativada" no CMDB.

---

## Usando o OWASP Top 10 como um Padrão

O OWASP Top 10 é prioritariamente um documento de conscientização. No entanto, isso não impediu as organizações de usá-lo como um padrão _de facto_ de AppSec da indústria desde sua criação em 2003. Se você deseja usar o OWASP Top 10 como um padrão de codificação ou teste, saiba que ele é o mínimo indispensável e apenas um ponto de partida.

Uma das dificuldades de usar o OWASP Top 10 como padrão é que documentamos riscos de AppSec, e não necessariamente problemas facilmente testáveis. Por exemplo, [A06:2025-Design Inseguro](A06_2025-Insecure_Design.md) está além do escopo da maioria das formas de teste. Outro exemplo é testar se o registro de logs e o monitoramento eficazes estão implementados e em uso, o que só pode ser feito com entrevistas e solicitando uma amostragem de respostas a incidentes eficazes. Uma ferramenta de análise de código estática pode procurar pela ausência de logs, mas pode ser impossível determinar se a lógica de negócio ou o controle de acesso está registrando violações de segurança críticas. Testadores de intrusão podem apenas ser capazes de determinar que invocaram a resposta a incidentes em um ambiente de teste, o qual raramente é monitorado da mesma forma que a produção.

Aqui estão nossas recomendações para quando é apropriado usar o OWASP Top 10:

| Caso de Uso                    | OWASP Top 10 2025    | OWASP Application Security Verification Standard |
| :----------------------------- | :------------------- | :----------------------------------------------- |
| Conscientização                | Sim                  |                                                  |
| Treinamento                    | Nível de entrada     | Abrangente                                       |
| Design e arquitetura           | Ocasionalmente       | Sim                                              |
| Padrão de codificação          | Mínimo indispensável | Sim                                              |
| Revisão de Código Seguro       | Mínimo indispensável | Sim                                              |
| Checklist de revisão por pares | Mínimo indispensável | Sim                                              |
| Teste de unidade               | Ocasionalmente       | Sim                                              |
| Teste de integração            | Ocasionalmente       | Sim                                              |
| Teste de intrusão              | Mínimo indispensável | Sim                                              |
| Suporte de ferramentas         | Mínimo indispensável | Sim                                              |
| Cadeia de Suprimentos Segura   | Ocasionalmente       | Sim                                              |

Encorajamos qualquer pessoa que queira adotar um padrão de segurança de aplicações a usar o [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS), pois ele foi projetado para ser verificável e testável, podendo ser usado em todas as partes de um ciclo de vida de desenvolvimento seguro.

O ASVS é a única escolha aceitável para fornecedores de ferramentas. Ferramentas não podem detectar, testar ou proteger de forma abrangente contra o OWASP Top 10 devido à natureza de vários dos riscos presentes, com referência ao [A06:2025-Design Inseguro](A06_2025-Insecure_Design.md). A OWASP desestimula quaisquer alegações de cobertura total do OWASP Top 10, porque isso é simplesmente falso.
