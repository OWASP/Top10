![OWASP Logo](../assets/TOP_10_logo_Final_Logo_Colour.png)

# Os Dez Riscos de Segurança mais Críticos para Aplicações Web

# Introdução

Bem-vindo à 8ª edição da OWASP Top Ten!

Um enorme agradecimento a todos que contribuíram com dados e perspectivas na pesquisa. Sem vocês, esta edição não seria possível. **MUITO OBRIGADO!**

## Apresentando OWASP Top 10:2025

- [A01:2025 - Controle de Acesso Quebrado](A01_2025-Broken_Access_Control.md)
- [A02:2025 - Configuração Insegura](A02_2025-Security_Misconfiguration.md)
- [A03:2025 - Falhas na Cadeia de Suprimentos de Software](A03_2025-Software_Supply_Chain_Failures.md)
- [A04:2025 - Falhas Criptográficas](A04_2025-Cryptographic_Failures.md)
- [A05:2025 - Injeção](A05_2025-Injection.md)
- [A06:2025 - Design Inseguro](A06_2025-Insecure_Design.md)
- [A07:2025 - Falhas de Autenticação](A07_2025-Authentication_Failures.md)
- [A08:2025 - Falhas de Integridade de Software e Dados](A08_2025-Software_or_Data_Integrity_Failures.md)
- [A09:2025 - Falhas de Registro e Alerta de Segurança](A09_2025-Security_Logging_and_Alerting_Failures.md)
- [A10:2025 - Manuseio Incorreto de Condições Excepcionais](A10_2025-Mishandling_of_Exceptional_Conditions.md)

## Mudanças da Top 10 para 2025

Há duas novas categorias e uma consolidação no Top Ten de 2025. Trabalhamos para manter nosso foco na raiz do problema em vez do sintoma, tanto quanto possível. Dada a complexidade da engenharia e segurança de software, é basicamente impossível criar 10 categorias sem algum nível de sobreposição.

![Mapping](../assets/2025-mappings.png)

- **[A01:2025 - Controle de Acesso Quebrado](A01_2025-Broken_Access_Control.md)** mantém sua posição em #1 como o risco mais sério; os dados indicam que, em média, 3,73% das aplicações testadas apresentavam uma ou mais das 40 Common Weakness Enumerations (CWEs) desta categoria. Como indicado pela linha pontilhada, o Server-Side Request Forgery (SSRF) foi incorporado a esta categoria.
- **[A02:2025 - Configuração Insegura](A02_2025-Security_Misconfiguration.md)** subiu da 5ª posição em 2021 para a 2ª em 2025. Configurações incorretas estão mais prevalentes; 3,00% das aplicações testadas tinham uma ou mais das 16 CWEs aqui listadas. Isso não surpreende, visto que o comportamento das aplicações depende cada vez mais de configurações.
- **[A03:2025 - Software Supply Chain Failures](A03_2025-Software_Supply_Chain_Failures.md)** (Falhas na Cadeia de Suprimentos de Software) é uma expansão de [A06:2021-Componentes Vulneráveis e Desatualizados](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) para incluir um escopo mais amplo de comprometimentos que ocorrem dentro ou através de todo o ecossistema de dependências de software, sistemas de build e infraestrutura de distribuição. Esta categoria foi votada massivamente como uma das principais preocupações na pesquisa com a comunidade. A categoria possui 5 CWEs e uma presença limitada nos dados coletados, mas acreditamos que isso se deve a desafios nos testes e esperamos que os testes evoluam nesta área. Esta categoria possui o menor número de ocorrências nos dados, mas também as maiores pontuações médias de explorabilidade (exploit) e impacto vindas de CVEs.
- **[A04:2025 - Falhas Criptográficas](A04_2025-Cryptographic_Failures.md)** caiu duas posições, de #2 para #4 no ranking. Os dados contribuídos indicam que, em média, 3,80% das aplicações possuem uma ou mais das 32 CWEs nesta categoria. Esta categoria frequentemente leva à exposição de dados sensíveis ou ao comprometimento do sistema.
- **[A05:2025 - Injeção](A05_2025-Injection.md)** caiu duas posições, de #3 para #5 no ranking, mantendo sua posição relativa a Falhas Criptográficas e Design Inseguro. Injeção é uma das categorias mais testadas, com o maior número de CVEs associados às 38 CWEs nesta categoria. Injeção inclui uma gama de problemas, desde Cross-Site Scripting (alta frequência/baixo impacto) até vulnerabilidades de SQL Injection (baixa frequência/alto impacto).
- **[A06:2025 - Design Inseguro](A06_2025-Insecure_Design.md)** caiu duas posições, de #4 para #6 no ranking, conforme Configuração Insegura e Falhas na Cadeia de Suprimentos de Software a ultrapassaram. Esta categoria foi introduzida em 2021 e observamos melhorias notáveis na indústria relacionadas à modelagem de ameaças (threat modeling) e uma maior ênfase em design seguro.
- **[A07:2025 - Falhas de Autenticação](A07_2025-Authentication_Failures.md)** mantém sua posição em #7 com uma leve mudança no nome (anteriormente era "[Falhas de Identificação e Autenticação](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)") para refletir com mais precisão as 36 CWEs nesta categoria. Esta categoria continua importante, mas o aumento do uso de frameworks padronizados para autenticação parece estar gerando efeitos benéficos nas ocorrências de falhas de autenticação.
- **[A08:2025 - Falhas de Integridade de Software e Dados](A08_2025-Software_or_Data_Integrity_Failures.md)** continua em #8 na lista. Esta categoria foca na falha em manter perímetros de confiança (trust boundaries) e verificar a integridade de artefatos de software, código e dados em um nível inferior às Falhas na Cadeia de Suprimentos de Software.
- **[A09:2025 - Falhas de Registro e Alerta de Segurança](A09_2025-Security_Logging_and_Alerting_Failures.md)** mantém sua posição em #9. Esta categoria teve uma leve mudança no nome (anteriormente "[Falhas de Registro e Monitoramento de Segurança](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)") para enfatizar a importância da funcionalidade de alerta necessária para induzir a ação apropriada diante de eventos de log relevantes. Um excelente registro de log sem alertas possui valor mínimo na identificação de incidentes de segurança. Esta categoria estará sempre sub-representada nos dados e foi novamente votada para uma posição na lista pelos participantes da pesquisa da comunidade.
- **[A10:2025 - Manuseio Incorreto de Condições Excepcionais](A10_2025-Mishandling_of_Exceptional_Conditions.md)** é uma nova categoria para 2025. Esta categoria contém 24 CWEs focadas em tratamento de erros inadequado, erros lógicos, falha aberta (failing open) e outros cenários relacionados decorrentes de condições anormais que os sistemas podem encontrar.

## Metodologia

Esta edição do Top Ten permanece informada por dados, mas não é cegamente impulsionada por eles. Classificamos 12 categorias com base nos dados contribuídos e permitimos que duas fossem promovidas ou destacadas por meio das respostas da pesquisa com a comunidade. Fazemos isso por uma razão fundamental: examinar os dados contribuídos é, essencialmente, olhar para o passado. Pesquisadores de Segurança de Aplicações dedicam tempo para identificar novas vulnerabilidades e desenvolver novos métodos de teste. Leva de semanas a anos para integrar esses testes em ferramentas e processos. No momento em que podemos testar confiavelmente uma fraqueza em escala, anos podem ter se passado. Também existem riscos importantes que talvez nunca possamos testar de forma confiável para que apareçam nos dados. Para equilibrar essa visão, utilizamos uma pesquisa com a comunidade para perguntar aos profissionais de segurança e desenvolvedores que estão na linha de frente o que eles veem como riscos essenciais que podem estar sub-representados nos dados de teste.

## Como as Categorias são Estruturadas

Algumas categorias mudaram em relação à edição anterior do OWASP Top Ten. Aqui está um resumo de alto nível das mudanças nas categorias.

Nesta iteração, solicitamos dados sem restrição de CWEs, como fizemos na edição de 2021. Perguntamos o número de aplicações testadas em um determinado ano (começando em 2021) e o número de aplicações com pelo menos uma instância de uma CWE encontrada nos testes. Este formato nos permite rastrear quão prevalente cada CWE é dentro da população de aplicações. Ignoramos a frequência para nossos propósitos; embora ela possa ser necessária em outras situações, ela apenas oculta a prevalência real na população de aplicações. Se uma aplicação possui quatro instâncias de uma CWE ou 4.000 instâncias, isso não faz parte do cálculo para o Top Ten. Especialmente porque testadores manuais tendem a listar uma vulnerabilidade apenas uma vez, não importa quantas vezes ela se repita em uma aplicação, enquanto frameworks de testes automatizados listam cada instância de uma vulnerabilidade como única. Passamos de aproximadamente 30 CWEs em 2017 para quase 400 em 2021 e para 589 CWEs nesta edição para análise no conjunto de dados. Planejamos realizar análises de dados adicionais como complemento no futuro. Este aumento significativo no número de CWEs exige mudanças na forma como as categorias são estruturadas.

Passamos vários meses agrupando e categorizando CWEs e poderíamos ter continuado por meses adicionais. Tivemos que parar em algum momento. Existem CWEs do tipo causa raiz e do tipo sintoma, onde as de causa raiz são como "Falha Criptográfica" e "Configuração Incorreta", em contraste com tipos de sintoma como "Exposição de Dados Sensíveis" e "Negação de Serviço". Decidimos focar na causa raiz sempre que possível, pois é mais lógico para fornecer orientações de identificação e remediação. Focar na causa raiz em vez do sintoma não é um conceito novo; o Top Ten tem sido uma mistura de sintoma e causa raiz. As CWEs também são uma mistura de sintoma e causa raiz; estamos simplesmente sendo mais deliberados ao apontar isso. Há uma média de 25 CWEs por categoria nesta edição, com limites inferiores de 5 CWEs para A03:2025-Software Supply Chain Failures e A09:2025 Security Logging and Alerting Failures, até 40 CWEs em A01:2025-Broken Access Control. Tomamos a decisão de limitar o número de CWEs em uma categoria a 40. Esta estrutura de categorias atualizada oferece benefícios adicionais de treinamento, pois as empresas podem focar em CWEs que façam sentido para uma linguagem/framework.

Perguntaram-nos por que não mudar para uma lista de 10 CWEs como um Top 10, similar ao MITRE Top 25 Most Dangerous Software Weaknesses. Existem duas razões principais pelas quais usamos múltiplas CWEs em categorias. Primeiro, nem todas as CWEs existem em todas as linguagens de programação ou frameworks. Isso causa problemas para ferramentas e programas de treinamento/conscientização, já que parte do Top Ten poderia não ser aplicável. A segunda razão é que existem múltiplas CWEs para vulnerabilidades comuns. Por exemplo, existem múltiplas CWEs para Injeção geral, Command Injection, Cross-Site Scripting, Senhas Hardcoded, Falta de Validação, Buffer Overflows, Armazenamento de Informações Sensíveis em Texto Simples e muitas outras. Dependendo da organização ou do testador, diferentes CWEs podem ser usadas. Ao usar uma categoria com múltiplas CWEs, podemos ajudar a elevar a base de referência e a conscientização sobre os diferentes tipos de fraquezas que podem ocorrer sob um nome de categoria comum. Nesta edição do Top Ten 2025, existem 248 CWEs dentro das 10 categorias. Há um total de 968 CWEs no [dicionário para download do MITRE](https://cwe.mitre.org) no momento deste lançamento.

## Como os dados são usados para selecionar as categorias

De forma semelhante ao que fizemos para a edição de 2021, aproveitamos os dados de CVE para _Explorabilidade_ (Exploitability) e _Impacto (Técnico)_. Baixamos o OWASP Dependency Check e extraímos as pontuações de Exploit e Impact do CVSS, agrupando-as pelas CWEs relevantes listadas com as CVEs. Isso exigiu uma boa dose de pesquisa e esforço, pois todas as CVEs possuem pontuações CVSSv2, mas há falhas no CVSSv2 que o CVSSv3 deveria corrigir. Após um certo ponto no tempo, todas as CVEs recebem também uma pontuação CVSSv3. Além disso, as faixas de pontuação e fórmulas foram atualizadas entre o CVSSv2 e o CVSSv3.

No CVSSv2, tanto a Explorabilidade quanto o Impacto (Técnico) podiam chegar a 10.0, mas a fórmula os reduzia para 60% para Explorabilidade e 40% para Impacto. No CVSSv3, o máximo teórico foi limitado a 6.0 para Explorabilidade e 4.0 para Impacto. Com o peso considerado, a pontuação de Impacto subiu quase um ponto e meio em média no CVSSv3, e a explorabilidade caiu quase meio ponto em média.

Existem aproximadamente 175 mil registros (contra 125 mil em 2021) de CVEs mapeadas para CWEs no National Vulnerability Database (NVD), extraídos do OWASP Dependency Check. Além disso, há 643 CWEs únicas mapeadas para CVEs (contra 241 em 2021). Dentro das quase 220 mil CVEs extraídas, 160 mil tinham pontuações CVSS v2, 156 mil tinham pontuações CVSS v3 e 6 mil tinham pontuações CVSS v4. Muitas CVEs possuem múltiplas pontuações, por isso o total ultrapassa 220 mil.

Para o Top Ten 2025, calculamos as pontuações médias de explorabilidade e impacto da seguinte maneira: agrupamos todas as CVEs com pontuações CVSS por CWE e ponderamos as pontuações de explorabilidade e impacto pela porcentagem da população que possuía CVSSv3, bem como a população restante com pontuações CVSSv2, para obter uma média geral. Mapeamos essas médias para as CWEs no conjunto de dados para usar como pontuação de Explorabilidade e Impacto (Técnico) para a outra metade da equação de risco.

Por que não usar o CVSS v4.0, você pode perguntar? Isso ocorre porque o algoritmo de pontuação foi fundamentalmente alterado e não fornece mais facilmente as pontuações de _Exploit_ ou _Impact_ como o CVSS v2 e o CVSSv3 fazem. Tentaremos descobrir uma maneira de usar a pontuação CVSS v4.0 para versões futuras do Top Ten, mas não conseguimos determinar uma forma oportuna de fazê-lo para a edição de 2025.

## Por que usamos uma pesquisa com a comunidade

Os resultados nos dados são amplamente limitados ao que a indústria consegue testar de forma automatizada. Fale com um profissional experiente em AppSec e ele lhe contará sobre coisas que encontra e tendências que vê que ainda não estão nos dados. Leva tempo para as pessoas desenvolverem metodologias de teste para certos tipos de vulnerabilidade e mais tempo ainda para que esses testes sejam automatizados e executados contra uma grande população de aplicações. Tudo o que encontramos é um olhar para o passado e pode estar perdendo tendências do último ano que não estão presentes nos dados.

Portanto, selecionamos apenas oito das dez categorias a partir dos dados porque eles são incompletos. As outras duas categorias vêm da pesquisa com a comunidade Top 10. Isso permite que os profissionais que estão na linha de frente votem no que veem como os riscos mais altos que podem não estar nos dados (e que talvez nunca sejam expressos em dados).

## Obrigado aos nossos contribuidores de dados

As seguintes organizações (juntamente com vários doadores anônimos) gentilmente doaram dados de mais de 2,8 milhões de aplicações para tornar este o maior e mais abrangente conjunto de dados de segurança de aplicações. Sem vocês, isso não seria possível.

- Accenture (Prague)
- Anônimo (múltiplos)
- Bugcrowd
- Contrast Security
- CryptoNet Labs
- Intuitor SoftTech Services
- Orca Security
- Probely
- Semgrep
- Sonar
- usd AG
- Veracode
- Wallarm

## Autores Principais

- Andrew van der Stock - X: [@vanderaj](https://x.com/vanderaj)
- Brian Glas - X: [@infosecdad](https://x.com/infosecdad)
- Neil Smithline - X: [@appsecneil](https://x.com/appsecneil)
- Tanya Janca - X: [@shehackspurple](https://x.com/shehackspurple)
- Torsten Gigler - Mastodon: [@torsten_gigler@infosec.exchange](https://infosec.exchange/@torsten_gigler)

## Registro de problemas e pull requests

Por favor, registre quaisquer correções ou problemas:

### Links do projeto:

- [Página Inicial](https://owasp.org/www-project-top-ten/)
- [Repositório GitHub](https://github.com/OWASP/Top10)
