# A03:2025 – Falhas na Cadeia de Suprimentos de Software ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Contexto

Esta categoria foi a mais votada na pesquisa da comunidade para o Top 10, com exatamente 50% dos entrevistados classificando-a como a nº 1. Desde sua aparição inicial no Top 10 de 2013 como "A9 – Utilização de Componentes com Vulnerabilidades Conhecidas", o risco cresceu em escopo para incluir todas as falhas na cadeia de suprimentos (_supply chain_), não apenas aquelas que envolvem vulnerabilidades conhecidas. Apesar desse aumento de escopo, as falhas na cadeia de suprimentos continuam sendo um desafio para identificação, com apenas 11 vulnerabilidades (CVEs) possuindo as CWEs relacionadas. No entanto, quando testada e reportada nos dados contribuídos, esta categoria apresenta a maior taxa média de incidência, de 5,19%. As CWEs relevantes são _CWE-477: Use of Obsolete Function_, _CWE-1104: Use of Unmaintained Third Party Components_, _CWE-1329: Reliance on Component That is Not Updateable_ e _CWE-1395: Dependency on Vulnerable Third-Party Component_.

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
   <td>6
   </td>
   <td>9.56%
   </td>
   <td>5.72%
   </td>
   <td>65.42%
   </td>
   <td>27.47%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>

## Descrição

Falhas na cadeia de suprimentos de software são interrupções ou outros comprometimentos no processo de construção, distribuição ou atualização de software. Frequentemente, são causadas por vulnerabilidades ou alterações maliciosas em códigos de terceiros, ferramentas ou outras dependências das quais o sistema depende.

Você provavelmente está **vulnerável** se:

- Você não rastreia cuidadosamente as versões de todos os componentes que utiliza (tanto no lado do cliente quanto no servidor). Isso inclui componentes usados diretamente, bem como dependências aninhadas (transitivas).
- O software é vulnerável, sem suporte ou desatualizado. Isso inclui o sistema operacional, servidor web/aplicação, sistema de gerenciamento de banco de dados (DBMS), aplicações, **APIs** e todos os componentes, ambientes de **runtime** e bibliotecas.
- Você não realiza varreduras de vulnerabilidades regularmente e não assina boletins de segurança relacionados aos componentes que utiliza.
- Você não possui um processo de gerenciamento de mudanças ou rastreamento de alterações em sua cadeia de suprimentos, incluindo o rastreamento de IDEs, extensões e atualizações de IDE, alterações no repositório de código da sua organização, **sandboxes**, repositórios de imagens e bibliotecas, a forma como os artefatos são criados e armazenados, etc. Cada parte da sua cadeia de suprimentos deve ser documentada, especialmente as mudanças.
- Você não realizou o endurecimento (_hardening_) de cada parte da sua cadeia de suprimentos, com foco especial no controle de acesso e na aplicação do menor privilégio.
- Seus sistemas de cadeia de suprimentos não possuem separação de funções (_separation of duties_). Nenhuma pessoa sozinha deve ser capaz de escrever o código e promovê-lo até a produção sem a supervisão de outro ser humano.
- Componentes de fontes não confiáveis, em qualquer parte da stack tecnológica, são usados ou podem impactar ambientes de produção.
- Você não corrige ou atualiza a plataforma subjacente, **frameworks** e dependências de maneira oportuna e baseada em riscos. Isso acontece comumente em ambientes onde o **patching** é uma tarefa mensal ou trimestral sob controle de mudanças, deixando as organizações expostas por dias ou meses a riscos desnecessários antes de corrigir as vulnerabilidades.
- Os desenvolvedores de software não testam a compatibilidade de bibliotecas atualizadas ou corrigidas.
- Você não protege as configurações de cada parte do seu sistema (consulte [A02:2025 – Configuração Insegura](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)).
- Seu **pipeline** de CI/CD possui segurança mais fraca do que os sistemas que ele constrói e implanta, especialmente se for complexo.

## Como Prevenir

Deve haver um processo de gerenciamento de **patches** para:

- Gerar e gerenciar centralizadamente a Lista de Materiais de Software (**SBOM** – _Software Bill of Materials_) de todo o seu software.
- Rastrear não apenas suas dependências diretas, mas também as transitivas, e assim por diante.
- Reduzir a superfície de ataque removendo dependências não utilizadas, recursos desnecessários, componentes, arquivos e documentação.
- Inventariar continuamente as versões de componentes tanto do lado do cliente quanto do servidor (ex: **frameworks**, bibliotecas) e suas dependências usando ferramentas como OWASP Dependency Track, OWASP Dependency Check, retire.js, etc.
- Monitorar continuamente fontes como CVE (_Common Vulnerability and Exposures_), NVD (_National Vulnerability Database_) e [Open Source Vulnerabilities (OSV)](https://osv.dev/) em busca de vulnerabilidades nos componentes utilizados. Use ferramentas de análise de composição de software (SCA), cadeia de suprimentos ou ferramentas de **SBOM** focadas em segurança para automatizar o processo. Assine alertas de vulnerabilidades de segurança relacionadas aos componentes que você usa.
- Obter componentes apenas de fontes oficiais (confiáveis) através de links seguros. Prefira pacotes assinados para reduzir a chance de incluir um componente modificado ou malicioso (consulte [A08:2025 – Falhas de Integridade de Software e Dados](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)).
- Escolher deliberadamente qual versão de uma dependência utilizar e atualizar apenas quando houver necessidade.
- Monitorar bibliotecas e componentes que não possuem manutenção ou que não criam **patches** de segurança para versões antigas. Se a correção não for possível, considere migrar para uma alternativa. Caso não seja viável, considere implantar um **patch** virtual para monitorar, detectar ou proteger contra o problema descoberto.
- Atualizar regularmente seu CI/CD, IDE e qualquer outra ferramenta de desenvolvimento.
- Evitar a implantação de atualizações em todos os sistemas simultaneamente. Use implantações em estágios ou _canary deployments_ para limitar a exposição caso um fornecedor confiável seja comprometido.

Deve haver um processo de gerenciamento de mudanças ou sistema de rastreamento para monitorar alterações em:

- Configurações de CI/CD (todas as ferramentas de construção e **pipelines**)
- Repositórios de código
- Áreas de **sandbox**
- IDEs de desenvolvedores
- Ferramental de **SBOM** e artefatos criados
- Sistemas de registro (**logging**) e **logs**
- Integrações de terceiros, como SaaS
- Repositórios de artefatos
- Registros de contêineres

Realize o _hardening_ dos seguintes sistemas, o que inclui habilitar MFA e restringir o IAM:

- Seu repositório de código (o que inclui não armazenar segredos, proteger ramificações/_branches_ e realizar backups).
- Estações de trabalho de desenvolvedores (**patching** regular, MFA, monitoramento e mais).
- Seu servidor de build e CI/CD (separação de funções, controle de acesso, builds assinados, segredos com escopo de ambiente, **logs** à prova de adulteração, entre outros).
- Seus artefatos (garanta a integridade via proveniência, assinatura e carimbo de tempo; promova artefatos em vez de reconstruí-los para cada ambiente; garanta que os builds sejam imutáveis).
- Infraestrutura como código (gerenciada como qualquer código, incluindo o uso de PRs e controle de versão).

Cada organização deve garantir um plano contínuo para monitoramento, triagem e aplicação de atualizações ou mudanças de configuração durante toda a vida útil da aplicação ou portfólio.

## Exemplos de Cenários de Ataque

**Cenário #1:** Um fornecedor confiável é comprometido com malware, levando ao comprometimento dos seus sistemas de computador quando você realiza a atualização. O exemplo mais famoso disso é provavelmente:

- O comprometimento da SolarWinds em 2019, que levou ao comprometimento de aproximadamente 18.000 organizações. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**Cenário #2:** Um fornecedor confiável é comprometido de tal forma que se comporta de maneira maliciosa apenas sob uma condição específica.

- O roubo de US$ 1,5 bilhão da Bybit em 2025 foi causado por [um ataque à cadeia de suprimentos em um software de carteira (_wallet_)](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/) que só era executado quando a carteira alvo estava em uso.

**Cenário #3:** O [ataque à cadeia de suprimentos `Shai-Hulud`](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) em 2025 foi o primeiro verme (_worm_) npm autopropagável bem-sucedido. Os ataques inseriram versões maliciosas de pacotes populares, que utilizavam um script pós-instalação para coletar e exfiltrar dados sensíveis para repositórios públicos do GitHub. O malware também detectava **tokens** npm no ambiente da vítima e os utilizava automaticamente para publicar versões maliciosas de qualquer pacote acessível. O verme atingiu mais de 500 versões de pacotes antes de ser interrompido pelo npm. Este ataque foi avançado, de rápida propagação e danoso; ao visar máquinas de desenvolvedores, demonstrou que os próprios desenvolvedores são agora alvos principais em ataques de cadeia de suprimentos.

**Cenário #4:** Componentes normalmente rodam com os mesmos privilégios da própria aplicação, portanto, falhas em qualquer componente podem resultar em sério impacto. Tais falhas podem ser acidentais (ex: erro de codificação) ou intencionais (ex: um _backdoor_ em um componente). Alguns exemplos de vulnerabilidades exploráveis em componentes descobertos são:

- CVE-2017-5638, uma vulnerabilidade de execução remota de código (RCE) no Struts 2 que permite a execução de código arbitrário no servidor, sendo responsabilizada por violações significativas.
- CVE-2021-44228 ("Log4Shell"), uma vulnerabilidade de dia zero de execução remota de código no Apache Log4j, responsabilizada por campanhas de ransomware, mineração de criptomoedas e outros ataques.

## Referências

- [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
- [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
- [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
- [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
- [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
- [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
- OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
- [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
- [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
- [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov)
- [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
- [GitHub Advisory Database](https://github.com/advisories)
- Ruby Libraries Security Advisory Database and Tools
- [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
- [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
- [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)

## Lista de CWEs Mapeadas

- [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)
- [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)
- [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
- [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)
- [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
- [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
