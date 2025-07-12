# A06:2021 – Componentes Vulneráveis e Desatualizados    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:-------------------------:|:------------------------:|:--------------------------:|:-----------------------:|:----------------:|:---------------:|:--------------------:|:-------------:|
| 3             | 27.96%                    | 8.77%                    | 51.78%                     | 22.47%                  | 5.00             | 5.00            | 30,457               | 0             |

## Visão Geral

Foi o segundo colocado na pesquisa da comunidade do Top 10, mas também tinha
dados suficientes para chegar ao Top 10 por meio da análise de dados.
Componentes vulneráveis são um problema conhecido que nós lutamos para
testar e avaliar o risco e é a única categoria que não tem nenhuma
_Common Weakness Enumerations_ (CWEs) mapeada para os CWEs incluídos,
então um _exploits_/impacto padrão de 5.0 é usado. Os CWEs notáveis
incluídos são *CWE-1104: Uso de Componentes de Terceiros não Mantidos*
e os dois CWEs dos Top 10 de 2013 e 2017.

## Descrição 

Você provavelmente está vulnerável:

- Se você não souber as versões de todos os componentes que usa
    (tanto do lado do cliente quanto do lado do servidor). Isso
    inclui componentes que você usa diretamente, bem como
    dependências aninhadas.

- Se o software for vulnerável, sem suporte ou desatualizado.
    Isso inclui o sistema operacional, servidor _web/application_,
    sistema de gerenciamento de banco de dados (DBMS), aplicações,
    APIs e todos os componentes, ambientes de tempo de execução e bibliotecas.

- Se você não faz a varredura de vulnerabilidades regularmente e
    não assina os boletins de segurança relacionados aos componentes que você usa.

- Se você não corrigir ou atualizar a plataforma, as estruturas e as dependências
    subjacentes de maneira oportuna e baseada em riscos. Isso geralmente acontece
    em ambientes em que a correção é uma tarefa mensal ou trimestral sob controle
    de alterações, deixando as organizações abertas a dias ou meses de exposição
    desnecessária a vulnerabilidades corrigidas.

- Se os desenvolvedores de software não testarem a compatibilidade de
   bibliotecas atualizadas, atualizações ou com patches.

- Se você não proteger as configurações dos componentes
    (consulte [A05: 2021-Configuração Incorreta de Segurança](A05_2021-Security_Misconfiguration.pt_BR.md)).

## Como Prevenir

Deve haver um processo de gerenciamento de dependências para:

- Remova dependências não utilizadas, recursos, componentes, arquivos
    e documentação desnecessários.

- Atualizar continuamente um inventário com as versões dos componentes
    do lado do cliente e do lado do servidor (por exemplo, estruturas,
    bibliotecas) e suas dependências usando ferramentas como _versions_,
    _OWASP Dependency Check_, _retire.js_, etc. Monitore continuamente fontes
    como _Common Vulnerability and Exposures_ (CVE) e _National Vulnerability
    Database_ (NVD) para vulnerabilidades nos componentes. Use ferramentas
    de análise de composição de software para automatizar o processo.
    Inscreva-se para receber alertas de e-mail sobre vulnerabilidades de
    segurança relacionadas aos componentes que você usa.

- Obtenha componentes apenas de fontes oficiais por meio de links seguros.
    Prefira pacotes assinados para reduzir a chance de incluir um componente
    malicioso modificado (consulte
    [A08: 2021-Software e Falhas de Integridade de Dados](A08_2021-Software_and_Data_Integrity_Failures.pt_BR.md)).

- Monitore bibliotecas e componentes sem manutenção ou que não criem patches
    de segurança para versões anteriores. Se o patch não for possível,
    considere implantar um patch virtual para monitorar, detectar ou proteger
    contra o problema descoberto.

Cada organização deve garantir um plano contínuo de monitoramento, triagem e
aplicação de atualizações ou alterações de configuração durante a vida
útil da aplicação ou portfólio.

## Exemplos de Cenários de Ataque

**Cenário #1:** Os componentes normalmente são executados com os mesmos
privilégios da própria aplicação, portanto, as falhas em qualquer componente
podem resultar em sério impacto. Essas falhas podem ser acidentais
(por exemplo, erro de codificação) ou intencionais (por exemplo, uma
_backdoor_ em um componente). Alguns exemplos de vulnerabilidades
de componentes exploráveis descobertos são:

- CVE-2017-5638, uma vulnerabilidade de execução remota de código
    do Struts 2 que permite a execução de código arbitrário no servidor,
    foi responsabilizada por violações significativas.

- Embora a Internet das Coisas (IoT) seja frequentemente difícil ou
    impossível de corrigir, a importância de corrigi-los pode ser
    grande (por exemplo, dispositivos biomédicos).

Existem ferramentas automatizadas para ajudar os invasores a encontrar
sistemas não corrigidos ou configurados incorretamente. Por exemplo,
o mecanismo de pesquisa Shodan IoT pode ajudá-lo a encontrar
dispositivos que ainda sofrem com a vulnerabilidade Heartbleed
corrigida em abril de 2014.

## Referências

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## Lista dos CWEs Mapeados

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
