# A9:2017 Utilização de Componentes com Vulnerabilidades Conhecidas

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 2 | Prevalência 3 \| Detectabilidade 2 | Técnico 2 \| Negócio |
| Embora seja fácil encontrar explorações já escritas para muitas vulnerabilidades conhecidas, outras vulnerabilidades requerem esforço concentrado para desenvolver uma exploração personalizada. | A prevalência desta questão é muito difundida. Padrões de desenvolvimento de fortemente orientados a componentes podem levar as equipes de desenvolvimento a não entender quais componentes elas usam em sua aplicação ou API, quanto menos mantê-los atualizados. Alguns scanners, como retire.js ajudam na detecção, mas a determinação da vulnerabilidade requer esforço adicional. | Enquanto algumas vulnerabilidades conhecidas levam a apenas impactos menores, algumas das maiores brechas até agora se basearam em explorar vulnerabilidades conhecidas nos componentes. Dependendo dos ativos que você está protegendo, talvez esse risco esteja no topo da sua lista. |

## A Aplicação Está Vulnerável?

Você provavelmente está vulnerável:

* Se você não conhece as versões de todos os componentes que você usa (tanto do lado do cliente quanto do lado do servidor). Isso inclui componentes que você usa diretamente, bem como dependências aninhadas.
* Se algum dos seus softwares está desatualizado. Isso inclui o SO, Servidor Web/App, DBMS, aplicações, APIs e todos os componentes, ambientes de execução e bibliotecas.
* Se você não procura vulnerabilidades regularmente e se inscreve em boletins de segurança relacionados aos componentes que você usa.
* Se você não arruma ou atualiza a plataforma que utiliza, frameworks e dependências em tempo hábil. Isso geralmente acontece em ambientes onde atualização de patches é uma tarefa mensal ou trimestral sob controle de mudanças, o que deixa as organizações abertas para muitos dias ou meses de exposição desnecessária a vulnerabilidades já consertadas.
* Se você não mantém seguras as configurações dos componentes (veja **A6:2017-Configuração Incorreta de Segurança**).

## Como Prevenir

Projetos de software devem ter um processo para:

* Remover dependências não utilizadas, recursos desnecessários, componentes, arquivos e documentação.
* Manter continuamente um inventário das versões dos componentes do lado do cliente e do lado do servidor (por exemplo, frameworks, bibliotecas) e suas dependências usando ferramentas como *versions, DependencyCheck, retire.js*, etc.
* Monitorar continuamente fontes como CVE e NVD para vulnerabilidades em seus componentes. Use ferramentas de análise de composição de software para automatizar o processo. Assine os alertas de e-mails para vulnerabilidades de segurança relacionadas aos componentes que você usa.
* Obtenha seus componentes apenas de fontes oficiais e, quando possível, prefira pacotes assinados para reduzir a chance de obter um componente malicioso modificado.
* Monitore bibliotecas e componentes que não são mantidos ou não tem mais patches de segurança para versões mais antigas. Se o patch não for possível, considere implantar um patch virtual para monitorar, detectar ou proteger contra o problema descoberto.

Toda organização deve garantir que haja um plano contínuo de monitoramento, triagem e aplicação de atualizações ou mudanças de configuração para toda a vida da aplicação ou portfólio.

## Exemplos de Cenários de Ataque

**Cenário #1**: Componentes tipicamente são executados com os mesmos privilégios da própria aplicação, portanto, falhas em qualquer componente podem resultar em impacto sério. Tais falhas podem ser acidentais (por exemplo, erro de codificação) ou intencional (por exemplo, *backdoor* no componente). Alguns exemplos de vulnerabilidades de componentes exploráveis descobertos são:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), uma vulnerabilidade de execução remota de código no Struts 2 que permite a execução de código arbitrário em o servidor, foi culpado por brechas significativas.
* Enquanto [a internet das coisas (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) são freqüentemente difíceis ou impossíveis de corrigir, a importância de corrigi-los pode ser grande (por exemplo: [marca-passos de St. Jude](https://arstechnica.com/information-technology/2017/08/465k-patients-need-a-firmware-update-to-prevent-serious-pacemaker-hacks/)).

Existem ferramentas automatizadas para ajudar os invasores a encontrar sistemas não corrigidos ou mal configurados. Por exemplo, o [mecanismo de busca de IoT Shodan](https://www.shodan.io/report/89bnfUyJ) pode ajudá-lo a encontrar dispositivos que ainda sofrem com a vulnerabilidade [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) que foi corrigida em abril de 2014.

## Referências

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://www.owasp.org/index.php/ASVS)
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Externas

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
