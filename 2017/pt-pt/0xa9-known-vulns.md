# A9:2017 Utilização de Componentes com Vulnerabilidades Conhecidas

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 2 | Prevalência 3 \| Deteção 2 | Técnico 2 \| Negócio |
| Enquanto é fácil encontrar exploits já escritos para muitas vulnerabilidades conhecidas, outras vulnerabilidades requerem um esforço concentrado para o desenvolvimento de um exploit especializado. | A prevalência deste tipo de situação é bastante abrangente. Padrões de desenvolvimento fortemente baseados em componentes podem causar que as equipas de desenvolvimento nem percebam quais os componentes que usam nas suas aplicações ou API, quanto mais manter os  mesmos devidamente actualizados. Este problema pode ser detectado pela utilização de scanners tais como o retire.js e através da inspeção dos caçalhos, no entanto verificar se os mesmos podem ser explorados requer um ataque e alguma descrição. | Enquanto algumas vulnerabilidades conhecidas podem levar a impactos menores, algumas das principais ataques até à data dependeram da exploração de vulnerabilidades em componentes. Dependendo dos activos que necessita de proteger, provavelmente este risco precisa de estar no topo da sua lista. |

## Está a Aplicação Vulnerável?

Estará vulnerável:

* Se não souber as versões de todos os componentes que usa (tanto do lado do cliente como do lado do servidor). Isto inclui compontes que usa directamente assim como as suas dependências.
* Está algum do software desactualizado? Isto inclui o SO, Servidor Web e Aplicacional, Servidor de Gestão de Bases de Dados, aplicações, APIs e todos os componentes, ambientes de execução e bibliotecas.
* Se não souber se as mesmas são vulneráveis. Ou por um lado não procura esta informação ou não efectua pesquisas de análises de vulnerabilidades de forma regular.
* Se não corrigir ou actualizar a plataforma subjacente, as frameworks e dependências de uma forma If you do not fix or upgrade the underlying platform, frameworks and dependencies em tempo útil. Isto acontece frequentemente em ambientes em que a realização das correções são uma tarefa realizada mensalmente ou trimestralmente, o que leva a que a organização fique exposta a muitos dias ou meses de exposição desnecessária as vulnerabilidades que entretanto já foram corrigidas. Esta é na verdade uma das principais causas que levou à maior reveleção de informação não autorizada de todos os tempos. 
* Se não garantir a segurança das configurações dos componentes (ver **A6:2017-Más Configurações de Segurança**).

## Como Prevenir?

Os projectos de software devem um processo estabelecido para:

* Remover dependências não-usadas, funcionalidades desnecessárias, componentes, ficheiros e documentação.
* Inventariação contínua das versões dos componentes tanto do lado cliente como do lado do servidor e das suas dependências usando ferramentas como o  [versions](http://www.mojohaus.org/versions-maven-plugin/), [DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/), entre outras.
* Monitorizar continuamente fontes de informação como o [CVE](https://cve.mitre.org/) e [NVD](https://nvd.nist.gov/) por vulnerabilidades nos componentes. Usar ferramentas de análise de composição de software para automatizar o processo.
* Apenas obter os componentes das fontes oficiais e, quando possível, preferir os pacotes assinados para reduzir a hipótese de obter uma versão de um componente que tenha sido modificado ou seja malicioso.
* Muitas bibliotecas e componentes não criam actualizações de segurança para versões antigas, ou são simplesmente não mantidos. Se não for possível efectuar correções de segurança, consider aplicar uma [actualização virtual](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F) para monitorar, detectar ou proteger contra um problema descoberto.

Cada organização deve assegurar que existe um plano para monitorizar, efectuar a triagem, e aplicar as actualizações ou alterações de configurações durante o tempo de vida da aplicação ou do conjunto de aplicações.

## Exemplos de Cenários de Ataque

Os componentes são tipicamente executados com os mesmos privilégios da própria aplicação, por isso as falhas nos componentes podem resultar num impacto sério na aplicação. Tais falhas podem ser acidentais (por exemplo, erro de codificação) ou intencionais (por exemplo, um backdoor num componente). Alguns exemplos de vulnerabilidades em componentes que podem ser exploradas são:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), uma vulnerabilidade de execução remota de código na Struts 2 que permite a execução remota de código arbitrário no servidor, tem sido responsável por significativas revelações não autorizadas de dados.
* Enquanto falhas na [Internet das Coisas (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) são frequentemente difíceis ou impossíveis de corrigir, a importância de as corrigir é muito significativa (por exemplo, [pacemakers de St. Jude](https://arstechnica.com/information-technology/2017/08/465k-patients-need-a-firmware-update-to-prevent-serious-pacemaker-hacks/)).

Existem ferramentas automáticas que ajudam os atacantes a encontrarem sistemas mal configurados ou que não estejam devidamente actualizados. Por exemplo, o [motor de busca Shodan](https://www.shodan.io/report/89bnfUyJ) pode ajudar a encontrar dispositivos que ainda são vulneráveis ao [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) que foi corrigida em Abril de 2014.

## Referências

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://www.owasp.org/index.php/ASVS)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### Externas

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
