# A9:2017 Utilização de Componentes Vulneráveis

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 2 | Prevalência: 3 \| Deteção: 2 | Técnico: 2 \| Negócio ? |
| Apesar de ser fácil encontrar ferramentas que já exploram vulnerabilidades conhecidas, algumas vulnerabilidades requerem um esforço superior no sentido de desenvolver uma forma individual de as explorar. | Este problema continua a prevalecer de forma generalizada. Padrões de desenvolvimento, que focam na utilização extensiva de componentes, podem levar a que as equipas de desenvolvimento não percebam que componentes devem utilizar na sua aplicação ou API. Algumas ferramentas como retire.js ajudam na tarefa de deteção destes casos, no entanto o abuso destas vulnerabilidades requer esforço adicional. | Enquanto algumas das vulnerabilidades mais conhecidas têm um impacto reduzido, algumas das maiores falhas de segurança, até à data, assentaram na exploração destas vulnerabilidades conhecidas, em componentes. |

## A Aplicação é Vulnerável?

A aplicação pode ser vulnerável se:

* Não conhecer as versões de todos os componentes que utiliza (tanto no âmbito
  do cliente como no servidor). Isto engloba componentes que utiliza
  diretamente, bem como as suas dependências.
* O software é vulnerável, deixou de ser suportado, ou está desatualizado. Isto
  inclui o SO, servidor web ou da aplicação, sistemas de gestão de base de dados
  (SGBDs), aplicações, APIs e todos os componentes, ambientes de execução, e
  bibliotecas.
* Não examinar regularmente os componentes que utiliza quanto à presença de
  vulnerabilidades e não subscrever relatórios de segurança relacionados com os
  mesmos.
* Não corrigir ou atualizar a plataforma base, frameworks e dependências de
  forma oportuna numa abordagem baseada no risco. Isto é um padrão comum em
  ambientes nos quais novas versões são lançadas mensalmente ou trimestralmente,
  levando a que as organizações fiquem expostas à exploração de vulnerabilidades
  já corrigidas, durante dias ou meses.
* Os programadores não testarem a compatibilidade com as novas versões,
  atualizações ou correções das bibliotecas.
* Não garantir a segurança das configurações dos componentes (ver
  [A6:2017-Configurações de Segurança Incorretas][0xa91]).

## Como Prevenir

O processo de gestão de correções e atualizações deve:

* Remover dependências não utilizadas assim como funcionalidades, componentes,
  ficheiros e documentação desnecessários.
* Realizar um inventário das versões dos componentes ao nível do cliente e do
  servidor (ex. _frameworks_, bibliotecas) e das suas dependências, usando para
  isso ferramentas como [versions][0xa92], [DependencyCheck][0xa93],
  [retire.js][0xa94], etc. Monitorize regularmente fontes como [Common
  Vulnerabilities and Exposures][0xa95] (CVE) e [National Vulnerability
  Database][0xa6] (NVD) em busca de vulnerabilidades em componentes.
  Automatize o processo. Subscreva alertas via e-mail sobre vulnerabilidades de
  segurança relacionadas com componentes utilizados.
* Obter componentes apenas de fontes oficiais e através de ligações seguras,
  preferindo pacotes assinados de forma a mitigar componentes modificados ou
  maliciosos.
* Monitorizar bibliotecas e componentes que não sofram manutenção ou cujas
  versões antigas não são alvo de atualizações de segurança. Considere aplicar
  [correções virtuais][0xa97] quando necessário.

As organizações deve manter um plano ativo de monitorização, triagem e aplicação
de atualizações ou mudanças na configuração das aplicações ao longo do ciclo de
vida.

## Exemplos de Cenários de Ataque

**Cenário #1**: Tipicamente os componentes executam com os mesmos privilégios da
aplicação onde se inserem, portanto quaisquer vulnerabilidades nos componentes
podem resultar num impacto sério. Falhas deste tipo podem ser acidentais (ex.
erro de programação) ou intencional (ex. _backdoor_ no componente). Exemplos de
abuso de vulnerabilidades em componentes são:

* [CVE-2017-5638][0xa98], a execução remota de código relacionado com uma
  vulnerabilidade Struts 2, a qual permite a execução de código arbitrário no
  servidor, foi responsável por várias quebras de segurança graves.
* Apesar da dificuldade é imperativo manter redes como [Internet of Things
  \(IoT\)][0xa99] atualizadas (ex. dispositivos biomédicos).

Existem ferramentas automáticas que ajudam os atacantes a encontrar sistemas mal
configurados ou com erros. Por exemplo, o motor de busca Shodan pode ajudar a
facilmente [encontrar dispositivos][0xa910] que possam ainda estar vulneráveis a
[Heartbleed][0xa911], vulnerabilidade esta que já foi corrigida em Abril de
2014.

## Referências

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and
  threat modelling][0xa912]
* [OWASP Dependency Check (for Java and .NET libraries)][0xa913]
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)][0xa914]
* [OWASP Virtual Patching Best Practices][0xa915]

### Externas

* [The Unfortunate Reality of Insecure Libraries][0xa916]
* [MITRE Common Vulnerabilities and Exposures (CVE) search][0xa917]
* [National Vulnerability Database (NVD)][0xa918]
* [Retire.js for detecting known vulnerable JavaScript libraries][0xa919]
* [Node Libraries Security Advisories][0xa920]
* [Ruby Libraries Security Advisory Database and Tools][0xa921]

[0xa91]: 0xa6-security-misconfiguration.md
[0xa92]: http://www.mojohaus.org/versions-maven-plugin/
[0xa93]: https://owasp.org/www-project-dependency-check/
[0xa94]: https://github.com/retirejs/retire.js/
[0xa95]: https://cve.mitre.org/
[0xa96]: https://nvd.nist.gov/
[0xa97]: https://owasp.org/www-community/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F
[0xa98]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
[0xa99]: https://en.wikipedia.org/wiki/Internet_of_things
[0xa910]: https://www.shodan.io/
[0xa911]: https://en.wikipedia.org/wiki/Heartbleed
[0xa912]: https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x10-V1-Architecture.md
[0xa913]: https://owasp.org/www-project-dependency-check/
[0xa914]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture
[0xa915]: https://owasp.org/www-community/Virtual_Patching_Best_Practices
[0xa916]: https://cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf
[0xa917]: https://www.cvedetails.com/version-search.php
[0xa918]: https://nvd.nist.gov/
[0xa919]: https://github.com/retirejs/retire.js/
[0xa920]: https://nodesecurity.io/advisories
[0xa921]: https://rubysec.com/

