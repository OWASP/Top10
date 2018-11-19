# A9:2017 Utilização de Componentes com Vulnerabilidades Conhecidas

| Agentes de Ameaça /Vetores de ataque | Fraquezas de Segurança     | Impactos               |
| -- | -- | -- |
| Nível de acesso : Exploração 2 | Prevalência 3 : Deteção 2 | Técnico 2 : Negócio |
| Apesar de ser fácil encontrar ferramentas que já exploram vulnerabilidades conhecidas, algumas vulnerabilidades requerem um esforço superior no sentido de desenvolver uma forma individual de as explorar.  | Este problema continua a prevalecer de forma generalizada. Padrões de desenvolvimento, que focam na utilização extensiva de componentes, podem levar a que as equipas de desenvolvimento não percebam que componentes devem utilizar na sua aplicação ou API. Algumas ferramentas de deteção como *retire.js* ajudam na tarefa de deteção destes casos, no entanto a deteção da exploração de vulnerabilidades requer esforço adicional.  | Enquanto algumas das vulnerabilidades mais conhecidas têm um impacto reduzido, algumas das maiores falhas de segurança, até à data, assentaram na exploração destas vulnerabilidades conhecidas, em componentes.  |

## A Aplicação está Vulnerável?

Provavelmente você está vulnerável:

* Se não conhecer as versões de todos os componentes que utiliza (tanto no âmbito do cliente como no servidor). Isto engloba componentes que utiliza diretamente, bem como as suas dependências.
* Se o *software* é vulnerável, deixou de ser suportado, ou está desatualizado. Isto inclui o SO, servidor web ou da aplicação, base de dados, sistemas de gestão (DBMS), aplicações, APIs e todos os componentes, ambientes de execução, e bibliotecas.
* Se você não examinar regularmente os componentes que utiliza quanto à presença de vulnerabilidades e não subscrever relatórios de segurança relacionados com os mesmos.
* Se não corrigir ou atualizar a plataforma base, *frameworks*, e dependências de forma oportuna numa abordagem baseada no risco. Isto é um padrão comum em ambientes nos quais novas versões são lançadas mensalmente ou trimestralmente, levando a que as organizações fiquem expostas à exploração de vulnerabilidades já corrigidas, durante dias ou meses.
* Se os desenvolvedores de *software* não testarem a compatibilidade com a atualização de bibliotecas corrigidas.
* Se não garantir a segurança das configurações dos componentes (referência **A6:2017-Security Misconfiguration**).

## Como Prevenir

Deve existir um processo de gestão de correções e atualizações, que:

* Remova dependências não utilizadas assim como funcionalidades, componentes, ficheiros, e documentação, desnecessários.
* Realize um inventário das versões dos componentes ao nível do cliente e do servidor (ex. *frameworks*, bibliotecas) e das suas dependências, através da utilização de ferramentas como *versions*,  *DependencyCheck*, *retire.js*, etc.
* Monitorize, regularmente, fontes de informação como o CVE e o NVD, em busca de vulnerabilidades em componentes. Utilize *software* de análise de forma a automatizar o processo. Subscreva alertas, via e-mail, de vulnerabilidades de segurança relacionadas com componentes utilizados.
* Apenas obtenha componentes de fontes oficiais através de ligações seguras. Dê preferência a pacotes assinados, de forma a reduzir a probabilidade de obter um componente modificado ou malicioso. 
* Monitorize bibliotecas e componentes que não sofram manutenção ou cujas versões antigas não são alvo de atualizações de segurança.
  
Cada organização deve assegurar que possui um plano ativo que vise a monitorização, triagem, e aplicação de atualizações ou mudanças na configuração da aplicação ou portefólio, ao longo do seu ciclo de vida.

## Exemplos de Cenários de Ataque

**Cenário #1**: Tipicamente, os componentes executam com os mesmos privilégios da aplicação onde se inserem, portanto quaisquer vulnerabilidades nos componentes podem resultar num impacto sério. Falhas deste tipo podem ser acidentais (ex. erro de programação) ou intencional (ex. *backdoor* no componente). Exemplos de exploração de vulnerabilidades em componentes são:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), a execução remota de código relacionado com uma vulnerabilidade Struts 2, a qual permite a execução de código arbitrário no servidor, foi responsável por várias quebras de segurança graves.
* Enquanto que redes como [Internet of Things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) continuam a ser frequentemente difíceis ou impossíveis de corrigir, a importância de as corrigir é fundamental (ex. dispositivos biomédicos).

Existem ferramentas automáticas que ajudam os atacantes a encontrar sistemas mal configuradas ou com erros. Por exemplo, o [motor de busca Shodan](https://www.shodan.io/report/89bnfUyJ) pode ajudar a facilmente encontrar dispositivos que possam ainda estar vulneráveis a [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed), vulnerabilidade esta que já foi corrigida em Abril de 2014.



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
