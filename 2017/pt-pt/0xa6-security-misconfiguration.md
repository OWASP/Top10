# A6:2017 Más Configurações de Segurança

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 3 | Prevalência 3 \| Deteção 3 | Técnico 2 \| Negócio |
| Os atacantes tentam frequentemente aceder a contas por defeito, páginas não usadas, falhas não corrigidas, ficheiros e e directorias não protegidas, etc. para ganhar acesso não autorizado ou conhecimento do sistema. | Más configurações de segurança podem ocorrer em qualquer nível do stack aplicacional, incluindo a plataforma, servidor web, servidor aplicacional, base de dados, frameworks, e código customizado. Scanners automatizados são úteis na detecção de más configurações, uso de configurações ou contas por defeito, serviços desnecessários, opções legadas etc. | Tais falhas frequentemente dão aos atacantes acesso não autorizado a alguns dados ou funcionalidades do sistema. Ocasionalmente, tais falhas resultam no compromisso total do sistema. O impacto do negócio depende das necessidades de protecção da aplicação e dados. |

## Está a Aplicação Vulnerável?

Está a sua aplicação a necessitar de algum tipo de endurecimento de segurança em alguma das partes do stack da aplicação? Incluindo:

* Existem algumas funcionalidades activadas ou instaladas (p.e. portos, serviços, páginas, contas, privilégioss)?
* Existem contas por defeito e as suas passwords ainda estão activas e inalteradas?
* Será que a forma de tratamento de erros revela dados de execução do stack ou outra informação de erros demasiado detalhada para os utilizadores?
* Em sistemas actualizados, estão as últimas funcionalidades de segurança desactivadas ou não estão configuradas de forma segura?
* Estão as configurações de segurança nos seus servidores aplicacionais, frameworks aplicacionais (p.e. Struts, Spring, ASP.NET), bibliotecas, bases de dados, etc. não estabelecidas com valores seguros?
* Para aplicações web, será que o servidor não envia as directivas de segurança para os agentes do cliente (p.e. [Security Headers](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)) ou será que não estão estabelecidas com valores seguros?
* Está algum do seu software desactualizado? (see **A9:2017-Utilização de Componentes com Vulnerabilidades Conhecidas**).

Sem um processo de configuração de segurança concertado e repetível, os sistemas enfrentam maiores riscos de segurança.

## Como Prevenir?

Falta à sua aplicação o endurecimento de segurança apropriado em alguma parte do stack aplicacional? Incluindo:

* Um processo de endurecimento repetível que o torne rápido e facilmente replicável para ser usado num outro ambiente que está devidamente protegido. Ambientes de desenvolvimento, de qualidade e de produção devem estar configurados de igual forma, com credenciais diferentes usadas em cada ambiente. Este processo deve ser automatizado para minimizar o esforço necessário para configurar um novo ambiente seguro.
* Remover ou não instalar quaisquer funcionalidades, componentes, documentação ou exemplos que seja desnecessários. Remover dependências e frameworks não usadas.
* Um processo para efectuar uma triagem a aplicar todas as actualizações e correções de uma forma atempada para cada um dos ambientes estabelecidos. Este processo necessita de incluir todas as frameworks, dependências e bibliotecas (ver **A9:2017 Utilização de Componentes com Vulnerabilidades Conhecidas**).
* Uma arquitectura aplicacional forte que ofereça uma efectiva separação segura entre componentes, com segmentação, contentorização ou grupos de segurança cloud (ACLs).
* Um processo automatizado para verificar a eficiência das configurações e parameterizações em todos os ambientes.

## Exemplos de Cenários de Ataque

**Cenário #1**: A consola de administração do servidor aplicacional é automaticamente instalada e não é removida. O atacante descobre que as páginas de administração estão no servidor, entra com as palavras-chave por defeito, e assume o controlo.

**Cenário #2**: A listagem de directorias não está desactivada no seu servidor. Um atacante descobre que pode listar uma directoria para encontrar um determinado ficheiro. O atacante descobre e descarrega as suas classes Java compiladas, que podem ser depois ser alvo de engenharia reversa para obter o seu código fonte costumizado. Um atacante pode depois encontrar uma falha séria de controlo de acesso da aplicação que pode explorar.

**Cenário #3**: A configuração do servidor aplicacional permite que informação de execução do stack seja retornado para os utilizadores, potencialmente expondo falhas tais como versões de frameworks que são conhecidas por serem vulneráveis.

**Cenário #4**: O servidor aplicacional vem acompanhado com um conjunto de aplicações de exemplo que não foram removidas do servidor de produção. Estas aplicações de possuem falhas de segurança conhecidas que os atacantes podem usar para comprometer o servidor.

**Cenário #5**: A configuração por defeito ou uma configuração antiga copida activa versões ou opções antigas e vulneráveis de um protocolo que pode ser explorado por um atacante ou malware.


## Referências

### OWASP

* [OWASP Testing Guide: Configuration Management](https://www.owasp.org/index.php/Testing_for_configuration_management)
* [OWASP Testing Guide: Testing for Error Codes](https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

Para consultar requisitos adicionais nesta área, por favor consulte o [ASVS requirements areas for Security Configuration (V11 and V19)](https://www.owasp.org/index.php/ASVS).

### Externas

* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CWE Entry 2 on Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
