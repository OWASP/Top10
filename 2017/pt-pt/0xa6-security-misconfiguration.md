# A6:2017 Más Configurações de Segurança

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Abuso 3 | Prevalência 3 \| Deteção 3 | Técnico 2 \| Negócio |
| Os atacantes tentam frequentemente aceder a contas padrão, páginas não usadas, falhas não corrigidas, ficheiros e diretorias não protegidas, etc. para ganhar acesso não autorizado ou conhecimento do sistema. | Más configurações de segurança podem ocorrer em qualquer nível da camada aplicacional, incluindo serviços de comunicação, plataforma, servidor web, servidor aplicacional, base de dados, _frameworks_, código customizado e máquinas virtuais pré-instaladas, _containers_ ou armazenamento. Scanners automatizados são úteis na detecção de más configurações, uso de configurações ou contas padrão, serviços desnecessários, opções herdadas etc. | Tais falhas concedem frequentemente aos atacantes acesso não autorizado a alguns dados ou funcionalidades do sistema. Ocasionalmente, tais falhas fazem com que o sistema seja completamente comprometido. O impacto no negócio depende das necessidades de protecção da aplicação e dados. |

## A Aplicação é Vulnerável?

A aplicação pode ser vulnerável se:

* Estão em falta medidas apropriadas de segurança em alguma parte da camada
  aplicacional.
* Funcionalidades desnecessárias estão ativas ou instaladas (e.g. portas de
  comunicação desnecessárias, serviços, páginas, contas ou privilégios).
* Existem contas padrão e as suas passwords ainda estão ativas e inalteradas.
* O rotina de tratamento de erros revela informação de execução (_stack trace_)
  ou outras mensagens que incluam detalhe excessivo para os utilizadores.
* Em sistemas atualizados, as últimas funcionalidades de segurança encontram-se
  desativadas ou configuradas de forma insegura.
* As definições de segurança nos servidores aplicacionais, _frameworks_ (e.g.
  Struts, Spring, ASP.NET), bibliotecas de código, base de dados, etc., não usam
  valores seguros.
* O servidor não inclui cabeçalhos ou diretivas de segurança nas respostas ou
  estas não usam valores seguros.
* O software está desatualizado ou vulnerável (ver **A9:2017 Utilização de
  Componentes com Vulnerabilidades Conhecidas**). Sem manutenção corretiva e um
  processo de aplicação de definições de segurança reprodutível os sistemas
  apresentam um risco mais elevado.

## Como Prevenir?

Processos de instalação seguros devem ser implementados, incluindo:

* Um processo reprodutível de robustecimento do sistema, que torne fácil e
  rápido criar um novo ambiente que esteja devidamente seguro.
  Ambientes de desenvolvimento, qualidade e produção devem todos estar
  configurados de forma semelhante com diferentes credências para cada ambiente.
  Este processo deve ser automatizado para minimizar o esforço necessário para
  configurar um novo ambiente seguro.
* A plataforma mínima necessária, sem funcionalidades desnecessárias,
  componentes, documentação ou exemplos. Remover ou não instalar funcionalidaes
  que não são usadas bem como _frameworks_.
* Uma tarefa para rever e atualizar as configurações de forma adequada e de
  acordo com as notas de segurança, atualizações e correções como parte do
  processo de gestão de correções (ver **A9:2017 Utilização de Componentes com
  Vulnerabilidades Conhecidas**).
* Uma arquitetura aplicacional segmentada que garanta uma separação efetiva e
  segura entre os componentes ou módulos, com segmentação, utilização de
  _containers_ ou grupos de segurança _cloud_ (Access Control List (ACL)).
* Envio de diretivas de segurança para o agente dos clientes e.g. [Security
  Headers][1].
* Um processo automatizado para verificação da eficácia das configurações e
  definições em todos os ambientes.

## Exemplos de Cenários de Ataque

**Cenário #1**: O servidor aplicacional vem com aplicações de demonstração que
não são removidas do servidor de produção. Estas aplicações de demonstração têm
falhas de segurança conhecidas que os atacantes usam para comprometer o
servidor. Se uma destas aplicações for a consola de administração e as contas
padrão não tiverem sido alteradas, o atacante consegue autenticar-se usando a
_password_ padrão, ganhando assim o controlo do servidor.

**Cenário #2**: A listagem de diretorias não está desativada no seu servidor.
Um atacante descobre que pode listar uma diretoria. O atacante encontra e
descarrega a sua classe Java compilada, revertendo-a para ver o seu código.
Assim o atacante pode identificar outras falhas graves no controlo de acessos da
sua aplicação.

**Cenário #3**: A configuração do servidor aplicacional gera mensagens de
erro detalhadas incluíndo, por exemplo, informação de execução (_stack trace_).
Isto expõe potencialmente informação sensível ou falhas subjacentes em versões
de componentes reconhecidamente vulneráveis.

**Cenário #4**: A configuração padrão ou uma configuração antiga copiada, ativa
versões ou opções antigas e vulneráveis de um protocolo que pode ser abusado por
um atacante ou malware.

## Referências

### OWASP

* [OWASP Testing Guide: Configuration Management][2]
* [OWASP Testing Guide: Testing for Error Codes][3]
* [OWASP Security Headers Project][1]

Para requisitos adicionais nesta área, por favor consulte o [ASVS requirements
areas for Security Configuration (V11 and V19)][4].

### Externas

* [NIST Guide to General Server Hardening][5]
* [CWE Entry 2 on Environmental Security Flaws][6]
* [CIS Security Configuration Guides/Benchmarks][7]

[1]: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
[2]: https://www.owasp.org/index.php/Testing_for_configuration_management
[3]: https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006)
[4]: https://www.owasp.org/index.php/ASVS
[5]: https://csrc.nist.gov/publications/detail/sp/800-123/final
[6]: https://cwe.mitre.org/data/definitions/2.html
[7]: https://www.cisecurity.org/cis-benchmarks/

