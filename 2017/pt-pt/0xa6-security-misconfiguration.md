# A6:2017 Configurações de Segurança Incorretas


| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 3 | Prevalência: 3 \| Deteção: 3 | Técnico: 2 \| Negócio ? |
| Os atacantes tentam frequentemente aceder a contas padrão, páginas não usadas, falhas não corrigidas, ficheiros e diretórios não protegidos, etc. para ganhar acesso não autorizado ou conhecimento do sistema. | Más configurações de segurança podem ocorrer em qualquer nível da camada aplicacional, incluindo serviços de comunicação, plataforma, servidor web, servidor aplicacional, base de dados, frameworks, código personalizado e máquinas virtuais pré-instaladas, containers ou armazenamento. Scanners automatizados são úteis na deteção de más configurações, uso de configurações ou contas padrão, serviços desnecessários, opções herdadas etc. | Tais falhas concedem frequentemente aos atacantes acesso não autorizado a alguns dados ou funcionalidades do sistema. Ocasionalmente, tais falhas fazem com que o sistema seja completamente comprometido. O impacto no negócio depende das necessidades de protecção da aplicação e dados. |

## A Aplicação é Vulnerável?

A aplicação pode ser vulnerável se:

- Estão em falta medidas apropriadas de segurança em alguma parte da camada
  aplicacional.
- Funcionalidades desnecessárias estão ativas ou instaladas (e.g. portos de
  comunicação desnecessários, serviços, páginas, contas ou privilégios).
- Existem contas padrão e as suas palavras-passe ainda estão ativas e
  inalteradas.
- A rotina de tratamento de erros revela informação de execução (_stack trace_)
  ou outras mensagens que incluam detalhe excessivo para os utilizadores.
- Em sistemas atualizados, as últimas funcionalidades de segurança encontram-se
  desativadas ou configuradas de forma insegura.
- As definições de segurança nos servidores aplicacionais, _frameworks_ (e.g.
  Struts, Spring, ASP.NET), bibliotecas de código, base de dados, etc., não usam
  valores seguros.
- O servidor não inclui cabeçalhos ou diretivas de segurança nas respostas ou
  estas não usam valores seguros.
- O software está desatualizado ou vulnerável (ver [A9:2017 Utilização de
  Componentes Vulneráveis][0xa61]).

Sem manutenção corretiva e um processo de aplicação de definições de segurança
reprodutível os sistemas apresentam um risco mais elevado.

## Como Prevenir

Processos de instalação seguros devem ser implementados, incluindo:

- Um processo automatizado e reprodutível de robustecimento do sistema, que
  torne fácil e rápido criar um novo ambiente devidamente seguro. Ambientes de
  desenvolvimento, qualidade e produção devem ser configurados de forma
  semelhante com credenciais específicas por ambiente.
- A plataforma mínima necessária, sem funcionalidades desnecessárias,
  componentes, documentação ou exemplos. Remover ou não instalar funcionalidades
  que não são usadas bem como frameworks.
- Uma tarefa para rever e atualizar as configurações de forma adequada e de
  acordo com as notas de segurança, atualizações e correções como parte do
  processo de gestão de correções (ver [A9:2017 Utilização de Componentes com
  Vulnerabilidades Conhecidas][0xa61]).
- Uma arquitetura aplicacional segmentada que garanta uma separação efetiva e
  segura entre os componentes ou módulos, com segmentação, utilização de
  containers ou grupos de segurança cloud (Access Control List (ACL)).
- Envio de diretivas de segurança para o agente dos clientes e.g. _Security
  Headers_.
- Um processo automatizado para verificação da eficácia das configurações e
  definições em todos os ambientes.

## Exemplos de Cenários de Ataque

**Cenário #1**: O servidor aplicacional inclui aplicações de demonstração que
não são removidas do servidor de produção. Para além de falhas de segurança
conhecidas que os atacantes usam para comprometer o servidor, se uma destas
aplicações for a consola de administração e as contas padrão não tiverem sido
alteradas, o atacante consegue autenticar-se usando a palavra-passe padrão,
ganhando assim o controlo do servidor.

**Cenário #2**: A listagem de diretorias não está desativada no servidor. O
atacante encontra e descarrega a sua classe Java compilada, revertendo-a para
ver o código e assim identificar outras falhas graves no controlo de acessos da
aplicação.

**Cenário #3**: A configuração do servidor aplicacional gera mensagens de erro
detalhadas incluindo, por exemplo, informação de execução (_stack trace_). Isto
expõe potencialmente informação sensível ou falhas subjacentes em versões de
componentes reconhecidamente vulneráveis.

**Cenário #4**: As permissões de partilha dum fornecedor de serviços Cloud
permitem, por omissão, o acesso a outros utilizadores do serviço via Internet.
Isto permite o acesso a dados sensíveis armazenados nesse serviço Cloud.

## Referências

### OWASP

- [OWASP Testing Guide: Configuration Management][0xa62]
- [OWASP Testing Guide: Testing for Error Codes][0xa63]
- [OWASP Security Headers Project][0xa64]

Para requisitos adicionais nesta área, por favor consulte o [ASVS requirements
areas for Security Configuration (V11 and V19)][0xa65].

### Externas

- [NIST Guide to General Server Hardening][0xa66]
- [CWE Entry 2 on Environmental Security Flaws][0xa67]
- [CWE-16: Configuration][0xa68]
- [CWE-388: Error Handling][0xa69]
- [CIS Security Configuration Guides/Benchmarks][0xa610]
- [Amazon S3 Bucket Discovery and Enumeration][0xa611]

[0xa61]: ./0xa9-known-vulns.md
[0xa62]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README
[0xa63]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README
[0xa64]: https://owasp.org/www-project-secure-headers/
[0xa65]: https://owasp.org/www-project-application-security-verification-standard/
[0xa66]: https://csrc.nist.gov/publications/detail/sp/800-123/final
[0xa67]: https://cwe.mitre.org/data/definitions/2.html
[0xa68]: https://cwe.mitre.org/data/definitions/16.html
[0xa69]: https://cwe.mitre.org/data/definitions/388.html
[0xa610]: https://www.cisecurity.org/cis-benchmarks/
[0xa611]: https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html

