# A6:2017 Configuração Incorreta de Segurança

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 3 | Prevalência 3 \| Detectabilidade 3 | Técnico 2 \| Negócio |
| Atacantes geralmente tentarão acessar contas padrão, páginas não utilizadas, falhas não corrigidas, arquivos e diretórios desprotegidos, etc., para obter acesso não autorizado ou conhecimento do sistema. | A configuração incorreta da segurança pode acontecer em qualquer nível das camadas da aplicação, incluindo serviços de rede, plataforma, servidor web, servidor de aplicativos, banco de dados, estruturas, código personalizado e máquinas virtuais, de contêineres ou de armazenamento pré-instaladas. Os scanners automatizados são úteis para detectar configurações erradas, uso de contas ou configurações padrão, serviços desnecessários, opções legadas etc. | Tais falhas freqüentemente dão aos atacantes acesso não autorizado a alguns dados ou funcionalidades do sistema. Ocasionalmente, tais falhas resultam em um comprometimento total do sistema. O impacto comercial depende das necessidades de proteção de sua aplicação e dados. |

## A Aplicação Está Vulnerável?

A aplicação pode ser vulnerável se:
* Falta endurecimento de segurança adequado em qualquer parte das camadas da aplicação.
* Recursos desnecessários são habilitados ou instalados (por exemplo, portas, serviços, páginas, contas ou privilégios desnecessários).
* As contas padrão e suas senhas ainda são ativadas e inalteradas.
* O tratamento de erros revela vestígios de *stacktraces* ou outras mensagens de erro excessivamente informativas aos usuários.
* Para sistemas atualizados, os recursos de segurança mais recentes estão desativados ou não estão configurados de forma segura.
* As configurações de segurança nos servidores de aplicação, frameworks de aplicação (por exemplo, Struts, Spring, ASP.NET), bibliotecas, bancos de dados, etc., não configurados para valores seguros.
* O servidor não envia cabeçalhos ou diretivas de segurança ou não está configurado para valores seguros.
* O software está desatualizado ou vulnerável (consulte **A9:2017-Utilização de Componentes com Vulnerabilidades Conhecidas**). 
Sem um processo planejado e repetido de configuração de segurança de aplicações, os sistemas estão em maior risco.

## Como Prevenir

Processos de instalação segura devem ser implementados, incluindo:

* Um processo de endurecimento replicável que torne rápido e fácil implantar outro ambiente que esteja devidamente bloqueado. Desenvolvimento, QA e ambientes de produção devem ser configurados de forma idêntica, com diferentes credenciais usadas em cada ambiente. Este processo deve ser automatizado para minimizar o esforço necessário para configurar um novo ambiente seguro.
* Uma plataforma mínima sem recursos, componentes, documentação e amostras desnecessários. Remova ou não instale recursos e frameworks não utilizados.
* Uma tarefa para revisar e atualizar as configurações apropriadas para todas as notas de segurança, atualizações e patches como parte do processo de gerenciamento de patches (veja **A9:2017-Utilização de Componentes com Vulnerabilidades Conhecidas**).
* Uma arquitetura de aplicações segmentados que forneça separação efetiva e segura entre componentes ou inquilinos, com segmentação, conteinerização ou grupos de segurança de nuvem (ACLs).
* Enviar diretivas de segurança para agentes clientes, por exemplo [Cabeçalhos de segurança](https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project).
* Um processo automatizado para verificar a eficácia das configurações e configurações em todos os ambientes

## Exemplo de Cenários de Ataque

**Cenário #1**: O servidor de aplicação vem com aplicativos de exemplo que não são removidos do seu servidor de produção. Esses aplicativos de exemplo possuem falhas conhecidas de segurança que atacantes usam para comprometer seu servidor. Se um desses aplicativos for o console de administração, e as contas padrão não foram alteradas, o atacante faz logon com senhas padrão e assume o controle.

**Cenário #2**: A listagem de diretórios não está desativada em seu servidor. Um atacante descobre que ele pode simplesmente listar diretórios. O atacante localiza e baixa suas classes Java compiladas, que são então descompiladas e sofrem engenharia reversa para visualizar seu código. O atacante então encontra uma falha séria de controle de acesso em sua aplicação.

**Cenário #3**: A configuração do servidor de aplicação permite mensagens de erro detalhadas, por exemplo, stacktraces que retornam para os usuários. Isso potencialmente expõe informações sensíveis ou falhas subjacentes, como versões de componentes que são conhecidas como vulneráveis.

**Cenário #4**: A configuração padrão ou uma antiga copiada ativa as versões antigas ou opções de protocolo vulneráveis que podem ser mal utilizadas por um atacante ou malware.

## Referências

### OWASP

* [OWASP Testing Guide: Configuration Management](https://wiki.owasp.org/index.php/Testing_for_configuration_management)
* [OWASP Testing Guide: Testing for Error Codes](https://wiki.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006))
* [OWASP Security Headers Project](https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project)

For additional requirements in this area, see the [ASVS requirements areas for Security Configuration (V11 and V19)](https://wiki.owasp.org/index.php/ASVS).

### Externas

* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
* [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
* [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
