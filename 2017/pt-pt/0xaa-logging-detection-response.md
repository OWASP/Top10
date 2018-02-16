# A10:2017 Registo e Monitorização Insuficiente

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 2 | Prevalência 3 \| Deteção 1 | Técnico 2 \| Negócio |
| A exploração do registo e monitorização insuficiente são o alicerce de quase todos os incidentes mais importantes. Os atacantes dependem da falta de monitorização e capacidade de resposta atempada para atingirem os seus objectivos sem serem detectados. | Este aspecto está incluído no Top 10 baseado num [inquérito realizado à indústria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Uma estratégia para determinar se possui capacidade de monitorização suficiente é examinar os seus ficheiros de registo depois de realizar testes de intrusão. As acções dos auditores deve ter sido registadas com detalhe suficiente para perceber que danos possam ter sido infligidos. | Muitos ataques bem sucedidos começam com uma análise de vulnerabilidades. Permitir que estas ferramentas continuem a ser executadas podem levar a um aumento da taxa de sucesso de exploração de falhas para perto dos 100%. Em 2016, o processo de identificação de uma falha levava [em média cerca de 191 days](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) – muito tempo para que algum tipo de dano pudesse ser inflingido.|

## Está a Aplicação Vulnerável?

Registo, detecção, monitorização e resposta activa insuficientes podem ocorrer em qualquer altura:

* Eventos auditáveis, tais como autenticação, autenticação falhada, e transações de elevado valor não são registados.
* Registos de aplicações e APIs não são monitorizados por actividades suspeitas.
* Limiares de alerta e de escalamento de respostas de acordo com o risco dos dados detidos pela aplicação não estão em vigor ou não são efectivos. 

Para organizações maiores e de elevado desempenho, a falta de uma resposta activa, tais como actividades de resposta e alerta em tempo real como o bloqueio de ataques automáticos a aplicações web e particularmente colocam a organização em risco de compromisso estendido. A resposta não necessita necessariamente de ser visível para o atacante, apenas que a aplicação e a infraestrurura associada, frameworks, níveis de serviços, entre outros, possam detectar e alertar os humanos ou ferramentas para responder em tempo quase real.

## Como Prevenir?

De acordo com o risco dos dados armazenados ou processados pela aplicação:

* Assegurar que todas as autenticações, falhas de controlo de acesso, falhas de validação de entradas do lado do servidor, possam ser registadas com contexto do utilizador suficiente para identificar as contas suspeitas ou maliciosas, e detidas o tempo suficiente para permitir análise forense posterior.
* Assegurar que as transações de elevado valor possuem um traço de auditoria com controlos de integridade para prevenir alterações ou remoções, tais como tabelas que apenas permitem adicionar registos ou similares.
* Estabelecer mecanismos efectivos de monitorização e alerta de forma a que as actividades suspeitas sejam detectadas e haja uma resposta dentro de um período de tempo aceitável.
* Estabelecer ou adoptar um plano de resposte e recuperação de incidentes, tais como o [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) ou superior.

Existem frameworks comercias e open-source de protecção aplicacional tais como o [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), firewalls de aplicações web tais como o [mod_security como o OWASP Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), e software de correlação de registos com dashboards e alertas personalizados. Testes de intrusão e análises por ferramentas DAST (tais como o OWASP ZAP) devem sempre despoletar alertas.

## Exemplos de Cenários de Ataque

**Cenário 1**: Um software open-source de gestão de foruns mantido por uma pequena equipa de desenvolvimento foi atacado usando uma falha no software do mesmo. Os atacantes conseguiram limpar o repositório interno de código fonte que continha a próxima versão, e todo o conteúdo do fórum. Apesar do código ter sido recuperado, a falta de monitorização, registo e alerta levou a um ataque sério. O sofware de projecto de software já não está activo devido a este problema.

**Cenário 2**: Um atacante faz uma análise de utilizadores que usem uma password comum. Ele pode assumir todas as contas usando a password. Para todos os utilizadores, esta análise deixa apenas o registo de uma autenticação falhada para trás. Depois de alguns dias esta análise pode ser repetida usando uma password diferente.

**Cenário 3**: Um retalhista nos EUA possui uma sandbox interna de análise de malware para analizar anexos. O software da sandbox detectou software potencialmente malicioso, mas ninguém deu resposta a esta deteção. A sandbox tinha vindo a produzir avisos já há algum tempo antes de uma falha ter sido detectada devido a transações fraudulentas usando o cartão de crédito por parte de um banco externo.

## Referências

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### Externas

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
