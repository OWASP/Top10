# A10:2017 Logs e Monitoração Insuficientes

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 2 | Prevalência 3 \| Detectabilidade 1 | Técnico 2 \| Negócio |
| A exploração de logs e monitoração insuficientes é o alicerce de quase todos os incidentes importantes. Os atacantes contam com a falta de monitoração e respostas feitas a tempo para alcançar seus objetivos sem serem detectados. | Este problema está incluído no Top 10 com base em uma [pesquisa da indústria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Uma estratégia para determinar se você tem monitoração suficiente é examinar seus registros após um teste de penetração. As ações dos testadores devem ser registradas o suficiente para entender quais os danos que podem ter feitos. | A maioria dos ataques bem sucedidos começa com sondagem de vulnerabilidade. Permitir que tais sondas continuem pode aumentar a probabilidade de exploração bem sucedida para quase 100%. Em 2016, a identificação de uma violação levou uma [média de 191 dias](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) - tempo suficiente para que estragos fossem feitos. |

## A Aplicação Está Vulnerável?

Insuficiência de logs, de detecção, de monitoração e resposta ativa ocorrem a qualquer momento:

* Eventos auditáveis, como logins, logins com falha e transações de alto valor não são registrados.
* Os logs de aplicações e APIs não são monitorados para atividades suspeitas.
* Os limiares de alerta e a escalação da resposta, conforme o risco dos dados detidos pela aplicação, não estão em vigor nem são efetivos.
* Testes de penetração e varredura pelas ferramentas [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) (como [OWASP ZAP](https://www.owasp.org/index.php)/OWASP_Zed_Attack_Proxy_Project)) não desencadeiam alertas.

Para as organizações maiores e de alto desempenho, a falta de respostas ativas, como atividades de alerta e resposta em tempo real como o bloqueio de ataques automatizados em aplicações Web e particularmente APIs, colocaria a organização em risco de um comprometimento estendido. A resposta não precisa necessariamente ser visível para o invasor, apenas que a aplicação e infra-estrutura associada, frameworks, camadas de serviço, etc. podem detectar e alertar humanos ou ferramentas para responder em tempo quase real.

## Como Prevenir

As per the risk of the data stored or processed by the application:

* Ensure all login, access control failures, server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis.
* Ensure that logs are generated in a format that can be easily consumed by a centralized log management solutions.
* Ensure high value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append only database tables or similar.
* Establish effective monitoring and alerting such that suspicious activities are detected and responded to in a timely fashion.
* Establish or adopt an incident response and recovery plan, such as [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) or later.

There are commercial and open source application protection frameworks such as [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), web application firewalls such as [mod_security with the OWASP Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), and log correlation software with custom dashboards and alerting. 

## Example Attack Scenarios

**Scenario 1**: An open source project forum software run by a small team was hacked using a flaw in its software. The attackers managed to wipe out the internal source code repository containing the next version, and all of the forum contents. Although source could be recovered, the lack of monitoring, logging or alerting led to a far worse breach. The forum software project is no longer active as a result of this issue.

**Scenario 2**: An attacker uses scans for users using a common password. They can take over all accounts using this password. For all other users this scan leaves only 1 false login behind. After some days this may be repeated with a different password.

**Scenario 3**: A major US retailer reportedly had an internal malware analysis sandbox analyzing attachments. The sandbox software had detected potentially unwanted software, but no one responded to this detection. The sandbox had been producing warnings for some time before the breach was detected due to fraudulent card transactions by an external bank.

## References

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### External

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
