# A10:2017 Logs e Monitoração Insuficientes

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidades de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Explorabilidade 2 | Prevalência 3 \| Detectabilidade 1 | Técnico 2 \| Negócio |
| A exploração de logs e monitoração insuficientes é o alicerce de quase todos os incidentes importantes. Os atacantes contam com a falta de monitoração e respostas feitas a tempo para alcançar seus objetivos sem serem detectados. | Este problema está incluído no Top 10 com base em uma [pesquisa da indústria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Uma estratégia para determinar se você tem monitoração suficiente é examinar seus registros após um teste de penetração. As ações dos testadores devem ser registradas o suficiente para entender quais os danos que podem ter feitos. | A maioria dos ataques bem sucedidos começa com sondagem de vulnerabilidade. Permitir que tais sondas continuem pode aumentar a probabilidade de exploração bem sucedida para quase 100%. Em 2016, a identificação de uma violação levou uma - tempo suficiente para que estragos fossem feitos. |

## A Aplicação Está Vulnerável?

Insuficiência de logs, de detecção, de monitoração e de resposta ativa ocorrem a qualquer momento:

- Eventos auditáveis, como logins, logins com falha e transações de alto valor não são registrados.
- Os logs de aplicações e APIs não são monitorados para atividades suspeitas.
- Os limiares de alerta e a escalação da resposta, conforme o risco dos dados detidos pela aplicação, não estão em vigor nem são efetivos.
- Testes de penetração e varredura pelas ferramentas [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) (como [OWASP ZAP](https://owasp.org/www-project-zap/)) não desencadeiam alertas.

Para as organizações maiores e de alto desempenho, a falta de respostas ativas, como atividades de alerta e resposta em tempo real como o bloqueio de ataques automatizados em aplicações Web e particularmente APIs, colocaria a organização em risco de um comprometimento estendido. A resposta não precisa necessariamente ser visível para o invasor, apenas que a aplicação e infra-estrutura associada, frameworks, camadas de serviço, etc. podem detectar e alertar humanos ou ferramentas para responder em tempo quase real.

## Como Prevenir

De acordo com o risco dos dados armazenados ou processados pela aplicação:

- Certifique-se de todos os logins, falhas de controle de acesso, as falhas de validação de entrada do lado do servidor possam ser registradas com um contexto de usuário suficiente para identificar contas suspeitas ou mal-intencionadas e mantidas por tempo suficiente para permitir análises forenses demoradas.
- Certifique-se de que os logs são gerados em um formato que pode ser facilmente consumido por uma solução centralizada de gerenciamento de logs.
- Certifique-se de que as transações de alto valor tenham uma trilha de auditoria com controles de integridade para evitar adulterações ou exclusões, como anexar apenas tabelas de banco de dados ou similares.
- Estabeleça monitorações e alertas eficazes, de modo que as atividades suspeitas sejam detectadas e respondidas em tempo hábil.
- Estabeleça ou adote um plano de respostas e recuperação a incidentes, como [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) ou posterior.

Existem frameworks de proteção de aplicações comerciais e de código aberto, como [OWASP AppSensor](https://owasp.org/www-project-appsensor/), firewalls de aplicações Web, como [mod_security com o OWASP Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/) e software de correlação de logs com painéis personalizados e alertas.

## Exemplos de Cenários de Ataque

**Cenário 1**: Um software de fórum de código aberto executado por uma pequena equipe foi pirateado usando uma falha em seu software. Os atacantes conseguiram eliminar o repositório de código fonte interno que contém a próxima versão e todos os conteúdos do fórum. Embora o código fonte possa ser recuperado, a falta de monitoração, logs ou alertas levou a uma violação muito pior. O projeto de software de fórum não está mais ativo como resultado dessa questão.

**Cenário 2**: Um atacante usa varreduras para encontrar usuários que usam uma senha comum. Eles podem assumir todas as contas usando esta senha. Para todos os outros usuários, esta varredura deixa apenas 1 login falso para trás. Após alguns dias, isso pode ser repetido com uma senha diferente.

**Cenário 3**: Um grande varejista dos EUA teria um sandbox interno de análise de malware analisando anexos. O sandbox detectou softwares potencialmente indesejados, mas ninguém respondeu a essa detecção. O sandbox tinha produzido avisos por algum tempo antes da violação ser detectada devido a transações fraudulentas de cartão por um banco externo.

## Referências

### OWASP

- [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging)
- [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
- [OWASP Testing Guide: Testing for Detailed Error Code](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

### Externas

- [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
