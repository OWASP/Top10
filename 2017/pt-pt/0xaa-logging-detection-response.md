# A10:2017 Registo e Monitorização Insuficiente

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de acesso : Abuso 2 | Prevalência 3 : Deteção 1 | Técnico 2 : Negócio |
| A exploração de registo e monitorização insuficiente é o alicerce de 
praticamente todos os grandes incidentes. Os atacantes usam essa falta de 
monitorização e capacidade de resposta para atingirem os seus objetivos sem serem
 detetados. | Este problema está incluído no Top 10 baseado numa 
 [pesquisa e análise da indústria][1]. Uma estratégia para determinar se a 
 monitorização é suficiente, é analisar os ficheiros de registos após um teste 
 de intrusão. Os registos devem detalhar as ações realizadas pelos auditores de 
 forma a ser possível perceber quais foram os danos que estes infligiram. | A 
 maioria dos ataques bem sucedidos começa com análise de vulnerabilidades. 
 Permitir que esta análise continue sem ser detetada, pode fazer com que 
 a probabilidade de sucesso do ataque aumente para praticamente 100%. Em 2016, 
 identificar uma falha demorava em [média 191 dias][2] - bastante tempo para 
 usar essa vulnerabilidade de modo a infligir algum tipo de dano. |

## A Aplicação é Vulnerável?

Registo, deteção, monitorização e resposta ativa insuficiente podem ocorrer em 
qualquer altura:

* Eventos auditáveis, tais como autenticação, autenticação falhada e transações 
de elevado valor não são registados.

* Avisos (*Warnings*) e erros não geram registos, ou então os registos gerados 
não são claros.

* Os registos de aplicações e APIs não são monitorizados com o objetivo de 
encontrar atividade suspeita.

* Registos são apenas guardados localmente.

* Os limites para os quais são lançados alertas não são apropriados e os processos 
de escalamento de resposta a esses alertas não estão em vigor ou não são efetivos. 

* Testes de intrusão e análises recorrendo a ferramentas [DAST][3] (tais como 
[OWASP ZAP][4]) não geram alertas.

* A aplicação não consegue detetar, escalar ou alertar em *real time* quando é 
alvo de ataques.

A aplicação está vulnerável a vazamento de informação se os seus eventos de 
registo e alerta forem visíveis para um utilizador ou atacante (ver 
A3:2017-Sensitive Information Exposure).

## Como Prevenir?

De acordo com o risco dos dados armazenados/processados pela aplicação:

* Assegurar que todos as autenticações, falhas de controlo de acesso e falhas de 
validação de input no servidor são registadas adequadamente. Estes registos devem 
ter contexto suficiente para identificar contas maliciosas ou suspeitas, e ser 
persistidos por tempo suficiente para permitir uma análise forense posterior.

* Assegurar que os registos são gerados num formato que possa ser facilmente 
consumido por um agregador de registos centralizado.

* Assegurar que transações com alto valor são auditadas com controlos de 
integridade para prevenir adulteração ou remoção, tais como tabelas de base de 
dados *append-only* ou semelhante.

* Estabelecer monitorização e alertas eficazes de forma a que atividades 
suspeitas sejam detetadas e tratadas em tempo útil.

* Estabelecer ou adotar planos de resposta e recuperação de incidentes, tais 
como [NIST 800-61 rev 2][5] ou mais recentes.

Existem *frameworks open source* comerciais de proteção aplicacional tais como 
o [OWASP AppSensor][6], *firewalls* de aplicações web tais como o 
[ModSecurity with the OWASP ModSecurity Core Rule Set][7], e software de 
correlação de registos com *dashboards* e alertas personalizáveis.

## Exemplos de Cenários de Ataque

**Cenário #1**: Um software open-source de gestão de fóruns mantido por uma 
pequena equipa de desenvolvimento foi atacado usando uma falha no software do 
mesmo. Os atacantes conseguiram limpar o repositório interno de código fonte que 
continha a próxima versão e também todo o conteúdo do fórum. Apesar do código 
ter sido recuperado, a falta de monitorização, registo e alerta levou 
posteriormente a um ataque mais sério. O sofware de projecto de software já não 
está activo devido a este problema.

**Cenário 2**: Um atacante faz uma análise de utilizadores (tentativa de login) 
usando uma password escolhida por ele. Ele pode assumir o controlo de todas as 
contas que usem essa password. Para todos os outros utilizadores, esta análise 
deixa apenas o registo de uma autenticação falhada para trás. Depois de alguns 
dias esta análise pode ser repetida usando uma password diferente.

**Cenário 3**: Um retalhista nos EUA possui uma *sandbox* interna de análise de 
malware em anexos. O *software* da *sandbox* detectou *software* potencialmente 
malicioso, mas ninguém deu resposta a esta deteção. A sandbox já produzia avisos 
há algum tempo até que uma falha foi detectada devido a transações fraudulentas 
por parte de um banco externo.

## Referências

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection][8]
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring][9]
* [OWASP Testing Guide: Testing for Detailed Error Code][10]
* [OWASP Cheat Sheet: Logging][11]

### Externas

* [CWE-223: Omission of Security-relevant Information][12]
* [CWE-778: Insufficient Logging][13]

[1]: (https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html)
[2]: (https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&)
[3]: (https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)
[4]: (https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
[5]: (https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
[6]: (https://www.owasp.org/index.php/OWASP_AppSensor_Project)
[7]: (https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project)
[8]: (https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
[9]: (https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
[10]: (https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
[11]: (https://www.owasp.org/index.php/Logging_Cheat_Sheet)
[12]: (https://cwe.mitre.org/data/definitions/223.html)
[13]: (https://cwe.mitre.org/data/definitions/778.html)