# A10:2017 Registo e Monitorização Insuficiente

| Agentes de Ameaça/Vetores de Ataque | Vulnerabilidade de Segurança | Impactos |
| -- | -- | -- |
| Nível de Acesso \| Exploração 2 | Prevalência 3 \| Deteção 1 | Técnico 2 \| Negócio |
| O abuso do registo e monitorização insuficiente são o alicerce de quase todos os incidentes mais importantes. Os atacantes dependem da falta de monitorização e capacidade de resposta atempada para atingirem os seus objetivos sem serem detetados. | Esta falha foi incluída no Top 10 baseado num [inquérito realizado à indústria][1]. Uma estratégia para determinar se possui capacidade de monitorização suficiente é examinar os seus ficheiros de registo depois de realizar testes de intrusão. As ações dos auditores deve ter sido registadas com detalhe suficiente para perceber que danos possam ter sido infligidos. | Muitos ataques bem sucedidos começam com uma análise de vulnerabilidades. Permitir que estas ferramentas continuem a ser executadas podem levar a um aumento da taxa de sucesso de exploração de falhas para perto dos 100%. Em 2016, o processo de identificação de uma falha levava [em média cerca de 191 days](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) – muito tempo para que algum tipo de dano pudesse ser inflingido.|

## A Aplicação é Vulnerável?

Insuficiência do registo, deteção, monitorização e resposta acontece sempre que:

* Eventos auditáveis como logins, logins falhados e transações de valor
  relevante não são registados
* Alertas e erros não são registados, ou geram mensagens desadequadas ou
  insuficientes.
* Registos das aplicações e APIs não são monitorizados com relação a atividade
  suspeita.
* Registos são armazenados localmente.
* Limites para geração de alertas e processos de elevação de resposta não estão
  definidos ou não são eficazes.
* Testes de intrusão e verificações por ferramentas [DAST][5] (e.g. [OWASP
  ZAP][6]) não geram alertas.
*  aplicação é incapaz de detetar, lidar com ou alertar em temo real ou
   quase-real para ataques em curso.

Está ainda vulnerável à fuga de informação se tornar os registos e alertas
visiveis para os utilizadores ou atacantes (ver A3:2017-Sensitive Information
Exposure).

## Como Prevenir

Dependendo do risco inerente à informação armazenada ou processda pela
aplicação:

* Assegurar que todos os logins, falhas no controlo de acessos e falhas na
  validação de dados de entrada no servidor são registados com detalhe
  suficiente do contexto do utilizador que permita identificar contas suspeitas
  ou maliciosas e mantidos por tempo suficiente que permita a análise forense
* Assegurar que os registos usam um formato que possa ser facilemente consumido
  e centradilizado por soluções de gestão de registos.
* Assegurar que as transações mais críticas têm registo pormenorizado para
  auditoria com controlos de integridade para pevenir adulteração ou remoção
  tais como tabelas de base de dados que permitam apenas a adição de novos
  registos.
* Definir processos de monitorização e alerta capazes de detetar atividade
  suspeita e resposta atempada
* Definir e adotar uma metodolodia de resposta a incidentes e plano de
  recuperação tal como [NIST 800-61 rev 2][2].
* Existem frameworks comercais e de código aberto para proteção de aplicações
  (e.g. [OWASP AppSensor][3]), Web Application Firewalls (WAF)
  (e.g. [ModSecurity with the OWASP ModSecurity Core Rule Set][4]) assim como
  ferramentas de análise de registos e alarmística.

## Exemplos de Cenários de Ataque

**Cenário #1**: Um projeto de código aberto mantido po ruma equipa pequena foi
abusado explorando uma vulnerabilidade do próprio software. Os atacantes
conseguiram ter acesso ao repositório interno onde estava o código da próxima
versão assim com otodos os conteúdos. Embora o código fonte possa ter
recuperado, a falta de monitorização, registo e alarmística tornam o incidente
mais gravoso. O projeto foi abandonado em consequência deste incidente.

**Cenário #2**: Um atacante usa uma ferramente automática para testar o uso duma
palavra-passe comum por forma a ganhar controlo sobre as contas que usam essa
password. Para as outras contas esta operação deixa apenas registo duma
tentativa de login falhado, podendo ser repetida dias depois com outra
palavra-passe.

**Cenário #3**: Um dos principais retalhista dos Estados Unidos tinha
internamente um ferramenta para análise de anexo para identificação de malware.
Esta ferramente detetou uma ocorrência mas ninguém atuou mesmo quando sucessivos
alertas continuaram a ser gerados até que uma falhar foi identificada em
consequência de transações fraudulentas.

## Referências

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection][7]
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring][8]
* [OWASP Testing Guide: Testing for Error Code][9]
* [OWASP Cheat Sheet: Logging][10]

### Externas

* [CWE-223: Omission of Security-relevant Information][11]
* [CWE-778: Insufficient Logging][12]

[1]: https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html
[2]: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
[3]: https://www.owasp.org/index.php/OWASP_AppSensor_Project
[4]: https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project
[5]: https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools
[6]: https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
[7]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection
[8]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home
[9]: https://www.owasp.org/index.php/Testing_for_Error_Code_(OTG-ERR-001)
[10]: https://www.owasp.org/index.php/Logging_Cheat_Sheet
[11]: https://cwe.mitre.org/data/definitions/223.html
[12]: https://cwe.mitre.org/data/definitions/778.html

