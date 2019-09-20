# A10:2017 Registo e Monitorização Insuficiente

| Agentes de Ameaça/Vectores de Ataque | Falha de Segurança | Impacto |
| -- | -- | -- |
| Específico App. \| Abuso: 2 | Prevalência: 3 \| Deteção: 1 | Técnico: 2 \| Negócio ? |
| O abuso do registo e monitorização insuficiente são o alicerce de quase todos os incidentes mais importantes. Os atacantes dependem da falta de monitorização e capacidade de resposta atempada para atingirem os seus objetivos sem serem detetados. | Esta falha foi incluída no Top 10 baseado num [inquérito realizado][0xaa1] à indústria. Uma estratégia para determinar se possui capacidade de monitorização suficiente é examinar os seus ficheiros de registo depois de realizar testes de intrusão. As ações dos auditores devem ter sido registadas com detalhe suficiente para perceber que danos possam ter sido infligidos. | Muitos ataques bem sucedidos começam com a identificação automática de vulnerabilidades. Permitir que estas ferramentas corram aumenta a taxa de sucesso para perto dos 100%. Em 2016, a identificação duma falha levava em média cerca de 191 dias – tempo q.b. para que algum tipo de dano pudesse ser inflingido. |

## A Aplicação é Vulnerável?

Insuficiência do registo, deteção, monitorização e resposta acontece sempre que:

* Eventos auditáveis como autenticação, autenticações falhadas e transações de
  valor relevante não são registados
* Alertas e erros não são registados, ou geram mensagens desadequadas ou
  insuficientes.
* Registos das aplicações e APIs não são monitorizados para deteção de atividade
  suspeita.
* Registos são armazenados localmente.
* Limites para geração de alertas e processos de elevação de resposta não estão
  definidos ou não são eficazes.
* Testes de intrusão e verificações por ferramentas [DAST][0xaa2] (e.g. [OWASP
  ZAP][0xaa3]) não geram alertas.
* A aplicação é incapaz de detetar, lidar com ou alertar em tempo real ou
  quase-real para ataques em curso.

Está ainda vulnerável à fuga de informação se tornar os registos e alertas
visíveis para os utilizadores ou atacantes (ver [A3:2017-Exposição de Dados
Sensíveis][0xaa4]).

## Como Prevenir

Dependendo do risco inerente à informação armazenada ou processada pela
aplicação:

* Assegurar que todas as autenticações, falhas no controlo de acessos e falhas
  na validação de dados de entrada no servidor são registados com detalhe
  suficiente do contexto do utilizador que permita identificar contas suspeitas
  ou maliciosas e mantidos por tempo suficiente que permita a análise forense.
* Assegurar que os registos usam um formato que possa ser facilmente consumido
  por uma solução de gestão de registos centralizada.
* Assegurar que as transações mais críticas têm registo pormenorizado para
  auditoria com controlos de integridade para prevenir adulteração ou remoção
  tais como tabelas de base de dados que permitam apenas adição de novos
  registos.
* Definir processos de monitorização e alerta capazes de detetar atividade
  suspeita e resposta atempada
* Definir e adotar uma metodologia de resposta a incidentes e plano de
  recuperação tal como [NIST 800-61 rev 2][0xaa5].

Existem _frameworks_ comerciais e de código aberto para proteção de aplicações
(e.g. [OWASP App Sensor][0xaa6]), _Web Application Firewalls_ (WAF) (e.g. 
[ModSecurity with the OWASP ModSecurity Core Rule Set][0xaa7]) assim como
ferramentas de análise de registos e alarmística.

## Exemplos de Cenários de Ataque

**Cenário #1**: Um projeto de código aberto de um forum mantido por uma equipa
pequena foi comprometido, abusando duma vulnerabilidade do próprio software. Os
atacantes conseguiram ter acesso ao repositório interno onde estava o código da
próxima versão assim com todos os conteúdos. Embora o código fonte possa ser
recuperado, a falta de monitorização, registo e alarmística tornam o incidente
mais grave. O projeto foi abandonado em consequência deste incidente.

**Cenário #2**: Um atacante usa uma ferramenta automática para testar o uso de
uma palavra-passe comum por forma a ganhar controlo sobre as contas que usam
essa password. Para as outras contas esta operação deixa apenas registo duma
tentativa de autenticação falhada, podendo ser repetida dias depois com outra
palavra-passe.

**Cenário #3**: Um dos principais retalhistas dos Estados Unidos tinha
internamente um ferramenta para análise de anexos para identificação de malware.
Esta ferramenta detetou uma ocorrência mas ninguém atuou mesmo quando sucessivos
alertas continuaram a ser gerados. Mais tarde a falha viria a ser identificada
em consequência de transações fraudulentas.

## Referências

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection][0xaa8]
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring][0xaa9]
* [OWASP Testing Guide: Testing for Error Code][0xaa10]
* [OWASP Cheat Sheet: Logging][0xaa11]

### Externas

* [CWE-223: Omission of Security-relevant Information][0xaa12]
* [CWE-778: Insufficient Logging][0xaa13]

[0xaa1]: https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html
[0xaa2]: https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools
[0xaa3]: https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
[0xaa4]: ./0xa3-sensitive-data-disclosure.md
[0xaa5]: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
[0xaa6]: https://www.owasp.org/index.php/OWASP_AppSensor_Project
[0xaa7]: https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project
[0xaa8]: https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection
[0xaa9]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home
[0xaa10]: https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home
[0xaa11]: https://www.owasp.org/index.php/Logging_Cheat_Sheet
[0xaa12]: https://cwe.mitre.org/data/definitions/223.html
[0xaa13]: https://cwe.mitre.org/data/definitions/778.html

