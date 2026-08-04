# A09:2025 – Falhas de Registro e Monitoramento de Segurança ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Contexto

**Falhas de Registro e Monitoramento de Segurança** (Security Logging & Alerting Failures) mantém sua posição em 9º lugar. Esta categoria teve uma leve mudança de nome para enfatizar a função de alerta necessária para induzir ações em eventos de _log_ relevantes. Esta categoria estará sempre sub-representada nos dados e, pela terceira vez, foi votada para uma posição na lista pelos participantes da pesquisa da comunidade. É uma categoria incrivelmente difícil de testar e possui representação mínima nos dados de CVE/CVSS (apenas 723 CVEs); porém, pode ter um grande impacto na visibilidade, no alerta de incidentes e na perícia forense. Esta categoria inclui problemas com o _tratamento adequado da codificação de saída para arquivos de log (CWE-117), inserção de dados sensíveis em arquivos de log (CWE-532) e registros insuficientes (CWE-778)._

## Tabela de Pontuação

<table>
  <tr>
   <td>CWEs Mapeadas 
   </td>
   <td>Taxa Máx. de Incidência
   </td>
   <td>Taxa Média de Incidência
   </td>
   <td>Cobertura Máxima
   </td>
   <td>Cobertura Média
   </td>
   <td>Exploit Médio Ponderado
   </td>
   <td>Impacto Médio Ponderado
   </td>
   <td>Total de Ocorrências
   </td>
   <td>Total de CVEs
   </td>
  </tr>
  <tr>
   <td>5
   </td>
   <td>11,33%
   </td>
   <td>3,91%
   </td>
   <td>85,96%
   </td>
   <td>46,48%
   </td>
   <td>7,19
   </td>
   <td>2,65
   </td>
   <td>260.288
   </td>
   <td>723
   </td>
  </tr>
</table>

## Descrição

Sem registro e monitoramento, ataques e violações não podem ser detectados, e sem alertas é muito difícil responder de forma rápida e eficaz durante um incidente de segurança. Registro, monitoramento contínuo, detecção e alertas insuficientes para iniciar respostas ativas ocorrem sempre que:

- Eventos auditáveis, como logins, falhas de login e transações de alto valor, não são registrados ou são registrados de forma inconsistente (por exemplo, registrando apenas logins bem-sucedidos, mas não tentativas falhas).
- Avisos e erros geram mensagens de _log_ inexistentes, inadequadas ou confusas.
- A integridade dos _logs_ não é devidamente protegida contra adulteração.
- _Logs_ de aplicações e APIs não são monitorados em busca de atividades suspeitas.
- Os _logs_ são armazenados apenas localmente e não possuem backup adequado.
- Limiares de alerta e processos de escalonamento de resposta apropriados não estão estabelecidos ou não são eficazes. Os alertas não são recebidos ou revisados em um tempo razoável.
- Testes de invasão (_penetration testing_) e varreduras por ferramentas de testes dinâmicos de segurança de aplicações (DAST), como Burp ou ZAP, não disparam alertas.
- A aplicação não consegue detectar, escalar ou alertar sobre ataques ativos em tempo real ou próximo ao tempo real.
- Você está vulnerável ao vazamento de informações sensíveis ao tornar eventos de registro e alerta visíveis para um usuário ou atacante (veja [A01:2025-Controle de Acesso Quebrado](A01_2025-Broken_Access_Control.md)), ou ao registrar informações sensíveis que não deveriam ser gravadas (como PII ou PHI).
- Você está vulnerável a injeções ou ataques nos sistemas de registro ou monitoramento se os dados de _log_ não forem codificados corretamente.
- A aplicação omite ou trata incorretamente erros e outras condições excepcionais, de modo que o sistema não percebe que houve um erro e, portanto, não consegue registrar que houve um problema.
- "Casos de uso" adequados para emissão de alertas estão ausentes ou desatualizados para reconhecer uma situação especial.
- O excesso de alertas falsos positivos impossibilita distinguir alertas importantes de irrelevantes, resultando em detecções tardias ou inexistentes (sobrecarga física da equipe do SOC).
- Alertas detectados não podem ser processados corretamente porque o _playbook_ para o caso de uso está incompleto, desatualizado ou ausente.

## Como Prevenir

Os desenvolvedores devem implementar alguns ou todos os seguintes controles, dependendo do risco da aplicação:

- Garantir que todas as falhas de login, controle de acesso e validação de entrada no lado do servidor possam ser registradas com contexto de usuário suficiente para identificar contas suspeitas ou maliciosas, e mantidas por tempo suficiente para permitir análises forenses posteriores.
- Garantir que cada parte do seu app que contenha um controle de segurança gere um _log_, independentemente de sucesso ou falha.
- Garantir que os _logs_ sejam gerados em um formato que as soluções de gerenciamento de _logs_ possam consumir facilmente.
- Garantir que os dados de _log_ sejam codificados corretamente para evitar injeções ou ataques aos sistemas de registro ou monitoramento.
- Garantir que todas as transações tenham uma trilha de auditoria com controles de integridade para evitar adulteração ou exclusão, como tabelas de banco de dados do tipo _append-only_ ou similares.
- Garantir que todas as transações que lancem um erro sofram _rollback_ e sejam reiniciadas. Sempre utilize a falha segura (_fail closed_).
- Se sua aplicação ou seus usuários se comportarem de forma suspeita, emita um alerta. Crie diretrizes para seus desenvolvedores sobre este tema para que possam codificar prevendo isso ou adquira um sistema para este fim.
- As equipes de DevSecOps e segurança devem estabelecer casos de uso eficazes de monitoramento e alerta, incluindo _playbooks_, para que atividades suspeitas sejam detectadas e respondidas rapidamente pela equipe do Centro de Operações de Segurança (SOC).
- Adicione ‘honeytokens’ como armadilhas para atacantes em sua aplicação, ex: no banco de dados, nos dados, ou como identidades de usuários reais e/ou técnicas. Como não são usados no fluxo normal de negócio, qualquer acesso gera dados de _log_ que podem disparar alertas com quase zero falsos positivos.
- A análise de comportamento e o suporte de IA podem ser, opcionalmente, técnicas adicionais para apoiar baixas taxas de falsos positivos em alertas.
- Estabeleça ou adote um plano de resposta e recuperação de incidentes, como o NIST 800-61r2 ou posterior. Ensine seus desenvolvedores de software como são os ataques e incidentes em aplicações, para que saibam reportá-los.

Existem produtos comerciais e de código aberto para proteção de aplicações, como o OWASP ModSecurity Core Rule Set, e softwares de correlação de _logs_ de código aberto, como a stack Elasticsearch, Logstash, Kibana (ELK), que apresentam painéis personalizados e alertas que podem ajudar a combater esses problemas. Também existem ferramentas comerciais de observabilidade que podem ajudar a responder ou bloquear ataques em tempo quase real.

## Cenários de Exemplo de Ataque

**Cenário 1:** O operador do site de um provedor de planos de saúde infantil não conseguiu detectar uma invasão devido à falta de monitoramento e registros. Uma parte externa informou ao provedor que um atacante havia acessado e modificado milhares de registros de saúde sensíveis de mais de 3,5 milhões de crianças. Uma revisão pós-incidente descobriu que os desenvolvedores do site não haviam corrigido vulnerabilidades significativas. Como não havia registro ou monitoramento do sistema, o vazamento de dados poderia estar em andamento desde 2013, um período de mais de sete anos.

**Cenário 2:** Uma grande companhia aérea indiana sofreu um vazamento de dados envolvendo mais de dez anos de dados pessoais de milhões de passageiros, incluindo dados de passaporte e cartão de crédito. O vazamento ocorreu em um provedor de hospedagem em nuvem terceirizado, que notificou a companhia aérea sobre a violação após algum tempo.

**Cenário 3:** Uma grande companhia aérea europeia sofreu uma violação passível de notificação pelo GDPR. O vazamento foi supostamente causado por vulnerabilidades de segurança em uma aplicação de pagamento exploradas por atacantes, que coletaram mais de 400.000 registros de pagamento de clientes. Como resultado, a companhia aérea foi multada em 20 milhões de libras pelo regulador de privacidade.

## Referências

- [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

- [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

- [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

- [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

- [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)

## Lista de CWEs Mapeadas

- [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

- [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)

- [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

- [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

- [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
