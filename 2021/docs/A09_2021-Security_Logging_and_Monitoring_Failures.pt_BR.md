# A09:2021 – Falhas de registro e monitoramento de segurança    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Fatores

| CWEs Mapeados | Taxa de Incidência Máxima | Taxa de Incidência Média | Exploração Média Ponderada | Impacto Médio Ponderado | Cobertura Máxima | Cobertura Média | Total de ocorrências | Total de CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 6.87                 | 4.99                | 53.67%       | 39.97%       | 53,615            | 242        |

## Visão Geral

O monitoramento e registro de segurança subiram da décima posição na lista OWASP Top 10 de 2017 para a terceira posição na pesquisa da comunidade Top 10. É desafiador testar o monitoramento e registro, muitas vezes envolvendo entrevistas ou perguntando se ataques foram detectados durante um teste de penetração. Não há muitos dados CVE/CVSS para essa categoria, mas detectar e responder a violações é crítico. Ainda assim, pode ser muito impactante para responsabilidade, visibilidade, alerta de incidentes e forense. Essa categoria se expande além da *CWE-117 Neutralização inadequada de saída para logs* para incluir a *CWE-223 Omissão de informações relevantes para segurança*, *CWE-532 Inserção de informações sensíveis em arquivo de log* e *CWE-778 Registro insuficiente*.

## Descrição

Retornando à lista OWASP Top 10 de 2021, essa categoria ajuda a detectar, escalonar e responder a violações ativas. Sem o monitoramento e registro, as violações não podem ser detectadas. A falta de registro, detecção, monitoramento e resposta ativa ocorre sempre que:

- Eventos auditáveis, como logins, logins falhos e transações de alto valor, não são registrados.

- Avisos e erros geram mensagens de log inexistentes, inadequadas ou confusas.

- Logs de aplicativos e APIs não são monitorados quanto a atividades suspeitas.

- Logs são armazenados apenas localmente.

- Limiares de alerta apropriados e processos de escalonamento de resposta não estão em vigor ou são eficazes.

- Testes de penetração e varreduras por ferramentas de teste de segurança de aplicativos dinâmicos (DAST), como OWASP ZAP, não acionam alertas.

- A aplicação não pode detectar, escalonar ou alertar para ataques ativos em tempo real ou quase em tempo real.

Você está vulnerável a vazamento de informações tornando eventos de registro e alerta visíveis para um usuário ou um atacante 
(veja [A01:2021-Quebra de Controle de Acesso](A01_2021-Broken_Access_Control.pt_BR.md)).

## Como Prevenir

Os desenvolvedores devem implementar alguns ou todos os controles a seguir, dependendo do risco da aplicação:

- Garantir que todas as falhas de login, controle de acesso e validação de entrada no lado do servidor possam ser registradas com contexto de usuário suficiente para identificar contas suspeitas ou maliciosas e mantidas por tempo suficiente para permitir análise forense atrasada.

- Garantir que os logs sejam gerados em um formato que as soluções de gerenciamento de logs possam facilmente consumir.

- Garantir que os dados de log sejam codificados corretamente para evitar injeções ou ataques nos sistemas de registro ou monitoramento.

- Garantir que transações de alto valor tenham uma trilha de auditoria com controles de integridade para evitar adulteração ou exclusão, como tabelas de banco de dados somente para adição ou similares.

- As equipes de DevSecOps devem estabelecer monitoramento e alerta efetivos para que atividades suspeitas sejam detectadas e respondidas rapidamente.

- Estabelecer ou adotar um plano de resposta e recuperação de incidentes, como o National Institute of Standards and Technology (NIST) 800-61r2 ou posterior.

Existem estruturas de proteção de aplicativos comerciais e de código aberto, como o OWASP ModSecurity Core Rule Set, e software de correlação de logs de código aberto, como o Elasticsearch, Logstash, Kibana (ELK) stack, que possuem painéis personalizados e alertas.

## Exemplos de Cenários de Ataque

**Cenário 1:** O operador do site do provedor de plano de saúde infantil não conseguiu detectar uma violação devido à falta de monitoramento e registro. Uma parte externa informou ao provedor do plano de saúde que um invasor havia acessado e modificado milhares de registros de saúde sensíveis de mais de 3,5 milhões de crianças. Uma revisão pós-incidente descobriu que os desenvolvedores do site não haviam abordado vulnerabilidades significativas. Como não houve registro ou monitoramento do sistema, a violação de dados pode ter estado em andamento desde 2013, um período de mais de sete anos.

**Cenário 2:** Uma grande companhia aérea indiana teve uma violação de dados envolvendo dados pessoais de milhões de passageiros por mais de dez anos, incluindo dados de passaporte e cartão de crédito. A violação de dados ocorreu em um provedor de hospedagem em nuvem de terceiros, que notificou a companhia aérea da violação depois de algum tempo.

**Cenário nº 3:** Uma grande companhia aérea europeia sofreu uma violação relatável do GDPR. A violação foi supostamente causada por vulnerabilidades de segurança do aplicativo de pagamento exploradas por invasores, que colheram mais de 400.000 registros de pagamento de clientes. A companhia aérea foi multada em 20 milhões de libras como resultado pelo regulador de privacidade.

## Referências

- [OWASP Proactive Controls: Implement Logging and Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

- [OWASP Application Security Verification Standard: V7 Logging and Monitoring](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: Testing for Detailed Error Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

- [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

- [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

- [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Lista dos CWEs Mapeados

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
