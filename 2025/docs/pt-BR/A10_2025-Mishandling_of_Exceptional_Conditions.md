# A10:2025 – Tratamento Incorreto de Condições Excepcionais ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}

## Contexto

**Tratamento Incorreto de Condições Excepcionais** (Mishandling of Exceptional Conditions) é uma categoria nova para 2025. Esta categoria contém 24 CWEs e foca em tratamento de erros inadequado, erros lógicos, falhas abertas (_failing open_) e outros cenários relacionados decorrentes de condições anormais que os sistemas podem encontrar. Esta categoria possui algumas CWEs que anteriormente eram associadas à má qualidade de código. Isso era geral demais para nós; em nossa opinião, esta categoria mais específica fornece uma orientação melhor.

CWEs notáveis incluídas nesta categoria: _CWE-209 Geração de Mensagem de Erro Contendo Informações Sensíveis, CWE-234 Falha ao Tratar Parâmetro Ausente, CWE-274 Tratamento Incorreto de Privilégios Insuficientes, CWE-476 Desreferência de Ponteiro NULO_ e _CWE-636 Falha em Falhar de Forma Segura ('Failing Open')_.

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
   <td>24
   </td>
   <td>20,67%
   </td>
   <td>2,95%
   </td>
   <td>100,00%
   </td>
   <td>37,95%
   </td>
   <td>7,11
   </td>
   <td>3,81
   </td>
   <td>769.581
   </td>
   <td>3.416
   </td>
  </tr>
</table>

## Descrição

O tratamento incorreto de condições excepcionais em software acontece quando os programas falham em prevenir, detectar e responder a situações incomuns e imprevisíveis, o que leva a travamentos (_crashes_), comportamentos inesperados e, às vezes, vulnerabilidades. Isso pode envolver uma ou mais das três falhas a seguir: a aplicação não evita que uma situação incomum aconteça, não identifica a situação enquanto ela ocorre e/ou responde mal ou não responde de forma alguma à situação posteriormente.

Condições excepcionais podem ser causadas por validação de entrada ausente, fraca ou incompleta; tratamento de erros de alto nível tardio em vez de ocorrer nas funções onde eles surgem; estados ambientais inesperados, como problemas de memória, privilégio ou rede; tratamento de exceções inconsistente; ou exceções que não são tratadas de forma alguma, permitindo que o sistema caia em um estado desconhecido e imprevisível. Sempre que uma aplicação não tem certeza de sua próxima instrução, uma condição excepcional foi tratada incorretamente. Erros e exceções difíceis de encontrar podem ameaçar a segurança de toda a aplicação por um longo tempo.

Muitas vulnerabilidades de segurança diferentes podem ocorrer quando tratamos incorretamente condições excepcionais, como _bugs_ de lógica, _overflows_, condições de corrida (_race conditions_), transações fraudulentas ou problemas com memória, estado, recurso, tempo, autenticação e autorização. Esses tipos de vulnerabilidades podem afetar negativamente a confidencialidade, disponibilidade e/ou integridade de um sistema ou de seus dados. Atacantes manipulam o tratamento de erros falho de uma aplicação para explorar essa vulnerabilidade.

## Como Prevenir

Para tratar uma condição excepcional adequadamente, devemos planejar para tais situações (esperar o pior). Devemos "capturar" (_catch_) cada erro de sistema possível diretamente no local onde ocorrem e, então, tratá-lo (o que significa fazer algo significativo para resolver o problema e garantir a recuperação da falha). Como parte do tratamento, devemos incluir o lançamento de um erro (para informar o usuário de forma compreensível), o registro do evento (_log_), bem como a emissão de um alerta se considerarmos justificado. Também devemos ter um manipulador de exceções global para o caso de algo ter passado despercebido. Idealmente, também teríamos ferramentas ou funcionalidades de monitoramento e/ou observabilidade que vigiam erros repetidos ou padrões que indiquem um ataque em andamento, podendo emitir uma resposta, defesa ou bloqueio de algum tipo. Isso pode nos ajudar a bloquear e responder a scripts e bots que focam em nossas fraquezas de tratamento de erros.

Capturar e tratar condições excepcionais garante que a infraestrutura subjacente de nossos programas não seja deixada para lidar com situações imprevisíveis. Se você estiver no meio de uma transação de qualquer tipo, é extremamente importante realizar o _rollback_ de cada parte da transação e começar de novo (também conhecido como falha segura ou _failing closed_). Tentar recuperar uma transação pela metade é frequentemente onde criamos erros irrecuperáveis.

Sempre que possível, adicione limites de taxa (_rate limiting_), cotas de recursos, _throttling_ e outras restrições para prevenir condições excepcionais antes de tudo. Nada em tecnologia da informação deve ser ilimitado, pois isso leva à falta de resiliência da aplicação, negação de serviço, ataques de força bruta bem-sucedidos e faturas de nuvem extraordinárias.

Considere se erros repetidos idênticos, acima de uma certa taxa, devem ser exibidos apenas como estatísticas mostrando a frequência com que ocorreram e em qual período. Esta informação deve ser anexada à mensagem original para não interferir no registro e monitoramento automatizados, veja [A09:2025 Falhas de Registro e Monitoramento de Segurança](A09_2025-Security_Logging_and_Alerting_Failures.md).

Além disso, queremos incluir uma validação de entrada rigorosa (com sanitização ou _escaping_ para caracteres potencialmente perigosos que precisamos aceitar) e um tratamento de erros, registro, monitoramento e alerta _centralizados_, além de um manipulador de exceções global. Uma aplicação não deve ter múltiplas funções para tratar condições excepcionais; isso deve ser realizado em um único lugar, da mesma forma todas as vezes. Também devemos criar requisitos de segurança de projeto para todos os conselhos desta seção, realizar atividades de modelagem de ameaças e/ou revisão de design seguro na fase de design de nossos projetos, realizar revisão de código ou análise estática, bem como executar testes de estresse, desempenho e invasão do sistema final.

Se possível, toda a sua organização deve tratar condições excepcionais da mesma maneira, pois isso facilita a revisão e a auditoria de código em busca de erros neste importante controle de segurança.

## Cenários de Exemplo de Ataque

**Cenário 1:** Exaustão de recursos via tratamento incorreto de condições excepcionais (Negação de Serviço) poderia ser causada se a aplicação captura exceções quando arquivos são carregados, mas não libera adequadamente os recursos depois. Cada nova exceção deixa recursos bloqueados ou indisponíveis, até que todos os recursos sejam esgotados.

**Cenário 2:** Exposição de dados sensíveis via tratamento inadequado ou erros de banco de dados que revelam o erro completo do sistema ao usuário. O atacante continua a forçar erros para usar as informações sensíveis do sistema para criar um ataque de _SQL injection_ melhor. Os dados sensíveis nas mensagens de erro do usuário servem como reconhecimento (_reconnaissance_).

**Cenário 3:** Corrupção de estado em transações financeiras poderia ser causada por um atacante interrompendo uma transação de múltiplas etapas via interrupções de rede. Imagine que a ordem da transação fosse: debitar conta do usuário, creditar conta de destino, registrar transação. Se o sistema não realizar o _rollback_ adequadamente de toda a transação (falha segura) quando houver um erro no meio do caminho, o atacante poderia potencialmente esvaziar a conta do usuário, ou possivelmente gerar uma condição de corrida que permita ao atacante enviar dinheiro para o destino várias vezes.

## Referências

OWASP MASVS‑RESILIENCE

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/)

## Lista de CWEs Mapeadas

- [CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-215 Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-234 Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
- [CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
- [CWE-248 Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
- [CWE-252 Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
- [CWE-274 Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
- [CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
- [CWE-369 Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
- [CWE-390 Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
- [CWE-391 Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
- [CWE-394 Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
- [CWE-396 Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
- [CWE-397 Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
- [CWE-460 Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
- [CWE-476 NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- [CWE-478 Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
- [CWE-484 Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
- [CWE-550 Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
- [CWE-636 Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
- [CWE-703 Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
- [CWE-754 Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
- [CWE-755 Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
- [CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)
