# A11:2021 - Próximos Passos

Por padrão, o OWASP Top 10 é essencialmente limitado aos dez riscos mais significativos. Cada OWASP Top 10 tem riscos "prestes" à serem considerados para inclusão, mas no final, eles não entraram na lista. Não importa como tentamos interpretar ou manipular os dados, os outros riscos eram mais prevalentes e impactantes.

Organizações que trabalham em direção a um programa maduro de appsec, consultorias de segurança ou fornecedores de ferramentas que desejam expandir a cobertura de suas ofertas, os três problemas seguintes valem bem o esforço para identificar e remediar.

## Problemas de qualidade do código

| CWEs Mapeadas  | Taxa de Incidência Máxima  | Taxa Média de Incidência  | Exploração Média Ponderada  | Impacto Médio Ponderado  | Cobertura Máxima  | Média de Cobertura  | Total de Ocorrências  | Total de CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

-   **Descrição**. Questões de qualidade de código incluem problemas conhecidos ou padrões de segurança, reutilização de variáveis para múltiplos propósitos, exposição de informações confidenciais na saída de depuração, erros de soma por desvios, tempo de verificação/tempo de uso (TOCTOU), erros de conversão assinados ou não assinados, _user after free_ e mais. A marca desta seção é que eles normalmente podem ser identificados com sinalizadores de compilador rigorosos, ferramentas de análise de código estático e plugins de linter em sua IDE. As linguagens modernas, por padrão, eliminaram muitos destes problemas, como o conceito de propriedade e empréstimo de memória do Rust, o padrão de processos do Rust e o tipo rígido de verificação de limites do Go.

-   **Como previnir**. Habilite e use as opções de análise de código estático do seu editor de código. Considere usar uma ferramenta de análise de código estático. Considere se seria possível usar ou migrar para uma linguagem ou _framework_ que elimina algumas classes de erros, como Rust ou Go.

-   **Exemplo de cenário de ataque**. Um atacante pode obter ou atualizar informações realizando uma condição de corrida usando uma variável estaticamente compartilhada em vários tópicos.

-   **Referências**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)


## Negação de serviço

| CWEs Mapeadas  | Taxa de Incidência Máxima  | Taxa Média de Incidência  | Exploração Média Ponderada  | Impacto Médio Ponderado  | Cobertura Máxima  | Média de Cobertura  | Total de Ocorrências  | Total de CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **Descrição**. Negação de serviço é sempre possível dado
     recursos suficientes. No entanto, as práticas de projeto e codificação têm um
     impacto significativo na magnitude da negação de serviço.
     Suponha que qualquer pessoa com o link possa acessar um arquivo grande ou uma
     transação que utilize muitos recursos computacionais em cada página. Neste
     caso, a negação de serviço requer menos esforço para se concretizar.

-   **Como prevenir**. Código de teste de desempenho para CPU, E/S e utilização de memória, 
    re-arquitetar, otimizar ou armazenar em cache operações que exigem muito processamento.
     Considere os controles de acesso para objetos maiores para garantir que apenas
     indivíduos autorizados podem acessar arquivos ou objetos enormes ou servir
     eles por uma rede de cache de borda.

-   **Exemplos de cenários de ataque**. Um invasor pode determinar que uma
     operação leva de 5 a 10 segundos para ser concluída. Ao executar quatro
     operações simultâneas, o servidor parece parar de responder.
     O invasor realiza então 1.000 requisições e coloca todo o sistema offline.

-   **Referências**
    - [OWASP Cheet Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Erro de gerenciamento de memória

| CWEs Mapeadas  | Taxa de Incidência Máxima  | Taxa Média de Incidência  | Exploração Média Ponderada  | Impacto Médio Ponderado  | Cobertura Máxima  | Média de Cobertura  | Total de Ocorrências  | Total de CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Descrição**. As aplicações web tendem a ser escritas em linguagens de memória gerenciada,
    como Java, .NET ou nodejs (JavaScript ou TypeScript). No entanto, 
    essas linguagens são escritas em linguagens de sistema que apresentam problemas de gerenciamento de memória,
    como estouros de buffers ou de heap, _user after free_, estouro de inteiros e muito mais.
    Ao longo dos anos, houve muitas fugas de sandbox que provam que,
    apenas porque a linguagem da aplicação web é nominalmente "segura" para a memória, as suas bases não são.

-   **Como prevenir**. Muitas APIs modernas agora são escritas em linguagens seguras de memória,
    como Rust ou Go. No caso do Rust, a segurança da memória é um recurso crucial da linguagem.
    Para códigos existentes, o uso de flags de compilador estritas, tipagem forte,
    análise de código estática e testes de mutação podem ser benéficos para identificar vazamentos de memória,
    sobrecargas de matriz e muito mais.

-   **Exemplos de cenários de ataque**. Os estouros de buffer e heap têm sido um recurso favorito dos invasores ao longo dos anos.
    O invasor envia dados para um programa, que armazena em um buffer de pilha subdimensionado.
    Como resultado, as informações da pilha de chamadas são substituídas, incluindo o ponteiro de retorno da função.
    Os dados definem o valor do ponteiro de retorno de modo que, quando a função retorna, transfere o controle.

-   **Referências**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
