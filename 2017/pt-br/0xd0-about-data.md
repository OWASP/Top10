# +Dat Metodologia e Dados

No evento *OWASP Project Summit*, os participantes ativos e os membros da comunidade decidiram em uma visão de vulnerabilidade, com até duas (2) classes de vulnerabilidades avançadas, com ordens definidas parcialmente por dados quantitativos e parcialmente por pesquisas qualitativas.

## Pesquisa Classificada à Indústria

Para a pesquisa, nós coletamos as categorias de vulnerabilidade que foram previamente identificadas como sendo "de ponta" ou foram mencionadas em comentários para 2017 RC1 na lista de endereços do Top 10. Nós as colocamos em uma pesquisa classificada e pedimos aos entrevistados que classificassem as quatro principais vulnerabilidades que sentiram que deveriam ser incluídas no OWASP Top 10-2017. A pesquisa foi aberta de 2 de agosto a 18 de setembro de 2017. Foram coletadas 516 respostas e as vulnerabilidades foram classificadas.

| Classificação | Categoria de Vulnerabilidade na Pesquisa | Pontos |
| -- | -- | -- |
| 1 | Exposição de Informações Privadas ('Violação de Privacidade') [CWE-359] | 748 |
| 2 | Falhas Criptográficas [CWE-310/311/312/326/327] | 584 |
| 3 | Deserialização de Dados Não Confiáveis [CWE-502] | 514 |
| 4 | Bypass de Autorização Através de Chave Controlada Pelo Usuário (IDOR & Path Traversal) [CWE-639] | 493 |
| 5 | Logs e monitoração insuficientes [CWE-223 / CWE-778] | 440 |

A Exposição de Informações Privadas é claramente a vulnerabilidade de maior ranking, mas se encaixa muito facilmente como uma ênfase adicional em **A3:2017-Exposição de Dados Sensíveis**. As falhas criptográficas podem caber dentro da Exposição de Dados Sensíveis. A deserialização insegura foi classificada em terceiro lugar, então foi adicionada ao Top 10 como **A8:2017-Desserialização Insegura** após avaliação de risco. Em quarto lugar, Chave Controlada Pelo Usuário está incluída em **A5:2017-Falha no Controle de Acesso**; é bom vê-lo com classificação alta na pesquisa, pois não há muitos dados relativos a vulnerabilidades de autorização. A categoria classificada em quinto lugar na pesquisa é Logs e Monitoração Insuficientes, que acreditamos ser uma boa opção para a lista Top 10, e é por isso que se tornou **A10:2017 - Logs e Monitoração Insuficientes**. Nós mudamos para um ponto em que as aplicações precisam ser capazes de definir o que pode ser um ataque e gerar logs, alertas, escalada e respostas adequadas.

## Chamada Pública de Dados

Tradicionalmente, os dados coletados e analisados eram mais na linha de freqüência de dados; quantas vulnerabilidades encontradas em aplicações testados. Como é sabido, as ferramentas tradicionalmente relatam todas as instâncias encontradas de uma vulnerabilidade e os seres humanos tradicionalmente relatam uma única descoberta com uma série de exemplos. Isso torna muito difícil agregar os dois estilos de relatórios de maneira comparável.

Para 2017, a taxa de incidência foi calculada por quantas aplicações em um conjunto de dados possuíam um ou mais de um tipo específico de vulnerabilidade. Os dados de muitos contribuidores maiores foram fornecidos em duas visualizações: o primeiro foi o tradicional estilo de freqüência de contar todas as instâncias encontradas de uma vulnerabilidade, a segunda foi a contagem de aplicações em que cada vulnerabilidade foi encontrada (uma ou mais vezes). Embora não seja perfeito, isso permite-nos razoavelmente comparar os dados de Ferramentas Auxiliadas por Humanos e Humanos Auxiliados por Ferramenta. O trabalho de análise e dados brutos está [disponível no GitHub](https://github.com/OWASP/Top10/tree/master/2017/datacall). Pretendemos expandir isso com estrutura adicional para futuras versões do Top 10.

Recebemos mais de 40 envios na chamada de dados, já que muitos eram da chamada de dados original que estava focada na freqüência, conseguimos usar dados de 23 contribuidores cobrindo ~114.000 aplicações. Usamos um período de um ano quando possível e identificado pelo contribuidor. A maioria das aplicações é única, embora reconheçamos a probabilidade de algumas aplicações repetidas entre os dados anuais da Veracode. Os 23 conjuntos de dados utilizados foram identificados como testes humanos auxiliados por ferramenta ou taxa de incidência especificamente fornecida por ferramentas auxiliadas por humanos. As anomalias nos dados selecionados de incidência de mais de 100% foram ajustadas até 100% no máximo. Para calcular a taxa de incidência, calculamos a porcentagem do total de aplicações que foram encontrados para conter cada tipo de vulnerabilidade. A classificação de incidência foi utilizada para o cálculo da prevalência no risco geral para classificar o Top 10.

