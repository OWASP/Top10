# +Dat Metodologia e Dados

No Summit de Projectos da OWASP, alguns participantes e membros da comunidade decidiram-se por uma visão de vulnerabilidade, com até duas (2) classes de vulnerabilidades avançadas, com ordenação definida parcialmente por dados quantitativos e parcialmente por inquéritos qualitativos.
 
## Inquérito de Classificação à Indústria

Para o inquérito, foram recolhidas as categorias de vulnerabilidades que foram previamente identificadas como sendo emergentes ou que tinham sido mencionadas em comentários à versão 2017 RC1 através da lista do Top 10. Colocamo-los num inquérito de classificação e solicitamos a quem respondia para ordenar as quatro vulnerabilidades que eles sentiam que deveriam ser incluídas no OWASP Top 10 2017. O inquérito esteve disponível de 2 de agosto a 18 de setembro de 2017. Foram recolhidas 516 respostas e as vulnerabilidades foram classificadas.

| Classificação | Categorias de Vulnerabilidades do Inquérito | Pontuação |
| -- | -- | -- |
| 1 | Exposição de Informação Privada ('Privacy Violation') [CWE-359] | 748 |
| 2 | Falhas Criptográficas [CWE-310/311/312/326/327]| 584 |
| 3 | De-serialização de Dados Deserialization of Untrusted Data [CWE-502] | 514 |
| 4 | Ultrapassar Autorização através de Chaves Controladas pelo Utilizador (IDOR & Path Traversal) [CWE-639] | 493 |
| 5 | Registo e Monitorização Insuficiente [CWE-223 / CWE-778]| 440 |

A exposição de dados privados é claramente a vulnerabilidade mais vem classificada, mas encaixa-se facilmente com um enfâse adicional no existente **A3:2017-Sensitive Data Exposure**. As falhas criptográficas podem encaixar-se dentro da Exposição de Dados Sensíveis. A de-serialização insegura ficou classificada em terceiro lugar, e por isso foi adicionada ao Top 10 como **A8:2017-De-serialização Insegura** depois da classificação de riscos. O quarto classificado foi a Chave Controlada pelo Utilizador que foi incluída na em **A5:2017-Quebra de Controlo de Acesso**; é bom verificar que ficou bem classificada no inquérito, uma vez que não existem muitos dados relativos a vulnerabilidades de autorização. O quinto classificado no inquérito foi o Registo e Monitorização Insuficiente, que nós acreditamos ser uma boa escolha para a lista do Top 10, que por isso se tornou no **A10:2017-Registo e Monitorização Insuficiente**. Chegamos a um ponto em que as aplicações necessitam de ser capazes de definir o que pode ser um ataque e gerar os registos, alertas, escalamento e repostas apropriadas. 

## Chamada Pública de Dados

Tradicionalmente, os dados recolhidos e analizados estavam mais alinhados com o dados de frequência; quantas vulnerabilidades foram encontradas nas aplicações testadas. Como é bem conhecido, as ferramentas reportam todas as instâncias encontradas de uma vulnerabilidade e os humanos reportam uma única instância de uma vulnerabilidade com alguns exemplos associados. Isto torna muito difícil agregar os dois estilos de relatório de uma forma comparável.

Para 2017, a taxa de incidência foi calculada com base em quantas aplicações num determinado conjunto de dados tinham um ou mais tipos específicos de vulnerabilidades. Os dados de muitos dos principais contribuidores foram trabalhados em duas perspectivas: a primeira foi o estilo tradicional de frequências de contagem de cada instância da vulnerabilidade encontrada; a segunda consistiu em contar as aplicações em que cada tipo de vulnerabilidade tinha sido encontrada (uma ou mais vezes. Apesar de não ser perfeito, este método permite comparar os dados de ferramentas que assistem humanos (*Human Assisted Tools*) e dos próprios humanos que operam como ferramentas (*Tool Assisted Humans*). Os dados em bruto e o trabalho de análise está [disponível no GitHub][1]. Pretendemos expandir esta metodologia, com algumas melhorias, para a versão de 2020 (ou antes).

Recebemos mais de 40 submissões à nossa chamada pública de dados, e como um grande número de dados originavam de dados focados na frequência, conseguimos usar dados de 23 contribuidores que cobrem aproximadamente 114,000 Aplicações. Usamos um bloco com um ano de duração sempre que possível e identificado pelo respectivo contribuidor. A grande maioria das aplicações eram únicas, apesar de reconhecermos a probabilidade de poderem existir algumas aplicações repetidas entre dos dados anuais da Veracode. Os 23 conjuntos de dados usadis foram identificados como sendo obtidos de testes realizados por humanos ou a taxa de incidentes de ferramentas automaticas. As anomalias nos dados selecionados que apresentassem uma incidência superior a 100% foram ajustados para um máximo de 100%. Para calcular o indíce de incidência, calculamos a percentagem do total das aplicações que continham algum tipo de vulnerabilidade. A classificação de incidências foi usada para calcular a prevalência no risco geral do Top 10. 

[1]:	https://github.com/OWASP/Top10/tree/master/2017/datacall
