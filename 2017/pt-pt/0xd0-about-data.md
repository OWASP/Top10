# +Dat Metodologia e Dados

## Visão Geral

No evento OWASP Project Summit, participantes e membros ativos da comunidade
definiram uma visão sobre as vulnerabilidade, com até duas (2) classes de
vulnerabilidades expectáveis para o futuro, com ordenação definida parcialmente
quer com base em dados quantitativos quer em inquéritos qualitativos.

## Inquérito de Classificação à Indústria

Para o inquérito, foram recolhidas as categorias de vulnerabilidades que foram
previamente identificadas como sendo emergentes ou que tinham sido mencionadas
em comentários à versão 2017 RC1 através da lista do Top 10. Colocámo-las num
inquérito de classificação e solicitámos aos participantes que ordenassem as
quatro vulnerabilidades que eles sentiam que deveriam ser incluídas no OWASP Top
10-2017. O inquérito esteve disponível de 2 de agosto a 18 de setembro de 2017.
Foram recolhidas 516 respostas e as vulnerabilidades foram ordenadas.

| Ordem | Categorias de Vulnerabilidades do Inquérito | Pontuação |
| -- | -- | -- |
| 1 | Exposição de Informação Privada ('Privacy Violation') [CWE-359] | 748 |
| 2 | Falhas Criptográficas [CWE-310/311/312/326/327]| 584 |
| 3 | De-serialização de dados não confiáveis [CWE-502] | 514 |
| 4 | Desvio de Autorização através de Chaves Controladas pelo Utilizador (IDOR & Path Traversal) [CWE-639] | 493 |
| 5 | Registo e Monitorização Insuficiente [CWE-223 / CWE-778]| 440 |

A Exposição de Informação Privada foi claramente a vulnerabilidade mais votada,
a qual encaixa facilmente, com enfâse adicional, na categoria
**A3:2017-Exposição de Dados Sensíveis** já existente. Da mesma forma as Falhas
Criptográficas podem encaixar-se nesta categoria "Exposição de Dados Sensíveis".
A de-serialização insegura ficou classificada em terceiro lugar, e por isso foi
adicionada ao Top 10 como **A8:2017-De-serialização Insegura** depois da
classificação de riscos.
O quarto classificado foi o Desvio de Autorização através de Chaves Controladas
pelo Utilizador que foi incluída na **A5:2017-Quebra de Controlo de Acessos**;
é bom verificar que ficou bem classificada no inquérito, uma vez que não existem
muitos dados relativos a vulnerabilidades de autorização. O quinto classificado
no inquérito foi o Registo e Monitorização Insuficiente, que nós acreditamos ser
uma boa escolha para a lista do Top 10, a qual deu origem à **A10:2017-Registo e
Monitorização Insuficiente**. Chegámos a um ponto em que as aplicações
necessitam de ser capazes de definir o que pode ser um ataque e gerar os
registos, alertas, escalamento e repostas apropriadas.

## Pedido Público de Contribuição de Dados

Tradicionalmente, os dados recolhidos e analizados eram orientados à frequência;
quantas vulnerabilidades foram encontradas nas aplicações testadas. Como é
sabido, as ferramentas tipicamente reportam todas as instâncias encontradas para
uma mesma vulnerabilidade no entanto os profissionais reportam uma única
instância dum tipo de vulnerabilidade, fornecendo váris exemplos associados.
Isto torna a agregação de resultdos destes dois estilos de relatório para fins
comparativos muito difícil.

Para 2017 a taxa de incidência foi calculada com base em quantas aplicações num
determinado conjunto de dados tinham um ou mais tipos específicos de
vulnerabilidades. Os dados de muitos dos principais contribuidores foram
trabalhados em duas perspectivas. A primeira seguiu o estilo tradicional de
frequências de contagem de cada instância da vulnerabilidade encontrada,
enquanto que a segunda consistiu em contar as aplicações em que cada tipo de
vulnerabilidade tinha sido encontrada (uma ou mais vezes). Apesar de não ser
perfeito, este método permite comparar os dados de ferramentas que assistem
humanos (_Human Assisted Tools_) e aqueles dos profissionais que operam as
ferramentas (_Tool Assisted Humans_). Os dados em bruto e o trabalho de análise
está [disponível no GitHub][1]. Pretendemos expandir esta metodologia, com
algumas melhorias, para versões futuras do TOP 10.

Recebemos mais de 40 submissões ao nosso pedido público para contribuição de
dados mas por um grande volume desses dados ter resultado dum pedido inicial
orientado à frequência, conseguimos apenas usar dados de 23 contribuidores que
cobrem aproximadamente 114,000 Aplicações.
Sempre que possível usámos apenas dados numa janela temporal de 1 (um) ano
identificados pelo respectivo contribuidor. A grande maioria das aplicações são
únicas, apesar de reconhecermos a probabilidade de poderem existir algumas
aplicações repetidas nos dados anuais da Veracode. Os 23 conjuntos de dados
usados foram identificados como sendo obtidos de testes realizados por humanos
ou a taxa de incidentes de ferramentas automáticas. As anomalias nos dados
selecionados que apresentassem uma incidência superior a 100% foram ajustados
para um máximo de 100%. Para calcular o índice de incidência, calculámos a
percentagem do total das aplicações que continham algum tipo de vulnerabilidade.
A classificação de incidência foi usada para calcular a prevalência no risco
geral dando origem à ordenação final do Top 10.

[1]:	https://github.com/OWASP/Top10/tree/master/2017/datacall

