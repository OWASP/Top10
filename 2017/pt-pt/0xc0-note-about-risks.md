# +R Nota Sobre Os Riscos

## É Sobre Os Riscos Que as Falhas Representam

A metodologia de Classificação de Risco para o Top 10 é baseada na [OWASP Risk
Rating Methodology][0xc01]. Para cada categoria do Top 10, estimamos o risco
típico que cada falha introduz numa aplicação web típica, ao observar os fatores
de ocorrência comuns e os fatores de impacto para cada falha. De seguida,
ordenamos o Top 10 de acordo com as falhas que tipicamente introduzem o risco
mais significativo para uma aplicação. Estes fatores são atualizados a cada nova
versão do Top 10 de acordo as mudanças que ocorrem.

[OWASP Risk Rating Methodology][0xc01] define diversos fatores que ajudam a
calcular o risco de uma determinada vulnerabilidade. Todavia, o Top 10 deve ser
genérico e não focar em vulnerabilidades específicas existentes em aplicações e
APIs reais. Consequentemente, não poderemos ser tão precisos quanto os donos do
sistema, no que diz respeito a calcular o risco para a(s) sua(s) aplicação(ões).
Você avaliará melhor a importância da(s) sua(s) aplicação(ões) e dos seus dados,
quais são as ameaças, como o sistema foi construído e como é utilizado.

A nossa metodologia inclui três fatores de ocorrência para cada falha
(prevalência, deteção e facilidade de abuso) e um fator de impacto (técnico). A
escala de risco para cada fator varia entre 1-Baixo até 3-Alto com terminologia
específica. A prevalência de uma falha é um fator que tipicamente não terá de
calcular. Para dados sobre a prevalência, recebemos estatísticas de diferentes
organizações (como referido na secção de Agradecimentos na página 26), agregamos
todos os dados pelos 10 fatores mais prováveis. Estes dados foram depois
combinados com os outros dois fatores de ocorrência (deteção e facilidade de
abuso) para calcular um índice de ocorrência de cada falha. Este último foi
então multiplicado pelo fator de impacto técnico médio estimado de cada item,
para apresentar uma ordenação geral dos riscos de cada item para o Top 10
(quanto mais elevado for o resultado, mais elevado é o risco). Deteção,
Facilidade de Abuso, e o Impacto foram calculados através da análise de CVEs
reportados que foram associados com cada item do Top 10.

**Nota**: Esta abordagem não tem em consideração a existência de um agente ameaça.
Nem tem em consideração quaisquer detalhes técnicos associados à sua aplicação
em particular. Qualquer um destes fatores pode afetar de forma significativa a
probabilidade geral de um atacante encontrar e explorar uma vulnerabilidade
específica. Esta classificação não tem em consideração o impacto específico no
seu negócio. A sua organização terá que decidir que riscos de segurança das
aplicações e APIs é que a sua organização está disposta a aceitar dada a sua
cultura, indústria, e o ambiente regulatório. O propósito do Top 10 da OWASP não
é realizar a análise de risco por si.

A imagem seguinte ilustra o nosso cálculo do risco para [A6:2017 - Configurações
de Segurança Incorretas][0xc02].

![Risk Calculation for A6:2017-Security Misconfiguration][0xc03]

[0xc01]: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
[0xc02]: ./0xa6-security-misconfiguration.md
[0xc03]: images/0xc0-risk-explanation.png

