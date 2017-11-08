# +R Notas sobre os Riscos

## É sobre Riscos, não Fraquezas

Apesar do [OWASP Top 10 2007][1] e das anteriores versões do Top 10 estarem muito focadas na identificação das vulnerabilidades mais prevalentes, o OWASP Top 10 sempre esteve organizado em torno de riscos. Este enfoque nos riscos causou alguma compreensível confusão em pessoas que procuravam uma taxonomia  estrita de fraquezas. O [OWASP Top 10 for 2010][2] clarificou o enfoque nos riscos no Top 10 sendo muito explicito sobre como os agentes de ameaça, vectores de ataque, fraquezas, impactos técnicos e impactos de negócio se combinam para produzir riscos. Esta versão do OWASP Top 10 continua no seguimento da mesma metodologia.

A metodologia de Classificação de Riscos para o OWASP Top 10 baseia-se na [Metodologia de Classificação de Riscos da OWASP][3]. Para cada item do Top 10, estimamos o risco típico que cada fraqueza introduz numa aplicação web típica olhando para factores comuns de ocorrência e para os factores de impacto de cada fraqueza. Depois ordenamos o Top 10 de acordo com essas fraquezas que tipicamente introduzem os riscos mais significativos numa aplicação. Estes factores são actualizados a cada nova versão do Top 10 de acordo com as mudanças que ocorram.

A [Metodologia de Classificação de Risco da OWASP][4] define múltiplos factores que ajudam a calcular o risco de uma determinada vulnerabilidade. No entanto, o  Top 10 deve ser genérico, ao invés de referir vulnerabilidades específicas existentes em APIs e aplicações reais. Por consequência, nunca poderemos ser tão específicos como o dono do sistema quando calculam o risco para a sua aplicação(ões). Você está melhor equipado para julgar a importância das suas aplicações e dados, quais são as suas ameaças, e como o seu sistema foi implementado e é operado.

A nossa metodologia inclui três factores de ocorrência para cada fraqueza (prevalência, detecção, e facilidade de exploração) e um factor de impacto (impacto técnico). A prevalência de uma fraqueza é um factor que tipicamente não tem que calcular. Para os dados da prevalência, fornecemos estatísticas de prevalência de um número de diferentes organizações (como foi referido na secção de Reconhecimento na página 4) e calculamos a média do conjunto dos seus dados para produzir a probabilidade em termos de prevalência no Top 10. Estes dados foram depois combinados com os outros dois factores de ocorrência (detecção e facilidade de exploração) para calcular a taxa de probabilidade de cada fraqueza. A taxa de probabilidade foi então multiplicada pela nossa média estimada do factor de impacto técnico para cada item para chegarmos à ordenação geral dos riscos para cada item no Top 10 (quanto mais elevado for o resultado, mais elevado é o risco).  

De notar que esta abordagem não tem em consideração a probabilidade do agente de ameaça. Nem tem em consideração quaisquer detalhes técnicos associados a uma qualquer aplicação em particular. Qualquer um destes factores pode afectar de forma significativa a probabilidade geral de um atacante encontrar e explorar uma vulnerabilidade específica. Esta classificação não tem em consideração o impacto específico no negócio. _A sua organização_ terá que decidir quanto risco de segurança de aplicações e APIs é que A _organização_ está disposta a aceitar dada a sua cultura, industria, e ambiente regulatório. Não é o objectivo do OWASP Top 10 fazer esta análise de risco por si.

A seguinte imagem ilustra o nosso cálculo do risco para **A6:2017 - Más Configurações de Segurança**.

![Risk Calculation for A6:2017-Security Misconfiguration][image-1]

[1]:	https://www.owasp.org/index.php/Top10
[2]:	https://www.owasp.org/index.php/Top_10_2010
[3]:	https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology
[4]:	https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology

[image-1]:	images/0xc0-risk-explanation.png