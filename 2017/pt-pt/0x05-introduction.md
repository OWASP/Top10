# I Introdução

## Seja bem vindo ao OWASP Top 10 - 2017

Esta nova atualização introduz um conjunto de novos problemas, dois dos quais
selecionados pela comunidade - **A8:2017 - Deserialização Insegura** e
**A10:2017 - Registo e Monitorização Insuficiente**.

A opinião da comunidade originou a maior coleção de dados alguma vez recolhida
na preparação de um _standard_ de segurança aplicacional e por isso estamos
confiantes que os restantes 8 problemas são os mais importantes para as
organizações endereçarem, em particular

* **A3:2017 - Exposição de Dados Sensíveis** relevante no âmbito da
  Regulamentação Geral da Protecção de Dados (GDPR) da UE
* **A6:2017 - Más Configurações de Segurança** em particular no que respeita a
  serviços/APIs e _cloud_
* **A9:2017 - Utilização de Componentes com Vulnerabilidades Conhecidas**, que
  pode ser particularmente desafiante em plataformas mais modernas, como
  Node.js.

O OWASP Top 10 de 2017 é baseado, essencialmente, em mais de 40 submissões de
dados de empresas especializadas na área da segurança aplicacional e num
inquérito realizado a profissionais individuais do sector, o qual obteve 515
respostas. Estes dados refletem as vulnerabilidades identificadas em centenas de
organizações e mais de 100.000 aplicações e APIs reais.

Os itens do Top 10 são selecionados e ordenados de acordo com a sua prevalência,
combinada com uma estimativa ponderada do potencial de abuso, detecção e
impacto.

O principal objetivo do OWASP Top 10 é o de educar programadores, desenhadores
e arquitectos de aplicações, bem como gestores e as próprias organizações sobre
as consequências dos problemas de segurança mais comuns e mais importantes no
contexto das aplicações web. O Top 10 oferece não só técnicas básicas para
proteção nestas áreas problemáticas e de elevado risco, mas também direções
sobre onde encontrar informação adicional sobre estes assuntos.

## Planeamento para atividades futuras

**Não pare no 10**. Existem centenas de problemas que podem afectar a segurança
geral de uma aplicação web tal como discutido no [Guia de Programadores da
OWASP][1] e nas [Séries de Cheat Sheets da OWASP][2]. Isto é leitura essencial
para alguém que esteja a desenvolver aplicações web e APIs. Orientações sobre
como encontrar efetivamente vulnerabilidades em aplicações web e APIs são
fornecidas no [OWASP Testing Guide][3].

**Mudança constante**. O OWASP Top 10 vai continuar a mudar. Mesmo sem mudar uma
única linha no código da sua aplicação, pode ficar vulnerável à medida que novas
falhas são descobertas e métodos de ataque são refinados. Por favor, reveja os
conselhos no final do Top 10 na parte “O que se segue para Programadores,
profissionais de Testes e Organizações” para mais informação.

**Pense positivo**. Quando estiver pronto para parar de perseguir
vulnerabilidades e focar-se na definição de controlos fortes de segurança
aplicacional, lembre-se que a OWASP mantém e promove o [Standard de Verificação
de Segurança Aplicacional (ASVS)][4] como guia de aspectos a verificar, tanto
para as organizações como para os revisores de aplicações.

**Use as ferramentas de forma inteligente**. As vulnerabilidades de segurança
podem ser bastante complexas e muito intrincadas no meio do código. Em muitos
casos a abordagem mais eficiente para encontrar e eliminar estas fraquezas
consiste na utilização de especialistas humanos munidos de boas ferramentas.

**Dispare em todas as direcções**. Foque-se em tornar a segurança parte
integrante da cultura da sua organização, em particular no departamento de
desenvolvimento. Pode encontrar mais informação em [Modelo de Garantia da
Maturidade do Software da OWASP (SAMM)][5].

## Reconhecimento

Gostaríamos de agradecer às organizações que contribuíram com os seus dados
sobre vulnerabilidades para suportar esta actualização de 2017. Recebemos mais
de 40 respostas à nossa solicitação de dados. Pela primeira vez todos os dados
que contribuíram para este Top 10 e a lista completa de contribuidores, foi
tornada pública. Acreditamos que esta é uma das maiores e mais heterogéneas
coleções de dados sobre vulnerabilidades alguma vez recolhida publicamente.

Uma vez que existem mais organizações do que espaço aqui disponível, criámos uma
página dedicada a reconhecer as contribuições realizadas. Queremos agradecer
sinceramente a estas organizações por quererem estar na linha da frente ao
partilhar publicamente os dados sobre vulnerabilidades resultante dos seus
esforços. Esperamos que esta tendência continue a crescer e encoraje mais
organizações a fazerem o mesmo e possivelmente serem vistas como um dos
principais marcos da segurança baseada em evidências. O OWASP Top 10 não seria
possível sem estas contribuições incríveis.

Um agradecimento especial aos mais de 500 indivíduos que gastaram o seu tempo a
preencher o questionário à indústria. A voz deles ajudou a definir duas novas
entradas no Top 10. Os comentários adicionais, as notas de encorajamento (e
críticas) foram todos devidamente apreciados. Sabemos que o vosso tempo é
valioso e por isso queremos dizer Obrigado.

Gostaríamos de agradecer antecipadamente a todos os indivíduos que contribuíram
com os seus comentários construtivos e relevantes, e pelo tempo que gastaram na
revisão desta actualização do Top 10. Tanto quanto possível, estão todos
listados na página de agradecimentos '+Ack'.

Finalmente, gostaríamos de agradecer antecipadamente a todos os tradutores que
irão traduzir esta actualização do Top 10 em múltiplas línguas, ajudando a
tornar o OWASP Top 10 mais acessível a todo o planeta.

[1]: https://www.owasp.org/index.php/OWASP_Guide_Project
[2]: https://www.owasp.org/index.php/Category:Cheatsheets
[3]: https://www.owasp.org/index.php/OWASP_Testing_Project
[4]: https://www.owasp.org/index.php/ASVS
[5]: https://www.owasp.org/index.php/OWASP_SAMM_Project

