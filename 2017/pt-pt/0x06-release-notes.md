# RN Notas da Versão

## O que mudou de 2013 para 2017?

Muita coisa mudou nos últimos quatro anos e o OWASP Top 10 precisava também ele
de mudar.
Refizemos por completo o OWASP Top 10, atualizámos a metodologia, utilizámos um
novo processo de recolha de dados, trabalhámos com a comunidade, reordámos os
riscos, reescrevemos cada risco e adicionámos referências a frameworks e
linguagens de programação que são agora amplamente usadas.

Durante a década que passou, e em particular nestes últimos anos, a arquitectura
fundamental das aplicações alterou-se de forma significativa:

* JavaScript é agora a principal linguagem em desenvolvimento web. Node.js e
  outras frameworks web modernas como Bootstrap, Electron, Angular, React entre
  muitas outras, fazem com que o código fonte que antes corria no servidor seja
  agora executado em browsers pouco confiáveis.
* _Single Page Applications_ (SPAs), escritas em frameworks JavaScript tais como
  Angular e React, permitem a criação de experiências de utilização extremamente
  modulares, isto para não mencionar o crescimento de aplicações móveis que usam
  as mesmas APIs das SPAs.
* Microserviços desenvolvidos em Node.js e Spring Boot estão a substituir as
  antigas aplicações empresariais baseadas em serviços de barramento que usavam
  Enterprise JavaBeans (EJBs) e outros semelhantes. Código antigo que não foi
  desenhado para ser aberto à Internet está agora exposto através de uma API ou
  serviço RESTful. Os pressupostos que foram usados para a criação deste código,
  tais como invocadores de confiança, simplesmente já não são válidos.

**Novos problemas, suportados pelos dados recolhidos**

* **A4:2017 - Entidades Externas de XML (XXE)** é uma nova categoria que é
  suportada principalmente pelos conjuntos de dados das ferramentas SAST -
  Static Application Security Testing

**Novos problemas, suportados pela comunidade**

Pedimos à comunidade que fornecesse a sua opinião sobre duas categorias de
poblemas voltados para o futuro. Das 516 submissões por pares e removendo alguns
problemas que já eram suportados pelos dados recolhidos (como Exposição de Dados
Sensíveis e XXE), os dois novos problemas encontrados são:

* **A8:2017 - De-serialização Insegura**, responsável por uma das piores brechas
  de todos os tempos, e
* **A10:2017 - Registo e Monitorização Insuficiente**, que case não esteja em
  falta pode prevenir ou atrasar significativamente atividade maliciosa e a
  deteção de falhas, ajudando na reposta a incidentes e na investigação forense.

**Removidos, mas não esquecidos**

* **A4-Referências Directas Inseguras a Objectos** e **A7 Falta de Controlo de
  Acesso ao Nível das Funções** juntaram-se, dando origem a **A5:2017 - Quebra
  de Controlo de Acesso**.
* **A8-Cross-Site Request Forgery (CSRF)**. Menos de 5% dos dados obtidos
  suportam atualmente o CSRF, o que o coloca na posição #13
* **A10-Redireccionamentos e Encaminhamentos Não Validados**. Menos de 1% dos
  dados obtidos suportam actualmente este problema, pelo que está agora na
  posição #25

![0x06-release-notes-1][1]

[1]: images/0x06-release-notes-1.png

