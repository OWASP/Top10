# RN Notas da Versão

## O que mudou de 2013 para 2017?

Muita coisa mudou nos últimos quatro anos e o OWASP Top 10 precisava também ele
de mudar. Refizemos por completo o OWASP Top 10, atualizámos a metodologia,
utilizámos um novo processo de recolha de dados, trabalhámos com a comunidade,
reordenamos os riscos, reescrevemos cada risco e adicionámos referências a
_frameworks_ e linguagens de programação que são agora amplamente usadas. 

Durante a década que passou, e em particular nestes últimos anos, a arquitetura
das aplicações alterou-se de forma significativa:

- Microserviços escritos em Node.js e Spring Boot estão a substituir as
  tradicionais aplicações monolíticas. Os Microserviços apresentam os seu
  próprios desafios de segurança como a confiança entre os microserviços,
  containers, gestão de segredos, etc. Código antigo que não foi pensado para
  estar exposto à Internet é agora acessível por meio de APIs e serviços
  RESTful, consumigos por SPAs e aplicações móveis. Premissas antigas, tais como
  entidades confiáveis, já não são válidas.
- Single Page Applications (SPAs), escritas utilizando frameworks JavaScript
  tais como Angular e React, permitem a criação de experiências de utilização
  extremamente modulares. Funcionalidades agora oferecidas no navegador web e
  que antes estavam no servidor trazem desafios de segurança próprios.
- JavaScript é agora a principal linguagem em desenvolvimento web com Node.js a
  correr no servidor e frameworks web modernas como Bootstrap, Electron,
  Angular, React a correr no navegador do cliente.

**Novos problemas, suportados pelos dados recolhidos**

- A4:2017 - Entidades Externas de XML (XXE) é uma nova categoria que é suportada
  principalmente pelos conjuntos de dados das ferramentas SAST - Static
  Application Security Testing 

**Novos problemas, suportados pela comunidade**

Pedimos à comunidade que fornecesse a sua opinião sobre duas categorias de
problemas voltados para o futuro. Das 516 submissões por pares e removendo
alguns problemas que já eram suportados pelos dados recolhidos (como Exposição
de Dados Sensíveis e XXE), os dois novos problemas encontrados são:

- A8:2017 - Desserialização Insegura, que permite a execução remota de código ou
  a manipulação de objetos sensíveis nas plataformas afetadas
- A10:2017 - Registo e Monitorização Insuficiente, que caso não esteja em falta
  pode prevenir ou atrasar significativamente atividade maliciosa e a deteção de
  falhas, ajudando na reposta a incidentes e na investigação forense.

**Removidos, mas não esquecidos**

- A4-Referências Directas Inseguras a Objectos e A7 Falta de Controlo de Acesso
  ao Nível das Funções juntaram-se, dando origem a A5:2017 - Quebra de Controlo
  de Acesso.
- A8 Cross-Site Request Forgery (CSRF). Como atualmente muitas das frameworks
  utilizadas incluem defesas contra CSRF, foi encontrada em menos de 5% das
  aplicações.
- A10-Redireccionamentos e Encaminhamentos Não Validados. Embora encontrado em
  8% das aplicações, foi cortada globalmente pelo XXE.

![0x06-release-notes-1][0x061]

[0x061]: images/0x06-release-notes-1.png

