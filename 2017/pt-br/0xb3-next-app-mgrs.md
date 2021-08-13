# +A: Próximos Passos para Gerente de Aplicações

## Gerencie o Ciclo de Vida Completo da Aplicação

Aplicações estão entre os sistemas mais complexos que os seres humanos criam e mantêm regularmente. O gerenciamento de TI para uma aplicação deve ser realizado por especialistas de TI que são responsáveis pelo ciclo geral de TI de uma aplicação. Sugerimos estabelecer o papel de gerente de aplicações como contrapartida técnica para o dono da aplicação. O gerente de aplicações está encarregado de todo o ciclo de vida da aplicação sob a perspectiva de TI desde coletar os requisitos até o processo de aposentadoria de sistemas, que muitas vezes é ignorado.

## Requisitos e Gerenciamento de Recursos

- Colete e negocie os requisitos de negócios para uma aplicação com o negócio, incluindo os requisitos de proteção em relação à confidencialidade, autenticidade, integridade e disponibilidade de todos os ativos de dados e a lógica comercial esperada.
- Compile os requisitos técnicos, incluindo requisitos de segurança funcionais e não funcionais.
- Planeje e negocie o orçamento que abrange todos os aspectos do projeto, construção, teste e operação, incluindo atividades de segurança.

## Pedido de Propostas (RFP) e Contratação

- Negocie com desenvolvedores internos ou externos os requisitos, incluindo diretrizes e requisitos de segurança em relação ao seu programa de segurança, por exemplo, SDLC, melhores práticas.
- Avalie o cumprimento de todos os requisitos técnicos, incluindo uma fase de planejamento e design.
- Negocie todos os requisitos técnicos, incluindo acordos de design, segurança e nível de serviço (SLA).
- Adote modelos e listas de verificação, como [Anexo de Contrato de Software Seguro OWASP](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex). **Nota**: O Anexo é uma amostra específica da lei de contratos dos EUA e é provável que necessite de revisão legal em sua jurisdição. Consulte conselhos legais qualificados antes de usar o Anexo

## Planejamento e Design

- Negocie planejamento e design com os desenvolvedores e acionistas internos, por exemplo especialistas em segurança.
- Defina a arquitetura de segurança, controles e contramedidas apropriadas às necessidades de proteção e ao nível de ameaça esperado. Isso deve ser suportado por especialistas em segurança.
- Certifique-se de que o proprietário do aplicativo aceita os riscos remanescentes ou fornece recursos adicionais.
- Em cada sprint, garantir que as histórias de segurança sejam criadas, incluindo restrições adicionadas para requisitos não funcionais.

## *Deployment*, Testes e *Rollout*

- Automatize o *deploy* seguro do aplicativo, interfaces e de todos os componentes necessários, incluindo as autorizações necessárias.
- Teste as funções técnicas e integração com a arquitetura de TI e coordene os testes de negócios.
- Crie casos de teste de "uso" e "abuso" de perspectivas técnicas e empresariais.
- Gerencie testes de segurança de acordo com os processos internos, as necessidades de proteção e o nível de segurança exigido pelo aplicativo.
- Coloque o aplicativo em operação e migre dos aplicativos usados anteriormente, se necessário.
- Finalize toda a documentação, incluindo o CMDB e arquitetura de segurança.

## Operação e Mudanças

- Opere incluindo o gerenciamento de segurança para a aplicação (por exemplo, gerenciamento de patches).
- Promova a consciência de segurança dos usuários e gerencie conflitos sobre usabilidade vs segurança.
- Planeje e gerencie mudanças, por exemplo, migre para novas versões da aplicação ou outros componentes como SO, middleware e bibliotecas.
- Atualize toda a documentação, inclusive no CMDB e na arquitetura de segurança, controles e contramedidas, incluindo qualquer procedimento ou documentação do projeto.

## Aposentando Sistemas

- Todos os dados necessários devem ser arquivados. Todos os outros dados devem ser totalmente apagados.
- Retire com segurança a aplicação, incluindo a exclusão de contas e funções não utilizadas e permissões.
- Defina o estado da sua aplicação a ser aposentada no CMDB.

