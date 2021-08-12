# +A: Próximos Passos Para Gestores de Aplicações

## Gerir o Ciclo de Vida das Aplicações

As aplicações são alguns dos sistemas mais complexos que os humanos criam e
mantêm regularmente. A gestão de TI para uma aplicação deve ser realizada por
especialistas de TI que são responsáveis pelo ciclo de vida global de TI de uma
aplicação.

Sugerimos que se defina o perfil de gestor da aplicação sendo este mais técnico
do que o de dono da aplicação. O gestor da aplicação é quem controla todo o
ciclo de vida da aplicação dum ponto de vista técnico, desde a identificação de
requisitos até à descontinuação do sistema, o qual é normalmente esquecido.

### Requisitos e Gestão de Recursos

* Identificar e negociar os requisitos de negócio para uma aplicação com os
  responsáveis da área de negócio, incluindo requisitos de proteção relacionados
  com confidencialidade, integridade e disponibilidade de todos os ativos de
  dados e respetiva lógica de negócio.
* Compilar os requisitos técnicos incluindo os requisitos funcionais e não
  funcionais de segurança.
* Planear e negociar o orçamento que deve cobrir todos os aspetos do desenho,
  construção, teste e operação, incluindo atividades de segurança.

### Solicitação de Propostas e Contratação

* Negociar os requisitos com os programadores internos ou externos, incluindo
  orientações e requisitos de segurança relativos ao seu programa de segurança,
  e.g. SDLC (_Systems Development Life Cycle_), melhores práticas.
* Classificar o cumprimento de todos os requisitos técnicos incluindo
  planeamento e fase de desenho.
* Negociar todos os requisitos técnicos incluindo o desenho, segurança e acordos
  de nível de serviço (SLA).
* Adotar modelos de documentos e listas de validação, tais como [Anexo de
  Contrato para Software Seguro da OWASP][0xb31].

**N.B.**: O Anexo é um exemplo específico para a lei de contratação nos EUA, e
provavelmente necessita de ser adaptada à realidade jurídica de outros países.
Por favor, obtenha aconselhamento legal antes de usar o Anexo.

### Planear e Desenhar

* Negociar o planeamento e desenho com os programadores e com os intervenientes
  internos, e.g. os especialistas de segurança.
* Definir a arquitetura de segurança, controlos e contramedidas adequadas às
  necessidades de proteção e nível de ameaça expectável. Isto deve ser feito em
  colaboração com os especialistas de segurança.
* Garantir que o dono da aplicação assume os riscos remanescentes ou que
  disponibiliza recursos adicionais.
* Para cada ciclo de desenvolvimento (_sprint_), assegurar que as tarefas
  (_stories_) de segurança são criadas para os requisitos funcionais, incluindo
  os constrangimentos adicionados aos requisitos não-funcionais.

### Instalação, Teste e Lançamento

* Automatizar a configuração segura da aplicação, interfaces e de todos os
  componentes necessários, incluindo autorizações.
* Testar as funções técnicas e integração com a arquitetura de TI e coordenar os
  testes de negócio.
* Criar casos de teste de “uso” e de “abuso” tanto da perspetiva técnica como de
  negócio.
* Gerir testes de segurança de acordo com os processos internos, as necessidades
  de proteção e o nível de segurança requerido pela aplicação.
* Colocar a aplicação em operação e, quando necessário, proceder à migração das
  aplicações em uso.
* Finalizar toda a documentação, incluindo a BDGC (Base de Dados de Gestão de
  Configurações) e a arquitetura de segurança.

### Operação e Alterações

* Operar incluindo a gestão de segurança para a aplicação (e.g. gestão de
  correções).
* Aumentar a consciencialização de segurança dos utilizadores e gerir conflitos
  da dicotomia entre usabilidade e segurança.
* Planear e gerir alterações, e.g. migrar para novas versões da aplicação ou
  outros componentes como o SO, _middleware_ ou bibliotecas.
* Atualizar toda a documentação, incluindo o DBGC e a arquitetura de segurança,
  controlos e contramedidas, incluindo quaisquer cadernos ou documentação de
  projeto.

### Descontinuação de Sistemas

* Dados relevantes devem ser arquivados. Todos os outros dados devem ser
  apagados de forma segura.
* Interromper a utilização da aplicação de forma segura, incluindo a remoção de
  contas, perfis e permissões não usadas.
* Atualizar o estado da aplicação para "descontinuada" na BDGC.

[0xb31]: https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex

